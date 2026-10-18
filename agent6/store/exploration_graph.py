"""
探索图（Exploration Graph）—— 单任务独立，记录攻击链路血缘。

节点类型(kind)：
    goal     本次任务目标
    intent   Planner 下发的攻击意图（待办/进行中/完成）
    fact     Worker 执行得到的事实
    finding  漏洞发现（可挂载到资产）
    hint     提示/线索（引导下一步）

边(rel)：
    derives   父子血缘：某 intent 衍生出某 fact/finding
    uses      intent 依赖某 fact
    leads_to  fact -> intent（新攻击面）
    supports  finding 佐证
"""
import time
from typing import Dict, List, Optional

from .db import jdump, jload, now


class ExplorationGraph:
    def __init__(self, db, task_id: str):
        self.db = db
        self.task_id = task_id
        self._seq = self._next_seq()

    def _next_seq(self) -> int:
        r = self.db.query_one(
            "SELECT COUNT(*) c FROM nodes WHERE task_id=?", (self.task_id,))
        return (r or {}).get("c", 0)

    def _new_id(self) -> str:
        self._seq += 1
        return f"{self.task_id}-N{self._seq}"

    # ---------- 节点 ----------
    def add_node(self, kind: str, label: str, data: Dict = None,
                 status: str = "pending", parent_id: str = None,
                 asset_ref: str = None) -> str:
        nid = self._new_id()
        ts = now()
        self.db.execute(
            "INSERT INTO nodes(id,task_id,kind,label,data,status,parent_id,asset_ref,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (nid, self.task_id, kind, label, jdump(data or {}), status,
             parent_id, asset_ref, ts, ts),
        )
        if parent_id:
            self.add_edge(parent_id, nid, "derives")
        return nid

    def update_node(self, nid: str, **fields):
        allowed = {"label", "status", "data", "parent_id", "asset_ref"}
        sets, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k == "data":
                v = jdump(v)
            sets.append(f"{k}=?")
            vals.append(v)
        if not sets:
            return
        sets.append("updated_at=?")
        vals.append(now())
        vals.append(nid)
        self.db.execute(f"UPDATE nodes SET {', '.join(sets)} WHERE id=?", vals)

    def add_edge(self, src_id: str, dst_id: str, rel: str):
        self.db.execute(
            "INSERT OR IGNORE INTO edges(task_id,src_id,dst_id,rel) VALUES(?,?,?,?)",
            (self.task_id, src_id, dst_id, rel),
        )

    # ---------- 语义化便捷方法 ----------
    def set_goal(self, goal: str, data: Dict = None) -> str:
        return self.add_node("goal", goal, data, status="running")

    def add_intent(self, label: str, data: Dict = None, parent_id: str = None,
                   asset_ref: str = None) -> str:
        return self.add_node("intent", label, data, status="pending",
                             parent_id=parent_id, asset_ref=asset_ref)

    def add_fact(self, label: str, data: Dict = None, parent_id: str = None,
                 asset_ref: str = None) -> str:
        return self.add_node("fact", label, data, status="done",
                             parent_id=parent_id, asset_ref=asset_ref)

    def add_finding(self, label: str, data: Dict = None, parent_id: str = None,
                    asset_ref: str = None) -> str:
        return self.add_node("finding", label, data, status="done",
                             parent_id=parent_id, asset_ref=asset_ref)

    def add_hint(self, label: str, data: Dict = None, parent_id: str = None) -> str:
        return self.add_node("hint", label, data, status="done", parent_id=parent_id)

    # ---------- 查询 ----------
    def intents(self, status: str = None) -> List[dict]:
        if status:
            rows = self.db.query(
                "SELECT * FROM nodes WHERE task_id=? AND kind='intent' AND status=?"
                " ORDER BY created_at", (self.task_id, status))
        else:
            rows = self.db.query(
                "SELECT * FROM nodes WHERE task_id=? AND kind='intent' ORDER BY created_at",
                (self.task_id,))
        return self._decode(rows)

    def findings(self) -> List[dict]:
        rows = self.db.query(
            "SELECT * FROM nodes WHERE task_id=? AND kind='finding' ORDER BY created_at",
            (self.task_id,))
        return self._decode(rows)

    def facts(self, limit: int = 200) -> List[dict]:
        rows = self.db.query(
            "SELECT * FROM nodes WHERE task_id=? AND kind='fact' ORDER BY created_at DESC LIMIT ?",
            (self.task_id, limit))
        return self._decode(rows)

    def pending_or_running(self) -> List[dict]:
        rows = self.db.query(
            "SELECT * FROM nodes WHERE task_id=? AND kind='intent' AND status IN"
            " ('pending','running') ORDER BY created_at", (self.task_id,))
        return self._decode(rows)

    @staticmethod
    def _decode(rows: List[dict]) -> List[dict]:
        for r in rows:
            r["data"] = jload(r["data"], {})
        return rows

    def graph(self) -> Dict[str, list]:
        nodes = self._decode(self.db.query(
            "SELECT * FROM nodes WHERE task_id=?", (self.task_id,)))
        edges = self.db.query("SELECT src_id,dst_id,rel FROM edges WHERE task_id=?",
                              (self.task_id,))
        return {
            "nodes": [{"id": n["id"], "kind": n["kind"], "label": n["label"],
                       "status": n["status"], "data": n["data"],
                       "asset_ref": n["asset_ref"]} for n in nodes],
            "links": [{"source": e["src_id"], "target": e["dst_id"], "rel": e["rel"]}
                      for e in edges],
        }

    # ---------- 详情（供 WebUI 悬浮/双击弹窗） ----------
    def detail(self, node_id: str) -> Dict:
        """单个探索图节点详情：父子、边、关联资产、相关工具调用。"""
        n = self.db.query_one("SELECT * FROM nodes WHERE id=? AND task_id=?",
                              (node_id, self.task_id))
        if not n:
            return {"ok": False, "error": f"节点不存在: {node_id}"}
        n["data"] = jload(n["data"], {})

        parent = None
        if n.get("parent_id"):
            parent = self.db.query_one(
                "SELECT id, kind, label, status FROM nodes WHERE id=?", (n["parent_id"],))
        children = self.db.query(
            "SELECT id, kind, label, status FROM nodes WHERE parent_id=? ORDER BY created_at",
            (node_id,))

        eout = self.db.query("SELECT src_id, dst_id, rel FROM edges WHERE task_id=? AND src_id=?",
                             (self.task_id, node_id))
        ein = self.db.query("SELECT src_id, dst_id, rel FROM edges WHERE task_id=? AND dst_id=?",
                            (self.task_id, node_id))
        ids = [e["dst_id"] for e in eout] + [e["src_id"] for e in ein]
        labels = {}
        if ids:
            ph = ",".join("?" * len(ids))
            for r in self.db.query(
                    f"SELECT id, kind, label, status FROM nodes WHERE id IN ({ph})", ids):
                labels[r["id"]] = r
        edges = ([{"rel": e["rel"], "direction": "out", "node": labels.get(e["dst_id"])}
                  for e in eout]
                 + [{"rel": e["rel"], "direction": "in", "node": labels.get(e["src_id"])}
                    for e in ein])

        asset = None
        if n.get("asset_ref"):
            asset = self.db.query_one(
                "SELECT id, kind, label FROM assets WHERE label=? OR key=? LIMIT 1",
                (n["asset_ref"], n["asset_ref"]))

        calls = self.db.query(
            "SELECT id, tool, status, result_summary, started_at, duration_ms"
            " FROM tool_calls WHERE task_id=? AND intent_id=? ORDER BY started_at LIMIT 30",
            (self.task_id, node_id))

        return {"ok": True, "node": n, "parent": parent, "children": children,
                "edges": edges, "asset": asset, "tool_calls": calls}

    # ---------- 给 Planner 的态势摘要 ----------
    def digest_for_planner(self, max_facts: int = 25) -> str:
        lines = []
        done = [i for i in self.intents() if i["status"] == "done"]
        pending = self.pending_or_running()
        lines.append(f"### 已完成意图 ({len(done)})")
        for i in done[-12:]:
            lines.append(f"  [done] {i['label']}")
        lines.append(f"### 待办/进行中意图 ({len(pending)})")
        for i in pending:
            lines.append(f"  [{i['status']}] {i['id']} {i['label']}")
        # 关键事实：被压缩过的历史事实不再逐条呈现（只留摘要 + 最近事实），控制 token
        all_facts = self.facts(max(max_facts * 3, max_facts))
        summaries = [f for f in all_facts
                     if (f.get("data") or {}).get("compressed_summary")]
        live = [f for f in all_facts
                if not (f.get("data") or {}).get("compressed")
                and not (f.get("data") or {}).get("compressed_summary")]
        lines.append(f"### 关键事实 (最近 {len(live[:max_facts])})")
        for f in live[:max_facts]:
            lines.append(f"  - {f['label']}")
        for s in summaries[:3]:
            d = s.get("data") or {}
            lines.append(f"### 历史事实摘要（已压缩 {d.get('count', 0)} 条）")
            digest = (d.get("digest") or "").strip()
            if digest:
                lines.append(digest[:1500])
        fs = self.findings()
        lines.append(f"### 已发现漏洞 ({len(fs)})")
        for f in fs:
            sev = (f.get("data") or {}).get("severity", "")
            lines.append(f"  - [{sev}] {f['label']}")
        return "\n".join(lines)
