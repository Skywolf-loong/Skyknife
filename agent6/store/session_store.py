"""任务/会话存储：tasks、events(活动流)、tool_calls、llm_usage(Token 统计)。"""
import time
from typing import Dict, List, Optional

from .db import jdump, jload, now


class SessionStore:
    def __init__(self, db):
        self.db = db

    # ---------- 任务 ----------
    def create_task(self, task_id: str, name: str, target: str, scope: str = "",
                    mode: str = "SRC", config: Dict = None, status: str = "pending"):
        self.db.execute(
            "INSERT OR REPLACE INTO tasks(id,name,target,scope,mode,status,created_at,config)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (task_id, name, target, scope, mode, status, now(), jdump(config or {})),
        )
        return task_id

    def start_task(self, task_id: str):
        self.db.execute("UPDATE tasks SET status='running', started_at=? WHERE id=?",
                        (now(), task_id))

    def finish_task(self, task_id: str, status: str = "done"):
        self.db.execute("UPDATE tasks SET status=?, finished_at=? WHERE id=?",
                        (status, now(), task_id))

    def delete_task(self, task_id: str, keep_assets: bool = False) -> Dict:
        """
        删除任务及其全部关联数据（事件流 / 工具调用 / Token 统计 / 探索图 / 资产图归属）。

        资产图清理策略（keep_assets=False 时生效）：
        - 仅删除「本任务首次发现（first_task==task_id）且未被其它任务引用」的资产，
          连同其资产关系边一并删除；
        - 被其它任务通过探索图节点（asset_ref）引用的共享资产予以保留，
          避免误删跨任务共享的资产库。
        """
        t = self.get_task(task_id)
        if not t:
            return {"ok": False, "error": f"任务不存在: {task_id}"}
        if t.get("status") == "running":
            return {"ok": False, "error": "任务正在运行，请先停止后再删除"}

        # 顺序：先删依赖节点关系的边，再删节点，最后删任务本身
        deleted = {}
        for table in ("events", "tool_calls", "llm_usage", "edges", "nodes",
                      "exploration_anchors"):
            try:
                cur = self.db.execute(f"DELETE FROM {table} WHERE task_id=?", (task_id,))
                deleted[table] = cur.rowcount if cur.rowcount > 0 else 0
            except Exception as e:
                deleted[table] = f"error: {e}"

        # 资产图清理：删除本任务独有资产（保留被其它任务引用的共享资产）
        assets_removed = 0
        if not keep_assets:
            owned = [r["key"] for r in
                     self.db.query("SELECT key FROM assets WHERE first_task=?", (task_id,))]
            # 其它任务通过探索图节点 asset_ref 引用的资产 key
            ref_keys = set()
            for r in self.db.query(
                    "SELECT DISTINCT asset_ref FROM nodes "
                    "WHERE task_id<>? AND asset_ref IS NOT NULL AND asset_ref<>''",
                    (task_id,)):
                ref_keys.add(r["asset_ref"])
            for key in owned:
                if key in ref_keys:
                    continue
                a = self.db.query_one("SELECT id FROM assets WHERE key=?", (key,))
                if a:
                    self.db.execute("DELETE FROM asset_edges WHERE src_id=? OR dst_id=?",
                                    (a["id"], a["id"]))
                    # 级联清理指向该资产的锚点（避免资产删除后锚点悬空）
                    self.db.execute("DELETE FROM exploration_anchors WHERE asset_id=?",
                                    (a["id"],))
                    self.db.execute("DELETE FROM assets WHERE id=?", (a["id"],))
                    assets_removed += 1

        self.db.execute("DELETE FROM tasks WHERE id=?", (task_id,))
        deleted["tasks"] = 1
        deleted["assets"] = assets_removed
        return {"ok": True, "task_id": task_id, "deleted": deleted,
                "assets_kept": keep_assets}

    def get_task(self, task_id: str) -> Optional[dict]:
        r = self.db.query_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if r:
            r["config"] = jload(r["config"], {})
        return r

    def list_tasks(self, limit: int = 100) -> List[dict]:
        rows = self.db.query("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,))
        for r in rows:
            r["config"] = jload(r["config"], {})
        return rows

    def task_token_total(self, task_id: str) -> Dict[str, int]:
        r = self.db.query_one(
            "SELECT COALESCE(SUM(prompt_tokens),0) p, COALESCE(SUM(completion_tokens),0) c,"
            " COALESCE(SUM(total_tokens),0) t FROM llm_usage WHERE task_id=?", (task_id,))
        return {"prompt": r["p"], "completion": r["c"], "total": r["t"]}

    # ---------- 事件流 ----------
    def add_event(self, task_id: str, etype: str, message: str, actor: str = "system",
                  data: Dict = None):
        self.db.execute(
            "INSERT INTO events(task_id,ts,type,actor,message,data) VALUES(?,?,?,?,?,?)",
            (task_id, now(), etype, actor, message, jdump(data or {})),
        )

    def events(self, task_id: str = None, limit: int = 200) -> List[dict]:
        if task_id:
            rows = self.db.query(
                "SELECT * FROM events WHERE task_id=? ORDER BY ts DESC LIMIT ?",
                (task_id, limit))
        else:
            rows = self.db.query("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
        for r in rows:
            r["data"] = jload(r["data"], {})
        return rows

    # ---------- 工具调用 ----------
    def log_tool_call(self, task_id: str, intent_id: str, tool: str, args: Dict,
                      status: str, result_summary: str, raw=None,
                      started_at: float = None, duration_ms: int = None,
                      request: str = None, response: str = None):
        traffic = None
        if request is not None or response is not None:
            traffic = jdump({"request": request, "response": response})
        self.db.execute(
            "INSERT INTO tool_calls(task_id,intent_id,tool,args,status,result_summary,raw,"
            "started_at,finished_at,duration_ms,traffic) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (task_id, intent_id, tool, jdump(args or {}), status,
             (result_summary or "")[:2000], jdump(raw) if raw is not None else None,
             started_at or now(), now(), duration_ms, traffic),
        )

    def tool_calls(self, task_id: str, limit: int = 200) -> List[dict]:
        rows = self.db.query(
            "SELECT * FROM tool_calls WHERE task_id=? ORDER BY started_at DESC LIMIT ?",
            (task_id, limit))
        for r in rows:
            r["args"] = jload(r["args"], {})
            r["traffic"] = jload(r["traffic"], None)
        return rows

    # ---------- LLM Token ----------
    def log_usage(self, task_id: str, agent: str, model: str,
                  prompt_tokens: int = 0, completion_tokens: int = 0):
        total = (prompt_tokens or 0) + (completion_tokens or 0)
        self.db.execute(
            "INSERT INTO llm_usage(task_id,agent,model,prompt_tokens,completion_tokens,"
            "total_tokens,created_at) VALUES(?,?,?,?,?,?,?)",
            (task_id, agent, model, prompt_tokens, completion_tokens, total, now()),
        )

    # ---------- 总览 ----------
    def overview(self, task_id: str) -> Dict:
        t = self.get_task(task_id) or {}
        tok = self.task_token_total(task_id)
        n_events = (self.db.query_one(
            "SELECT COUNT(*) c FROM events WHERE task_id=?", (task_id,)) or {}).get("c", 0)
        n_calls = (self.db.query_one(
            "SELECT COUNT(*) c FROM tool_calls WHERE task_id=?", (task_id,)) or {}).get("c", 0)
        return {"task": t, "tokens": tok, "events": n_events, "tool_calls": n_calls}
