"""
资产图（Asset Graph）—— 全局共享，多任务复用。

节点类型(kind)：
    root_domain  根域名      key: dom:example.com
    subdomain    子域名      key: dom:sub.example.com
    ip           IP          key: ip:1.2.3.4
    port         IP:端口     key: port:1.2.3.4:80
    service      服务        key: svc:1.2.3.4:80:nginx
    webapp       Web 站点    key: web:https://x/
    endpoint     接口端点    key: ep:https://x/path?method=GET

边(rel)：
    resolves_to  域名 -> IP
    has_port     域名/IP -> port
    runs_service port -> service
    hosts_app    port/域名 -> webapp
    has_endpoint webapp -> endpoint
    subdomain_of 子域名 -> 根域名
"""
import time
from typing import Dict, List, Optional

from .db import jdump, jload, now


class AssetGraph:
    def __init__(self, db):
        self.db = db

    # ---------- 节点 ----------
    def upsert(self, kind: str, key: str, label: str, props: Dict = None,
               task_id: str = None) -> int:
        """按 key 去重 upsert，返回资产 id。已存在则合并 props 并更新 last_seen。"""
        props = props or {}
        ts = now()
        row = self.db.query_one("SELECT id, props FROM assets WHERE key=?", (key,))
        if row:
            merged = jload(row["props"], {}) or {}
            merged.update(props)
            self.db.execute(
                "UPDATE assets SET label=?, props=?, last_seen=? WHERE id=?",
                (label, jdump(merged), ts, row["id"]),
            )
            return row["id"]
        cur = self.db.execute(
            "INSERT INTO assets(kind,key,label,props,first_task,first_seen,last_seen)"
            " VALUES(?,?,?,?,?,?,?)",
            (kind, key, label, jdump(props), task_id, ts, ts),
        )
        return cur.lastrowid

    def get_id(self, key: str) -> Optional[int]:
        r = self.db.query_one("SELECT id FROM assets WHERE key=?", (key,))
        return r["id"] if r else None

    def link(self, src_key: str, dst_key: str, rel: str, props: Dict = None):
        sid = self.get_id(src_key)
        did = self.get_id(dst_key)
        if sid is None or did is None:
            return False
        self.db.execute(
            "INSERT OR IGNORE INTO asset_edges(src_id,dst_id,rel,props) VALUES(?,?,?,?)",
            (sid, did, rel, jdump(props or {})),
        )
        return True

    # ---------- 高层写入（供 Worker 调用） ----------
    def add_domain(self, domain: str, task_id=None, props=None) -> int:
        return self.upsert("root_domain", f"dom:{domain}", domain, props, task_id)

    def add_subdomain(self, sub: str, parent: str = None, task_id=None, props=None) -> int:
        aid = self.upsert("subdomain", f"dom:{sub}", sub, props, task_id)
        if parent:
            self.add_domain(parent, task_id)
            self.link(f"dom:{sub}", f"dom:{parent}", "subdomain_of")
        return aid

    def add_ip(self, ip: str, domain: str = None, task_id=None, props=None) -> int:
        aid = self.upsert("ip", f"ip:{ip}", ip, props, task_id)
        if domain:
            self.add_domain(domain, task_id)
            self.link(f"dom:{domain}", f"ip:{ip}", "resolves_to")
        return aid

    def add_port(self, ip: str, port: int, domain: str = None, task_id=None,
                 service: str = None, props=None) -> str:
        self.add_ip(ip, domain, task_id)
        pkey = f"port:{ip}:{port}"
        p = dict(props or {})
        if service:
            p["service"] = service
        self.upsert("port", pkey, f"{ip}:{port}", p, task_id)
        # 连到 IP；若有域名则域名的 has_port（资产搜索可达）
        self.link(f"ip:{ip}", pkey, "has_port")
        if domain:
            self.link(f"dom:{domain}", pkey, "has_port")
        return pkey

    def add_service(self, ip: str, port: int, name: str, version: str = "",
                    task_id=None, props=None) -> str:
        pkey = f"port:{ip}:{port}"
        skey = f"svc:{ip}:{port}:{name}"
        p = dict(props or {})
        if version:
            p["version"] = version
        self.upsert("service", skey, f"{name} {version}".strip(), p, task_id)
        self.link(pkey, skey, "runs_service")
        return skey

    def add_webapp(self, url: str, ip: str = None, port: int = None, task_id=None,
                   props=None) -> str:
        wkey = f"web:{url.rstrip('/')}"
        self.upsert("webapp", wkey, url, props or {}, task_id)
        if ip and port:
            self.link(f"port:{ip}:{port}", wkey, "hosts_app")
        return wkey

    def add_endpoint(self, url: str, webapp_url: str = None, method: str = "GET",
                     task_id=None, props=None) -> str:
        ekey = f"ep:{method.upper()}:{url}"
        p = dict(props or {})
        p["method"] = method.upper()
        self.upsert("endpoint", ekey, url, p, task_id)
        if webapp_url:
            self.link(f"web:{webapp_url.rstrip('/')}", ekey, "has_endpoint")
        return ekey

    # ---------- 查询 / 可视化 ----------
    # ---------- 任务范围过滤（防止跨任务目标串扰） ----------
    @staticmethod
    def _task_filter(task_id, alias: str = "") -> str:
        """资产归属本任务的判定 SQL 片段：本任务首次发现，或被本任务节点锚定。

        多表 JOIN 时传 alias（如 'a'）消解列名歧义。
        """
        if not task_id:
            return ""
        p = f"{alias}." if alias else ""
        return (f" ({p}first_task=? OR {p}id IN ("
                "SELECT DISTINCT asset_id FROM exploration_anchors WHERE task_id=?))")

    @staticmethod
    def _task_params(task_id) -> tuple:
        return (task_id, task_id) if task_id else ()

    def stats(self, task_id: str = None) -> Dict[str, int]:
        if task_id:
            flt = self._task_filter(task_id, alias="a")
            rows = self.db.query(f"SELECT kind, COUNT(*) c FROM assets a WHERE {flt} GROUP BY kind",
                                 self._task_params(task_id))
            edge_total = (self.db.query_one(
                "SELECT COUNT(*) c FROM asset_edges e JOIN assets a ON a.id=e.src_id"
                f" WHERE {flt}", self._task_params(task_id)) or {}).get("c", 0)
        else:
            rows = self.db.query("SELECT kind, COUNT(*) c FROM assets GROUP BY kind")
            edge_total = (self.db.query_one(
                "SELECT COUNT(*) c FROM asset_edges") or {}).get("c", 0)
        out = {r["kind"]: r["c"] for r in rows}
        out["total"] = sum(out.values())
        out["edge_total"] = edge_total
        return out

    def list_assets(self, kind: str = None, limit: int = 500,
                    task_id: str = None) -> List[dict]:
        where, params = [], []
        if kind:
            where.append("kind=?"); params.append(kind)
        if task_id:
            where.append(self._task_filter(task_id).strip())
            params.extend(self._task_params(task_id))
        sql = "SELECT * FROM assets"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        rows = self.db.query(sql, tuple(params))
        for r in rows:
            r["props"] = jload(r["props"], {})
        return rows

    # ---------- 分页（供 WebUI 资产清单，避免一次拉取全部节点卡死） ----------
    def count_assets(self, kind: str = None, task_id: str = None,
                     q: str = None) -> int:
        where, params = [], []
        if kind:
            where.append("kind=?"); params.append(kind)
        if task_id:
            where.append(self._task_filter(task_id).strip())
            params.extend(self._task_params(task_id))
        if q:
            where.append("(label LIKE ? OR key LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        sql = "SELECT COUNT(*) c FROM assets"
        if where:
            sql += " WHERE " + " AND ".join(where)
        row = self.db.query_one(sql, tuple(params))
        return (row or {}).get("c", 0)

    def list_paged(self, page: int = 1, page_size: int = 50,
                   kind: str = None, task_id: str = None,
                   q: str = None) -> List[dict]:
        page = max(1, int(page or 1))
        page_size = max(1, min(int(page_size or 50), 500))
        offset = (page - 1) * page_size
        where, params = [], []
        if kind:
            where.append("kind=?"); params.append(kind)
        if task_id:
            where.append(self._task_filter(task_id).strip())
            params.extend(self._task_params(task_id))
        if q:
            where.append("(label LIKE ? OR key LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        sql = "SELECT * FROM assets"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([page_size, offset])
        rows = self.db.query(sql, tuple(params))
        for r in rows:
            r["props"] = jload(r["props"], {})
        return rows

    def digest(self, max_items: int = 40, task_id: str = None) -> str:
        """生成给 Planner/Worker 看的资产态势文本。

        task_id 给定时只呈现与本任务相关的资产（本任务发现或本任务锚定过），
        避免其它任务发现的目标被本任务误当成攻击面（跨任务串扰）。
        """
        st = self.stats(task_id=task_id)
        lines = [f"资产统计: " + ", ".join(f"{k}={v}" for k, v in st.items())]
        by_kind: Dict[str, list] = {}
        for a in self.list_assets(limit=max_items * 3, task_id=task_id):
            by_kind.setdefault(a["kind"], []).append(a)
        for kind in ["root_domain", "subdomain", "ip", "port", "service", "webapp", "endpoint"]:
            items = by_kind.get(kind, [])[:max_items]
            if not items:
                continue
            lines.append(f"## {kind} ({len(by_kind.get(kind, []))})")
            for a in items:
                extra = ""
                p = a.get("props") or {}
                if p.get("service"):
                    extra = f" ({p['service']}{('/' + p['version']) if p.get('version') else ''})"
                lines.append(f"  - {a['label']}{extra}")
        return "\n".join(lines)

    def graph(self, limit: int = None) -> Dict[str, list]:
        """返回 {nodes, links, total_nodes}，供 WebUI 力导向图渲染。

        limit>0 时**按节点优化**：仅返回「关联度（degree）最高」的前 limit 个节点
        及其相互之间的边，避免大图一次性传输 + 力导向 O(n²) 布局导致卡死；
        完整资产清单由 /api/assets 分页接口承载。
        """
        nodes = self.db.query(
            "SELECT id, kind, key, label, props, first_task, first_seen, last_seen"
            " FROM assets")
        edges = self.db.query("SELECT src_id, dst_id, rel FROM asset_edges")
        # 覆盖标记：有锚点的资产视为 covered
        covered_ids = {r["asset_id"] for r in self.db.query(
            "SELECT DISTINCT asset_id FROM exploration_anchors")}
        deg: Dict[int, int] = {}
        for e in edges:
            deg[e["src_id"]] = deg.get(e["src_id"], 0) + 1
            deg[e["dst_id"]] = deg.get(e["dst_id"], 0) + 1
        out_nodes = [{"id": n["id"], "kind": n["kind"], "key": n["key"],
                      "label": n["label"], "props": jload(n["props"], {}),
                      "first_task": n["first_task"], "first_seen": n["first_seen"],
                      "last_seen": n["last_seen"],
                      "degree": deg.get(n["id"], 0),
                      "covered": n["id"] in covered_ids} for n in nodes]
        total_nodes = len(out_nodes)
        if limit and limit > 0 and total_nodes > limit:
            out_nodes.sort(key=lambda x: x["degree"], reverse=True)
            out_nodes = out_nodes[:limit]
        keep = {n["id"] for n in out_nodes}
        links = [{"source": e["src_id"], "target": e["dst_id"], "rel": e["rel"]}
                 for e in edges
                 if e["src_id"] in keep and e["dst_id"] in keep]
        return {"nodes": out_nodes, "links": links, "total_nodes": total_nodes}

    # ---------- 探索锚点（Exploration Anchors） ----------
    def anchor(self, node_id: str, asset_id: int, task_id: str = None,
               relation: str = "targets") -> bool:
        """把探索图节点锚定到资产节点。asset_id 必须已存在，否则返回 False。"""
        try:
            aid = int(asset_id)
        except (TypeError, ValueError):
            return False
        row = self.db.query_one("SELECT id FROM assets WHERE id=?", (aid,))
        if not row:
            return False
        self.db.execute(
            "INSERT OR IGNORE INTO exploration_anchors"
            "(node_id,asset_id,task_id,relation,created_at) VALUES(?,?,?,?,?)",
            (node_id, aid, task_id, relation or "targets", now()))
        return True

    def anchor_by_key(self, node_id: str, asset_key: str, task_id: str = None,
                      relation: str = "targets") -> bool:
        """按资产 key（如 ip:1.2.3.4）或 label 锚定，自动解析为 asset_id。"""
        aid = self.resolve_asset_id(asset_key)
        if aid is None:
            return False
        return self.anchor(node_id, aid, task_id, relation)

    def resolve_asset_id(self, ref: str) -> Optional[int]:
        """按 key 或 label 精确匹配，返回 asset_id；找不到返回 None。"""
        if not ref:
            return None
        a = self.db.query_one(
            "SELECT id FROM assets WHERE key=? OR label=? LIMIT 1", (ref, ref))
        return a["id"] if a else None

    def anchors_for_asset(self, asset_id) -> List[dict]:
        try:
            aid = int(asset_id)
        except (TypeError, ValueError):
            return []
        rows = self.db.query(
            "SELECT a.id, a.node_id, a.asset_id, a.task_id, a.relation, a.created_at,"
            " n.kind, n.label FROM exploration_anchors a"
            " LEFT JOIN nodes n ON n.id=a.node_id WHERE a.asset_id=? ORDER BY a.created_at",
            (aid,))
        return rows

    def backfill_anchors(self) -> int:
        """从历史 nodes.asset_ref（软引用）幂等回填锚点表。

        asset_ref 存的是资产 label 或 key；精确匹配，避免 URL 场景的误锚。
        返回本次新增的锚点数。
        """
        added = 0
        rows = self.db.query(
            "SELECT id, task_id, asset_ref FROM nodes"
            " WHERE asset_ref IS NOT NULL AND asset_ref != ''")
        for r in rows:
            ref = r["asset_ref"]
            a = self.db.query_one(
                "SELECT id FROM assets WHERE label=? OR key=? LIMIT 1", (ref, ref))
            if not a:
                continue
            cur = self.db.execute(
                "INSERT OR IGNORE INTO exploration_anchors"
                "(node_id,asset_id,task_id,relation,created_at) VALUES(?,?,?,?,?)",
                (r["id"], a["id"], r["task_id"], "targets", now()))
            if cur.rowcount > 0:
                added += 1
        return added

    # ---------- 资产覆盖度（Asset Coverage） ----------
    def purge_orphan_anchors(self) -> int:
        """清理悬空锚点（asset_id 或 node_id 已不存在），返回删除条数。"""
        cur = self.db.execute(
            "DELETE FROM exploration_anchors WHERE asset_id NOT IN (SELECT id FROM assets)"
            " OR node_id NOT IN (SELECT id FROM nodes)")
        return cur.rowcount if cur.rowcount > 0 else 0

    def coverage(self) -> Dict:
        """统计资产覆盖度：哪些资产已被探索锚定（covered），哪些尚未覆盖。

        对标 ARTEX 的 asset coverage graph——用于引导 Planner 优先攻击未覆盖资产。
        """
        self.backfill_anchors()
        self.purge_orphan_anchors()
        total_row = self.db.query_one("SELECT COUNT(*) c FROM assets")
        total = (total_row or {}).get("c", 0)
        # 只统计真实存在的资产（JOIN），避免悬空锚点把 covered 撑过 total
        covered_row = self.db.query_one(
            "SELECT COUNT(DISTINCT ea.asset_id) c FROM exploration_anchors ea"
            " JOIN assets a ON a.id=ea.asset_id")
        covered = (covered_row or {}).get("c", 0)

        by_kind = {}
        for r in self.db.query("SELECT kind, COUNT(*) c FROM assets GROUP BY kind"):
            by_kind[r["kind"]] = {"total": r["c"], "covered": 0}
        for r in self.db.query(
                "SELECT a.kind, COUNT(DISTINCT ea.asset_id) c"
                " FROM exploration_anchors ea JOIN assets a ON a.id=ea.asset_id"
                " GROUP BY a.kind"):
            if r["kind"] in by_kind:
                by_kind[r["kind"]]["covered"] = r["c"]

        uncovered = self.db.query(
            "SELECT id, kind, key, label, last_seen FROM assets"
            " WHERE id NOT IN (SELECT DISTINCT asset_id FROM exploration_anchors)"
            " ORDER BY last_seen DESC LIMIT 500")
        for u in uncovered:
            u["last_seen"] = u.get("last_seen")

        return {
            "total": total,
            "covered": covered,
            "uncovered": max(0, total - covered),
            "coverage": round(covered / total, 4) if total else 0.0,
            "by_kind": by_kind,
            "uncovered_assets": uncovered,
        }

    # ---------- 详情（供 WebUI 悬浮/双击弹窗） ----------
    def detail(self, asset_id) -> Dict:
        """单个资产详情：属性 + 双向邻居 + 关联漏洞。"""
        try:
            aid = int(asset_id)
        except (TypeError, ValueError):
            return {"ok": False, "error": f"资产 ID 非法: {asset_id}"}
        a = self.db.query_one("SELECT * FROM assets WHERE id=?", (aid,))
        if not a:
            return {"ok": False, "error": f"资产不存在: {asset_id}"}
        a["props"] = jload(a["props"], {})

        out = self.db.query(
            "SELECT a.id, a.kind, a.label, r.rel FROM asset_edges r"
            " JOIN assets a ON a.id=r.dst_id WHERE r.src_id=?", (aid,))
        inn = self.db.query(
            "SELECT a.id, a.kind, a.label, r.rel FROM asset_edges r"
            " JOIN assets a ON a.id=r.src_id WHERE r.dst_id=?", (aid,))
        neighbors = ([dict(r, direction="out") for r in out]
                     + [dict(r, direction="in") for r in inn])

        # 关联漏洞：asset_ref 精确等于 label/key，或包含 label（URL 场景）
        label, key = a["label"], a["key"]
        findings = self.db.query(
            "SELECT id, task_id, kind, label, status, data FROM nodes"
            " WHERE kind='finding' AND (asset_ref=? OR asset_ref=? OR asset_ref LIKE ?)"
            " ORDER BY created_at DESC LIMIT 30",
            (label, key, f"%{label}%"))
        seen, uniq = set(), []
        for f in findings:
            if f["id"] in seen:
                continue
            seen.add(f["id"])
            f["data"] = jload(f["data"], {})
            uniq.append(f)

        return {"ok": True, "asset": a, "neighbors": neighbors, "findings": uniq}
