"""
Worker **过程（trace）存储与跨 work 检索**。

对应 ARTEX 的「难点二」：
    一次深入探索里，很多有价值的观察（某个报错、某段响应、某个隐藏参数）出现在
    某个 worker 的执行过程中，却未必被总结成一条正式的 fact。如果只有「事实」能在
    agent 之间传递，这些中间观察就随会话一起消失了，后面的 worker 只能重踩一遍。

于是让 worker 具备**读取同任务其它 work 的执行过程**的能力：
    * list_worker_traces          先看本任务有哪些 work 跑过
    * get_worker_trace(intent_id, step_ids)  取某个 work 具体几步的完整内容
    * search_all_worker_traces(q) 按关键字在本任务其它 work 的过程里检索

边界纪律（重点，别顺手把职责也放宽了）：
    这些工具**只读**。拿到 process 信息的 worker 仍然只对自己领到的那条意图负责，
    不会因为看到别人过程里的线索就擅自改 todo 或去执行别人的意图。
    检索默认**排除调用者自己这条 intent**，避免自我干扰。
"""
import time
from typing import Dict, List, Optional

from .db import jdump, jload

_SCHEMA = """
CREATE TABLE IF NOT EXISTS worker_traces (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id    TEXT NOT NULL,
    intent_id  TEXT NOT NULL,
    step       INTEGER NOT NULL,
    kind       TEXT,
    content    TEXT,
    created_at REAL
)
"""
_INDEX = """
CREATE INDEX IF NOT EXISTS idx_traces_task_intent
    ON worker_traces(task_id, intent_id, step)
"""


class TraceStore:
    def __init__(self, db, task_id: str):
        self.db = db
        self.task_id = task_id
        db.execute(_SCHEMA)
        db.execute(_INDEX)

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------
    def record(self, intent_id: str, step: int, kind: str, content) -> int:
        if isinstance(content, (dict, list)):
            content = jdump(content)
        self.db.execute(
            "INSERT INTO worker_traces(task_id,intent_id,step,kind,content,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (self.task_id, str(intent_id), int(step), str(kind or ""),
             str(content or ""), time.time()))
        return self._last_id()

    def _last_id(self) -> int:
        r = self.db.query_one("SELECT last_insert_rowid() AS id")
        return (r or {}).get("id", 0)

    # ------------------------------------------------------------------
    # 读取
    # ------------------------------------------------------------------
    def list_traces(self) -> List[dict]:
        """列出本任务所有 work 的过程概览（按 intent 聚合）。"""
        rows = self.db.query(
            "SELECT intent_id, COUNT(*) steps, MAX(step) last_step,"
            " MAX(created_at) updated_at FROM worker_traces"
            " WHERE task_id=? GROUP BY intent_id ORDER BY updated_at DESC",
            (self.task_id,))
        out = []
        for r in rows:
            first = self.db.query_one(
                "SELECT content FROM worker_traces WHERE task_id=? AND intent_id=?"
                " ORDER BY step LIMIT 1", (self.task_id, r["intent_id"]))
            out.append({"intent_id": r["intent_id"], "steps": r["steps"],
                        "last_step": r["last_step"],
                        "preview": ((first or {}).get("content") or "")[:160]})
        return out

    def get_trace(self, intent_id: str,
                  step_ids: Optional[List[int]] = None) -> List[dict]:
        """取某个 work 的步骤内容；step_ids 可精确定位到几步。"""
        if step_ids:
            ph = ",".join("?" * len(step_ids))
            rows = self.db.query(
                f"SELECT step,kind,content,created_at FROM worker_traces"
                f" WHERE task_id=? AND intent_id=? AND step IN ({ph})"
                f" ORDER BY step", [self.task_id, intent_id, *step_ids])
        else:
            rows = self.db.query(
                "SELECT step,kind,content,created_at FROM worker_traces"
                " WHERE task_id=? AND intent_id=? ORDER BY step",
                (self.task_id, intent_id))
        return [{"step": r["step"], "kind": r["kind"], "content": r["content"]}
                for r in rows]

    def search(self, query: str, exclude_intent_id: str = None,
               limit: int = 20, snippet: int = 260) -> List[dict]:
        """在**本任务**的过程里做关键字检索（大小写不敏感子串，多词 AND）。

        默认排除调用者自己的 intent（ARTEX 的做法），避免自我干扰；
        命中项带 intent_id 与 step，便于回溯到具体那一步的完整内容。
        """
        q = (query or "").strip()
        if not q:
            return []
        words = [w for w in q.replace("，", " ").split() if w]
        if not words:
            return []

        sql = "SELECT intent_id, step, kind, content FROM worker_traces WHERE task_id=?"
        args: List = [self.task_id]
        for w in words:
            sql += " AND LOWER(content) LIKE LOWER(?)"
            args.append(f"%{w}%")
        if exclude_intent_id:
            sql += " AND intent_id<>?"
            args.append(str(exclude_intent_id))
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(int(limit))

        out = []
        for r in self.db.query(sql, args):
            c = r["content"] or ""
            low, hit = c.lower(), -1
            for w in words:
                hit = max(hit, low.find(w.lower()))
            start = max(0, hit - snippet // 3) if hit >= 0 else 0
            out.append({"intent_id": r["intent_id"], "step": r["step"],
                        "kind": r["kind"],
                        "snippet": c[start:start + snippet]})
        return out

    def purge_task(self):
        self.db.execute("DELETE FROM worker_traces WHERE task_id=?", (self.task_id,))
