"""
Planner 跨唤醒共享的**规划待办**（Planning Todo）。

对应 ARTEX 的「难点一」：
    planner 是事件驱动的，图一变就被唤醒，但每次唤醒都是**一次全新的会话**——
    它不记得上一轮想过什么。而真实攻击链往往是有前后依赖的多步序列
    （发现注入点 → 拿到凭据 → 横向 → 提权），一次性并行派下去只会乱套。

解法：把一条**串行利用链按任务持久化一次**（挂在 task_id 上，而非某次 LLM 调用上），
之后每轮由程序而非模型来决定该派哪一步：

    * 一步 ready ⟺ 它的前置步骤(deps)全部 done，且它依赖的事实(requires)全部已落图
    * 一步 done  ⟺ 它声明要产出的事实(produces)已经出现在探索图里

于是这条链在「事件驱动 + 无状态会话」环境下仍能稳定推进：**不重复、不错序、不遗漏**。

关键分工（与 ARTEX 一致）：
    让 LLM 负责「下一步该做什么」，不让 LLM 负责「这条链走到哪了、谁该先跑」——
    后者是确定性的活儿，交给程序算。
"""
import time
from typing import Dict, List, Optional

from .store.db import jdump, jload

_SCHEMA = """
CREATE TABLE IF NOT EXISTS planner_todos (
    task_id     TEXT NOT NULL,
    step_id     TEXT NOT NULL,
    label       TEXT,
    tool        TEXT,
    args        TEXT,
    deps        TEXT,
    requires    TEXT,
    produces    TEXT,
    status      TEXT DEFAULT 'pending',
    evidence    TEXT,
    intent_ref  TEXT,
    created_at  REAL,
    updated_at  REAL,
    PRIMARY KEY (task_id, step_id)
)
"""


class PlanningTodo:
    """单个任务的规划待办，跨 planner 唤醒共享。"""

    STATUS_PENDING = "pending"
    STATUS_DONE = "done"
    STATUS_SKIPPED = "skipped"

    def __init__(self, db, task_id: str):
        self.db = db
        self.task_id = task_id
        db.execute(_SCHEMA)

    # ------------------------------------------------------------------
    # 写入：幂等地登记一条链（重复登记不会覆盖已有步骤的状态）
    # ------------------------------------------------------------------
    def sync(self, steps: List[dict]) -> int:
        """按 task 幂等同步一条利用链，返回新增的步骤数。

        step 形如：
            {"id":"s1","label":"识别注入点","deps":[],"requires":[],
             "produces":["注入点"],"tool":"sql_injection","args":{...}}
        """
        added = 0
        for idx, s in enumerate(steps or []):
            sid = str(s.get("id") or f"s{idx+1}")
            if self.db.query_one(
                    "SELECT 1 FROM planner_todos WHERE task_id=? AND step_id=?",
                    (self.task_id, sid)):
                continue  # 已存在：不重置状态，保证跨唤醒累积
            ts = time.time()
            self.db.execute(
                "INSERT INTO planner_todos(task_id,step_id,label,tool,args,deps,"
                "requires,produces,status,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (self.task_id, sid, s.get("label") or sid, s.get("tool"),
                 jdump(s.get("args") or {}), jdump(s.get("deps") or []),
                 jdump(s.get("requires") or []), jdump(s.get("produces") or []),
                 self.STATUS_PENDING, ts, ts))
            added += 1
        return added

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def steps(self) -> List[dict]:
        rows = self.db.query(
            "SELECT * FROM planner_todos WHERE task_id=? ORDER BY created_at",
            (self.task_id,))
        return [self._dec(r) for r in rows]

    @staticmethod
    def _dec(r: dict) -> dict:
        return {
            "id": r["step_id"], "label": r["label"], "tool": r["tool"],
            "args": jload(r["args"], {}), "deps": jload(r["deps"], []),
            "requires": jload(r["requires"], []), "produces": jload(r["produces"], []),
            "status": r["status"], "evidence": r["evidence"], "intent_ref": r["intent_ref"],
        }

    # ------------------------------------------------------------------
    # 核心：由程序而非模型决定「这一轮该做什么」
    # ------------------------------------------------------------------
    @staticmethod
    def _matched(patterns: List[str], hay: str) -> bool:
        """所有 pattern 都要能在 hay 里找到（大小写不敏感子串匹配）。"""
        hay = (hay or "").lower()
        return all(str(p).lower() in hay for p in patterns)

    def _facts_text(self, facts: List[str]) -> str:
        return " || ".join(str(f) for f in facts or [])

    def one(self, step_id: str) -> Optional[dict]:
        r = self.db.query_one(
            "SELECT * FROM planner_todos WHERE task_id=? AND step_id=?",
            (self.task_id, step_id))
        return self._dec(r) if r else None

    def advance_by_facts(self, facts: List[str]) -> List[str]:
        """凡是 produces 的事实已经到齐的步骤，自动标记完成。返回被完成的 step_id。"""
        hay = self._facts_text(facts)
        done = []
        for s in self.steps():
            if s["status"] != self.STATUS_PENDING:
                continue
            if s["produces"] and self._matched(s["produces"], hay):
                self.mark_done(s["id"], evidence="由已产出事实自动完成")
                done.append(s["id"])
        return done

    def ready(self, facts: List[str], limit: int = 1) -> List[dict]:
        """返回当前**可执行**的步骤：前置步骤全部完成 + 依赖事实全部具备。

        这是每轮真正会被派发下去的东西；多数情况下应为 0 条 —— **允许什么都不派**，
        这是自主 agent 能收敛而不是无限空转的关键。
        """
        hay = self._facts_text(facts)
        status = {s["id"]: s["status"] for s in self.steps()}
        out = []
        for s in self.steps():
            if s["status"] != self.STATUS_PENDING:
                continue
            if not all(status.get(d) == self.STATUS_DONE or d not in status
                       for d in s["deps"]):
                continue
            if s["requires"] and not self._matched(s["requires"], hay):
                continue
            out.append(s)
            if len(out) >= limit:
                break
        return out

    # ------------------------------------------------------------------
    # 状态迁移
    # ------------------------------------------------------------------
    def mark_done(self, step_id: str, evidence: str = "", intent_ref: str = ""):
        r = self.db.query_one(
            "SELECT status FROM planner_todos WHERE task_id=? AND step_id=?",
            (self.task_id, step_id))
        if not r or r["status"] == self.STATUS_DONE:
            return False
        self.db.execute(
            "UPDATE planner_todos SET status=?, evidence=?, intent_ref=?, updated_at=?"
            " WHERE task_id=? AND step_id=?",
            (self.STATUS_DONE, evidence, intent_ref, time.time(),
             self.task_id, step_id))
        return True

    def mark_skipped(self, step_id: str, reason: str = ""):
        self.db.execute(
            "UPDATE planner_todos SET status=?, evidence=?, updated_at=?"
            " WHERE task_id=? AND step_id=?",
            (self.STATUS_SKIPPED, reason, time.time(), self.task_id, step_id))

    # ------------------------------------------------------------------
    def snapshot(self) -> Dict:
        """给 planner / UI 看的整链进度摘要。"""
        ss = self.steps()
        return {
            "total": len(ss),
            "done": sum(1 for s in ss if s["status"] == self.STATUS_DONE),
            "pending": sum(1 for s in ss if s["status"] == self.STATUS_PENDING),
            "skipped": sum(1 for s in ss if s["status"] == self.STATUS_SKIPPED),
            "steps": ss,
        }

    def digest(self) -> str:
        """渲染成给 LLM 看的文本：只描述状态，不让它自己判断顺序。"""
        lines = []
        for s in self.steps():
            flag = {"pending": "未开始", "done": "已完成", "skipped": "已跳过"}.get(
                s["status"], s["status"])
            extra = []
            if s["deps"]:
                extra.append("依赖步骤:" + ",".join(s["deps"]))
            if s["requires"]:
                extra.append("需事实:" + ",".join(s["requires"]))
            if s["produces"]:
                extra.append("产出:" + ",".join(s["produces"]))
            lines.append(f"- [{flag}] {s['id']} {s['label']}"
                         + (f" （{'；'.join(extra)}）" if extra else ""))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    def clear(self):
        self.db.execute("DELETE FROM planner_todos WHERE task_id=?", (self.task_id,))
