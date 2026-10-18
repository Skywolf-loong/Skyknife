"""
任务调度与会话持久化。

- 新建任务：分配任务号 -> 落库 -> 运行 Orchestrator
- 断点续跑：探索图/资产图已持久化，resume 直接复用 task_id 继续未完成意图
- 批量任务：多目标顺序/并发执行
"""
import re
from typing import Dict, List, Optional

from .llm import LLMClient
from .orchestrator import Orchestrator
from .store import SessionStore
from .store.db import get_db
from .tools import ToolRegistry


def next_task_id(db=None) -> str:
    db = db or get_db()
    rows = db.query("SELECT id FROM tasks")
    mx = 0
    for r in rows:
        m = re.fullmatch(r"T(\d+)", r["id"] or "")
        if m:
            mx = max(mx, int(m.group(1)))
    return f"T{mx + 1}"


def _make_llm(session_store, task_id, dry_run=False):
    if dry_run:
        from .llm import DryRunLLM
        return DryRunLLM(session_store=session_store, task_id=task_id)
    return LLMClient(session_store=session_store, task_id=task_id)


def run_task(target: str, mode: str = "SRC", scope: str = "", name: str = "",
             max_rounds: int = 20, max_workers: int = 3, planner_max_intents: int = 5,
             worker_max_steps: int = 5, tools: ToolRegistry = None,
             llm=None, db=None, task_id: Optional[str] = None,
             dry_run: bool = False) -> Dict:
    """创建并运行一个任务；若给定 task_id 则复用（续跑）。"""
    db = db or get_db()
    ss = SessionStore(db)
    tools = tools or ToolRegistry("skills")

    task_id = task_id or next_task_id(db)
    existing = ss.get_task(task_id)
    if not existing:
        ss.create_task(task_id, name or target, target, scope, mode,
                       config={"max_rounds": max_rounds, "max_workers": max_workers})
    llm = llm or _make_llm(ss, task_id, dry_run=dry_run)

    orch = Orchestrator(llm, tools, task_id, target, scope=scope or target, mode=mode,
                        max_rounds=max_rounds, max_workers=max_workers,
                        planner_max_intents=planner_max_intents,
                        worker_max_steps=worker_max_steps, db=db)
    return orch.run()


def resume_task(task_id: str, tools: ToolRegistry = None, llm=None, db=None,
                max_rounds: int = 20, max_workers: int = 3) -> Dict:
    """断点续跑：复用既有任务与双图，继续推进未完成意图。"""
    db = db or get_db()
    ss = SessionStore(db)
    t = ss.get_task(task_id)
    if not t:
        raise ValueError(f"任务不存在: {task_id}")
    tools = tools or ToolRegistry("skills")
    llm = llm or _make_llm(ss, task_id)
    orch = Orchestrator(llm, tools, task_id, t["target"], scope=t.get("scope") or t["target"],
                        mode=t.get("mode") or "SRC", max_rounds=max_rounds,
                        max_workers=max_workers, db=db)
    return orch.run()


def run_batch(items: List[Dict], tools: ToolRegistry = None, llm=None, db=None,
              **kw) -> List[Dict]:
    """
    批量任务。items: [{"target":..,"mode":..,"scope":..,"name":..}, ...]
    顺序执行（避免同一 IP 段相互干扰）；如需并发可自行用线程包裹。
    """
    db = db or get_db()
    tools = tools or ToolRegistry("skills")
    results = []
    for it in items:
        try:
            r = run_task(target=it["target"], mode=it.get("mode", "SRC"),
                         scope=it.get("scope", ""), name=it.get("name", ""),
                         tools=tools, llm=llm, db=db, **kw)
        except Exception as e:
            r = {"target": it.get("target"), "error": str(e)}
        results.append(r)
    return results
