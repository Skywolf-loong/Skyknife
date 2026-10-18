"""
后台任务运行器 —— 供 Web 控制台发起 / 停止自主渗透任务。

- 任务在独立线程运行，主线程（HTTP 服务）不被阻塞
- ToolRegistry 全局复用（首次装载 skills 较慢，之后共享）
- 持有 Orchestrator 引用，支持从界面停止任务
"""
import threading
import traceback
from typing import Dict, Optional

_LOCK = threading.Lock()
_TOOLS = None
_TOOLS_LOCK = threading.Lock()
_RUNNING: Dict[str, dict] = {}


# ----------------------------------------------------------------------------
# 工具层（全局单例）
# ----------------------------------------------------------------------------
def get_tools():
    global _TOOLS
    with _TOOLS_LOCK:
        if _TOOLS is None:
            from ..tools import ToolRegistry
            _TOOLS = ToolRegistry("skills")
        return _TOOLS


def reload_tools():
    global _TOOLS
    with _TOOLS_LOCK:
        from ..tools import ToolRegistry
        _TOOLS = ToolRegistry("skills")
        return _TOOLS


def tools_count() -> int:
    """工具总数（含知识型 Skill，用于界面展示完整装备清单）。"""
    try:
        return len(get_tools().list_tools(include_knowledge=True))
    except Exception:
        return 0


# ----------------------------------------------------------------------------
# 任务启停
# ----------------------------------------------------------------------------
def _make_llm(ss, task_id: str, dry_run: bool):
    """
    构造 LLM 客户端。

    「设置 → LLM 配置」里保存的 base_url / model / temperature / max_tokens /
    timeout / api_key 全部生效；未保存过的字段回落到 config.yaml（由
    ``settings.default_settings()`` 保证合并结果始终完整）。
    """
    from ..llm import DryRunLLM, LLMClient
    if dry_run:
        return DryRunLLM(session_store=ss, task_id=task_id)
    cfg, api_key = {}, None
    try:
        from ..settings import load_settings
        llm = (load_settings().get("llm") or {})
        # 设置里的字段名 → LLMClient 读取的字段名（base_url 在客户端里叫 api_url）
        mapping = {"base_url": "api_url", "model": "model",
                   "temperature": "temperature", "max_tokens": "max_tokens",
                   "request_timeout": "request_timeout"}
        inner = {}
        for src, dst in mapping.items():
            v = llm.get(src)
            if v not in (None, ""):
                inner[dst] = v
        cfg = {"llm": inner}
        api_key = str(llm.get("api_key") or "") or None
    except Exception as e:
        print(f"[runner] 读取 LLM 设置失败，回落 config.yaml: {e}")
        cfg = {}
    return LLMClient(session_store=ss, task_id=task_id, cfg=cfg or None,
                     api_key=api_key)


def start_task(target: str, mode: str = "SRC", scope: str = "", name: str = "",
               workers: int = 3, rounds: int = 20, intents: int = 5,
               dry_run: bool = False, require_approval: bool = False,
               approval_timeout: int = 180, token_budget: int = 0,
               logic_agent: bool = True, context_compress: bool = True,
               compress_every: int = 3, chain_review: bool = True) -> str:
    """在后台线程启动一个自主渗透任务，返回 task_id。"""
    from ..orchestrator import Orchestrator
    from ..scheduler import next_task_id
    from ..store import SessionStore
    from ..store.db import get_db

    db = get_db()
    ss = SessionStore(db)
    task_id = next_task_id(db)
    scope = scope or target
    if not ss.get_task(task_id):
        ss.create_task(task_id, name or target, target, scope, mode,
                       config={"max_rounds": rounds, "max_workers": workers,
                               "planner_max_intents": intents, "dry_run": dry_run,
                               "require_approval": require_approval,
                               "approval_timeout": approval_timeout,
                               "logic_agent": logic_agent,
                               "chain_review": chain_review,
                               "context_compress": context_compress,
                               "compress_every": compress_every})

    def _work():
        orch = None
        try:
            llm = _make_llm(ss, task_id, dry_run)
            orch = Orchestrator(llm, get_tools(), task_id, target, scope=scope,
                                mode=mode, max_rounds=rounds, max_workers=workers,
                                planner_max_intents=intents, db=db,
                                require_approval=require_approval,
                                approval_timeout=approval_timeout,
                                token_budget=token_budget,
                                logic_agent=logic_agent,
                                context_compress=context_compress,
                                compress_every=compress_every,
                                chain_review=chain_review)
            with _LOCK:
                if task_id in _RUNNING:
                    _RUNNING[task_id]["orch"] = orch
            orch.run()
        except Exception as e:
            ss.add_event(task_id, "error", f"任务异常：{e}", "system")
            print(f"[runner] 任务 {task_id} 异常: {e}")
            traceback.print_exc()
            try:
                ss.finish_task(task_id, "failed")
            except Exception:
                pass
        finally:
            with _LOCK:
                _RUNNING.pop(task_id, None)

    th = threading.Thread(target=_work, daemon=True, name=f"task-{task_id}")
    with _LOCK:
        _RUNNING[task_id] = {"task_id": task_id, "target": target, "mode": mode,
                             "dry_run": dry_run, "thread": th, "orch": None}
    th.start()
    return task_id


def start_demo(target: str = "example.com", mode: str = "SRC") -> str:
    """后台灌入离线演示数据（无需 API Key）。"""
    from ..demo import seed_demo
    from ..scheduler import next_task_id
    from ..store import SessionStore
    from ..store.db import get_db

    db = get_db()
    ss = SessionStore(db)
    task_id = next_task_id(db)

    def _work():
        try:
            if not ss.get_task(task_id):
                ss.create_task(task_id, "演示任务", target, target, mode,
                               config={"demo": True})
            seed_demo(target=target, mode=mode, task_id=task_id, db=db)
        except Exception as e:
            ss.add_event(task_id, "error", f"演示数据生成失败：{e}", "system")
            print(f"[runner] demo 失败: {e}")
            traceback.print_exc()
        finally:
            with _LOCK:
                _RUNNING.pop(task_id, None)

    th = threading.Thread(target=_work, daemon=True, name=f"demo-{task_id}")
    with _LOCK:
        _RUNNING[task_id] = {"task_id": task_id, "target": target, "mode": mode,
                             "dry_run": True, "thread": th, "orch": None}
    th.start()
    return task_id


def stop_task(task_id: str) -> bool:
    with _LOCK:
        item = _RUNNING.get(task_id)
        if not item:
            return False
        orch = item.get("orch")
    if orch:
        try:
            orch.stop()
            return True
        except Exception:
            return False
    return False


def running() -> Dict[str, dict]:
    with _LOCK:
        return {k: {"task_id": k, "target": v["target"], "mode": v["mode"],
                    "dry_run": v["dry_run"], "alive": v["thread"].is_alive()}
                for k, v in _RUNNING.items()}


def is_running(task_id: str) -> bool:
    with _LOCK:
        return task_id in _RUNNING


def reconcile_orphaned_tasks() -> int:
    """
    进程启动后调用：把数据库里残留的 running 任务标记为 stopped。

    全新进程启动时没有任何存活的任务线程，因此 DB 中仍标记 running 的任务，
    必然是上一次被强杀（Ctrl+C / 任务管理器 / 断电）的孤儿任务。若不处理，
    它们会一直显示「运行中」且无法删除。这里统一复位为 stopped。
    """
    from ..store import SessionStore
    from ..store.db import get_db
    try:
        db = get_db()
        ss = SessionStore(db)
        n = 0
        for t in ss.list_tasks(limit=1000):
            if (t.get("status") == "running") or (t.get("status") == "paused"):
                ss.finish_task(t["id"], "stopped")
                ss.add_event(t["id"], "task",
                             "进程重启，自动将孤儿运行中任务标记为已停止", "system")
                n += 1
        if n:
            print(f"[runner] 已复位 {n} 个孤儿运行中任务 -> stopped")
        return n
    except Exception as e:
        print(f"[runner] reconcile_orphaned_tasks 失败: {e}")
        return 0
