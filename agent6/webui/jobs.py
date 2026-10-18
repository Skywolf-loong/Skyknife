"""
漏洞作业（一键优化 / 复测 / AI 复测）的后台执行与进度管理。

与 runner.py 的任务线程互不干扰：这里专门服务于「发现」页的漏洞优化智能体。
作业在独立线程跑，HTTP 服务不被阻塞；前端通过 /api/vulns/job/<id> 轮询进度。
"""
import threading
import time
from typing import Dict, List, Optional

_LOCK = threading.RLock()
_JOBS: Dict[str, dict] = {}
_SEQ = 0
_MAX_JOBS = 50          # 内存里最多保留的作业数（超出丢弃最旧的已结束作业）
_MAX_LOGS = 300

_ACTIONS = {
    "optimize": "一键优化",
    "retest": "POC 复测",
    "ai_retest": "AI 复测",
    "logic": "业务逻辑专项",
    "chain_review": "攻击链复盘",
}


def _new_job_id() -> str:
    global _SEQ
    with _LOCK:
        _SEQ += 1
        return f"VJ{_SEQ:04d}"


def _trim_jobs():
    """控制内存占用：只淘汰已经结束的旧作业。"""
    with _LOCK:
        if len(_JOBS) <= _MAX_JOBS:
            return
        done = [k for k, v in _JOBS.items() if v.get("status") != "running"]
        done.sort(key=lambda k: _JOBS[k].get("started_at") or 0)
        for k in done[:max(0, len(_JOBS) - _MAX_JOBS)]:
            _JOBS.pop(k, None)


def _make_job(action: str, ids: List[str], opts: dict = None) -> dict:
    total = 1 if action in ("logic", "chain_review") else len(ids or [])
    return {
        "job_id": _new_job_id(),
        "action": action,
        "action_name": _ACTIONS.get(action, action),
        "ids": list(ids or []),
        "opts": opts or {},
        "status": "running",           # running / done / error
        "total": total,
        "done": 0,
        "current": "",
        "stage": "",
        "logs": [],
        "results": [],
        "summary": {},
        "error": None,
        "started_at": time.time(),
        "finished_at": None,
    }


def start_job(action: str, ids: List[str], opts: dict = None,
              tools=None, llm=None) -> str:
    """启动一个漏洞作业，返回 job_id。"""
    job = _make_job(action, ids, opts)
    jid = job["job_id"]
    with _LOCK:
        _JOBS[jid] = job
        _trim_jobs()

    def _progress(stage: str, msg: str):
        with _LOCK:
            j = _JOBS.get(jid)
            if not j:
                return
            j["stage"] = stage or ""
            j["current"] = msg or ""
            j["logs"].append({"ts": time.time(), "stage": stage, "msg": msg})
            if len(j["logs"]) > _MAX_LOGS:
                del j["logs"][:len(j["logs"]) - _MAX_LOGS]

    def _on_item(n: int, total: int, res: dict):
        with _LOCK:
            j = _JOBS.get(jid)
            if not j:
                return
            j["done"] = n
            j["total"] = total
            j["results"].append(res if isinstance(res, dict) else {"raw": str(res)})

    def _work():
        try:
            if action == "chain_review":
                from ..chain_reviewer import ChainReviewer
                cr = ChainReviewer(llm=llm, progress=_progress)
                out = cr.review(opts.get("task_id") or "",
                                source=opts.get("source") or "manual",
                                use_llm=bool(opts.get("use_llm", True)))
                with _LOCK:
                    j = _JOBS.get(jid)
                    if j:
                        j["status"] = "done" if out.get("ok") else "error"
                        j["error"] = None if out.get("ok") else (out.get("error") or "复盘失败")
                        j["summary"] = out
                        j["results"] = [out]
                        j["done"] = 1
                        j["total"] = 1
                        j["current"] = "完成" if out.get("ok") else j["error"]
                        j["finished_at"] = time.time()
                return

            if action == "logic":
                from ..logic_agent import LogicAgent
                la = LogicAgent(llm=llm, tools=tools,
                                mode=opts.get("mode") or "SRC", progress=_progress)
                out = la.run(opts.get("task_id") or "", opts.get("target") or "",
                             opts.get("scope") or "")
                with _LOCK:
                    j = _JOBS.get(jid)
                    if j:
                        j["status"] = "done"
                        j["summary"] = out or {}
                        j["results"] = [out]
                        j["done"] = 1
                        j["total"] = 1
                        j["current"] = "完成"
                        j["finished_at"] = time.time()
                return

            from ..vuln_agent import VulnAgent
            agent = VulnAgent(llm=llm, tools=tools, progress=_progress)
            if action == "optimize":
                out = agent.optimize(ids, opts, on_item=_on_item)
            elif action == "retest":
                out = agent.retest(ids, opts, on_item=_on_item)
            elif action == "ai_retest":
                out = agent.ai_retest(ids, opts, on_item=_on_item)
            else:
                raise ValueError(f"未知作业类型: {action}")
            with _LOCK:
                j = _JOBS.get(jid)
                if j:
                    j["status"] = "done"
                    j["summary"] = out.get("summary") or {}
                    j["results"] = out.get("results") or j["results"]
                    j["done"] = j["total"]
                    j["current"] = "完成"
                    j["finished_at"] = time.time()
        except Exception as e:
            with _LOCK:
                j = _JOBS.get(jid)
                if j:
                    j["status"] = "error"
                    j["error"] = str(e)
                    j["current"] = f"失败：{e}"
                    j["finished_at"] = time.time()

    th = threading.Thread(target=_work, daemon=True, name=f"vulnjob-{jid}")
    th.start()
    return jid


def get_job(jid: str) -> Optional[dict]:
    with _LOCK:
        j = _JOBS.get(jid)
        return dict(j) if j else None


def list_jobs(limit: int = 20) -> List[dict]:
    with _LOCK:
        items = sorted(_JOBS.values(), key=lambda x: x.get("started_at") or 0,
                       reverse=True)
    out = []
    for j in items[:limit]:
        out.append({k: j.get(k) for k in
                    ("job_id", "action", "action_name", "status", "total", "done",
                     "current", "stage", "started_at", "finished_at", "summary",
                     "error")})
    return out


def running_jobs() -> List[str]:
    with _LOCK:
        return [j["job_id"] for j in _JOBS.values() if j.get("status") == "running"]
