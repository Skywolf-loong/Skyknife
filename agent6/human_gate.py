"""
人在环路（Human-in-the-Loop）审批门禁。

设计要点
--------
- 全局单例，跨任务维护「待审批」队列；每条记录带唯一 id、风险级别、理由。
- 执行引擎（Worker）要调用危险工具前调用 ``request()``，该方法会 **阻塞**
  当前工作线程，直到界面通过 API ``decide()`` 批准/拒绝并唤醒，或超时。
- 超时策略默认 ``approve``（保证无人值守任务不被卡死，但会在理由中标注「超时自动通过」）；
  也可设为 ``reject`` 走最保守安全策略。
- 危险判定 ``assess_risk()``：command 一律 high；含利用/注入关键词的技能 high；
  HTTP 写操作（POST/PUT/DELETE 或带载荷）medium；其余 low。仅 high/medium 在开启审批时拦截。
- ``decide()`` / 超时自动决定都会落到 DB 的 ``approvals`` 表：内存 ``_items`` 会被
  ``_prune()`` 在 30 分钟后清掉，落库才能保证「审批记录」可回溯。
"""
import threading
import time
from typing import Dict, List, Optional

# 高危利用类技能关键词（名字或描述命中其一即视为高危）
DANGER_KEYWORDS = [
    "exploit", "payload", "inject", "xss", "sqli", "sql注入", "rce", "command",
    "exec", "shell", "反弹", "webshell", "upload", "暴力", "brute", "crack",
    "破解", "dos", "flood", "利用", "注入", "getshell", "提权", "后门",
    "反弹shell", "bypass", "traversal", "lfi", "rfi", "ssrf",
]


def assess_risk(tool: str, args: Optional[Dict]) -> (str, str):
    """返回 (risk_level, reason)。risk_level ∈ {high, medium, low}。"""
    args = args if isinstance(args, dict) else {}
    if tool == "command":
        cmd = (args.get("command") or args.get("cmd") or "")
        return "high", f"本地命令执行：{cmd[:120]}"
    if tool == "http":
        method = (args.get("method") or "GET").upper()
        url = args.get("url") or ""
        data = args.get("data") or ""
        if method in ("POST", "PUT", "DELETE", "PATCH") or "payload" in (data + url).lower():
            return "medium", f"HTTP {method} 请求（含请求体/载荷）：{url[:120]}"
        return "low", f"HTTP {method} 只读请求：{url[:120]}"
    name = (tool or "").lower()
    if any(k in name for k in DANGER_KEYWORDS):
        return "high", f"高危利用类技能：{tool}"
    return "low", f"技能 {tool}"


def _persist_approval(rec: dict, action: str, reason: str = "", auto: bool = False):
    """把一次审批决定写入 DB（best-effort：任何异常都不影响门禁主流程）。"""
    try:
        from .store.db import get_db, jdump, now
        get_db().execute(
            "INSERT INTO approvals(approval_id,task_id,tool,args,risk,reason,action,"
            "decision_reason,auto,created_at,decided_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (rec.get("id"), rec.get("task_id"), rec.get("tool"),
             jdump(rec.get("args") or {}), rec.get("risk"), rec.get("reason") or "",
             action, reason or "", 1 if auto else 0,
             rec.get("created_at") or now(), now()),
        )
    except Exception:
        pass


class HumanGate:
    def __init__(self):
        self._cond = threading.Condition()
        self._items: Dict[str, dict] = {}
        self._seq = 0

    # ---------- 执行引擎侧：阻塞请求审批 ----------
    def request(self, task_id: str, tool: str, args: Optional[Dict],
                risk: str = "medium", reason: str = "",
                timeout: int = 180, timeout_action: str = "approve") -> Dict:
        """发起一次审批请求并阻塞，直到被决定或超时。

        返回 {"decision": "approved"|"rejected", "reason": str, "auto": bool}
        """
        with self._cond:
            self._seq += 1
            aid = f"AP{self._seq:05d}"
            rec = {
                "id": aid, "task_id": task_id, "tool": tool,
                "args": args if isinstance(args, dict) else {},
                "risk": risk, "reason": reason, "status": "pending",
                "decision_reason": "", "created_at": time.time(),
                "timeout": timeout, "timeout_action": timeout_action,
            }
            self._items[aid] = rec

        # 清理已决定的旧记录（在持锁块之外调用，避免重入死锁）
        self._prune()

        # 阻塞等待 UI 决策（释放锁，允许 Web 线程调用 decide 并 notify）
        with self._cond:
            waited = 0.0
            step = 0.5
            while self._items.get(aid, {}).get("status") == "pending" and waited < timeout:
                self._cond.wait(timeout=step)
                waited += step

        with self._cond:
            rec = self._items.get(aid)
            if rec and rec["status"] == "pending":
                action = "approved" if (timeout_action or "approve") == "approve" else "rejected"
                rec["status"] = "timeout_" + action
                rec["decision_reason"] = (
                    f"审批超时（{int(timeout)}s）未人工干预，按默认策略"
                    f"{'自动通过' if action == 'approved' else '自动拒绝'}"
                )
                _persist_approval(rec, rec["status"], rec["decision_reason"], auto=True)
                return {"decision": action, "reason": rec["decision_reason"], "auto": True}
            if rec:
                return {
                    "decision": "approved" if rec["status"] == "approved" else "rejected",
                    "reason": rec["decision_reason"], "auto": False,
                }
        return {"decision": "approved", "reason": "no record", "auto": True}

    # ---------- 界面侧：决策 ----------
    def decide(self, approval_id: str, action: str, reason: str = "") -> bool:
        """action ∈ {approved, rejected}。返回是否成功。

        - 记录不存在            → False
        - 已处于相同决定态       → True（幂等，避免前端重复点击报「操作失败」）
        - 已处于相反决定态/超时  → False
        - 仍 pending             → 正常决定并返回 True
        """
        action = "approved" if action == "approved" else "rejected"
        with self._cond:
            rec = self._items.get(approval_id)
            if not rec:
                return False
            if rec["status"] == action:
                return True  # 幂等：已经批准/拒绝过了
            if rec["status"] != "pending":
                return False  # 已决定（可能为相反动作）或已超时取消
            rec["status"] = action
            rec["decision_reason"] = (reason or "").strip()
            self._cond.notify_all()
        _persist_approval(rec, action, rec["decision_reason"], auto=False)
        return True

    # ---------- 任务停止/删除时：取消其待审批项 ----------
    def clear_task(self, task_id: str) -> int:
        """任务停止/删除时取消其所有待审批项，释放被阻塞的工作线程。

        返回被取消（pending→cancelled）的条数。cancelled 不会再出现在
        ``pending()`` 队列中，从而避免「已删除的任务仍在界面弹出审批」。
        """
        n = 0
        cancelled = []
        with self._cond:
            for rec in self._items.values():
                if rec.get("task_id") == task_id and rec.get("status") == "pending":
                    rec["status"] = "cancelled"
                    rec["decision_reason"] = "任务已停止/删除，审批被取消"
                    cancelled.append(rec)
                    n += 1
            if n:
                self._cond.notify_all()
        for rec in cancelled:
            _persist_approval(rec, "cancelled", rec["decision_reason"], auto=True)
        return n

    # ---------- 清理已决定的旧记录，避免 _items 无限增长 ----------
    def _prune(self):
        now = time.time()
        expired = [k for k, v in self._items.items()
                   if v.get("status") != "pending"
                   and now - v.get("created_at", 0) > 1800]
        for k in expired:
            del self._items[k]
        # 兜底上限：超过 2000 条时优先删除最旧的已决项（pending 永不清）
        if len(self._items) > 2000:
            decided = sorted(
                (k for k, v in self._items.items() if v.get("status") != "pending"),
                key=lambda k: self._items[k].get("created_at", 0))
            for k in decided:
                if len(self._items) <= 2000:
                    break
                del self._items[k]

    # ---------- 查询 ----------
    def pending(self, task_id: Optional[str] = None) -> List[dict]:
        with self._cond:
            items = [dict(v) for v in self._items.values()
                     if v.get("status") == "pending"]
        items = [i for i in items if task_id is None or i["task_id"] == task_id]
        return sorted(items, key=lambda x: x["created_at"])

    def list_all(self) -> List[dict]:
        with self._cond:
            items = [dict(v) for v in self._items.values()]
        return sorted(items, key=lambda x: x["created_at"])


_gate_singleton: Optional[HumanGate] = None
_gate_lock = threading.Lock()


def get_gate() -> HumanGate:
    global _gate_singleton
    if _gate_singleton is None:
        with _gate_lock:
            if _gate_singleton is None:
                _gate_singleton = HumanGate()
    return _gate_singleton
