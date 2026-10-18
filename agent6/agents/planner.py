"""
Planner —— 全局规划者（每个任务一个）。

职责：读取探索图与资产图当前态势，维护待办攻击意图清单，保证链路有序
      （资产测绘 → 端口 → 指纹 → 漏洞探测 → 利用），不跳步、不重复。
输出：一批新 intent（含建议工具/参数）或 finish 决策。
"""
import json
from typing import Dict, List

from ..utils import extract_json

PHASES = ["资产测绘", "端口与服务", "指纹识别", "漏洞探测", "漏洞利用/验证"]

SYSTEM_TMPL = """你是一个自主渗透测试系统的 **Planner（规划者）**。你不执行工具，只负责规划与派单。

## 渗透方法论（必须按阶段有序推进，不跳步）
1. 资产测绘：根域名 -> 子域名枚举 -> DNS 解析 -> 存活 IP
2. 端口与服务：对存活 IP 做端口扫描、服务识别
3. 指纹识别：对 Web 端口/站点做技术栈指纹、目录扫描、参数发现
4. 漏洞探测：针对已识别技术栈与参数做漏洞验证（SQLi/XSS/LFI/命令注入/敏感信息泄露等）
5. 漏洞利用/验证：在授权与低影响前提下做最小化验证

## 硬性规则
- **不重复**：已完成/待办的意图不要重复下发；同目标同动作只做一次。
- **依赖有序**：没有资产就不要扫端口；没有端口/服务就不要测漏洞。
- **每轮最多派 {max_intents} 个意图**，优先补齐当前阶段缺口。
- 每个意图必须带 `tool`（必须来自下方工具清单）与 `args`。

## 当前运行模式：{mode}
{mode_rules}

## 可用工具清单
{tools}

## 输出（严格只输出一个 JSON 对象，不要 markdown 代码块）
{{
  "reasoning": "本轮规划思路（简述当前处于哪个阶段、为何下发这些意图）",
  "intents": [
    {{"label": "意图描述", "tool": "工具名", "args": {{...}}, "priority": "high|medium|low"}}
  ],
  "chain": [
    {{"id": "s1", "label": "步骤描述", "deps": [], "requires": [], "produces": [], "tool": "工具名", "args": {{}}}}
  ],
  "finish": false,
  "summary": "若 finish=true，填写最终结论"
}}
当攻击面已穷尽（无新资产、无新漏洞可测）且无需再执行时，令 "intents": [] 且 "finish": true。

**串行利用链（chain）**：若后续步骤必须依赖前一步产出的事实才能得到
（典型如「发现注入点」→「拿到凭据」→「横向」→「提权」），请在 `chain` 中登记**整条链**。
同一条链只需登记一次，程序会跨轮次记住进度并按依赖逐步放行，你不必重复描述它。
字段含义：`deps` 依赖前序步骤 id；`requires` 本步执行前必须具备的事实关键字；
`produces` 本步预计产出的事实关键字（事实一旦落图，该步自动标记完成）。
"""

MODE_RULES = {
    "SRC": "SRC 模式：仅做合规验证（XSS 用 alert(1)，SQLi 用时间盲注，LFI 仅 /etc/hostname，"
           "命令注入仅 id/whoami）；禁读业务数据/禁改数据/禁用真实凭据/禁重型扫描器。",
    "HVV": "HVV 模式：红队演练，可做较深利用，但禁 DoS/禁破坏/禁外泄真实数据，最小影响。",
    "测绘": "测绘模式：**仅信息收集**（端口/指纹/DNS/SSL/子域/目录），严禁任何漏洞验证与利用。",
}

USER_TMPL = """## 任务
目标：{target}
范围：{scope}
模式：{mode}
迭代轮次：第 {round} 轮

## 资产图态势（仅本任务范围：本任务发现或本任务触及过的资产）
{asset_digest}

## 探索图态势（本任务）
{exploration_digest}

{intervention_block}请基于以上态势，规划下一轮要执行的攻击意图（最多 {max_intents} 个）。
若已无可执行的攻击面，返回 finish=true 并给出 summary。
"""


class Planner:
    def __init__(self, llm, tool_registry, session_store=None, task_id=None,
                 mode: str = "SRC", max_intents: int = 5):
        self.llm = llm
        self.tools = tool_registry
        self.session_store = session_store
        self.task_id = task_id
        self.mode = mode
        self.max_intents = max_intents

    def _system(self) -> str:
        # 提示词可由「多智能体管理」覆盖；并附上自定义子代理清单供主 Agent 决定是否委派
        tmpl, extra = None, ""
        try:
            from ..agent_admin import get_prompt, agents_context
            tmpl = get_prompt("planner")
            extra = agents_context()
        except Exception:
            tmpl, extra = None, ""
        tmpl = tmpl or SYSTEM_TMPL
        try:
            base = tmpl.format(
                max_intents=self.max_intents,
                mode=self.mode,
                mode_rules=MODE_RULES.get(self.mode, ""),
                tools=self.tools.tool_digest(max_tools=80),
            )
        except Exception:
            base = tmpl
        if extra:
            base = base + "\n\n" + extra
        return base

    def plan(self, target: str, scope: str, asset_digest: str,
             exploration_digest: str, round_no: int, extra_hint: str = "") -> Dict:
        intervention_block = ""
        if extra_hint:
            intervention_block = (
                "## 人工干预指令（必须由 Planner 优先遵循）\n"
                + extra_hint + "\n\n")
        user = USER_TMPL.format(
            target=target, scope=scope or target, mode=self.mode, round=round_no,
            asset_digest=asset_digest or "(空)",
            exploration_digest=exploration_digest or "(空)",
            max_intents=self.max_intents,
            intervention_block=intervention_block,
        )
        messages = [{"role": "system", "content": self._system()},
                    {"role": "user", "content": user}]
        try:
            resp = self.llm.chat(messages, agent="planner")
        except Exception as e:
            return {"reasoning": f"LLM 错误: {e}", "intents": [], "finish": True,
                    "summary": f"规划失败: {e}"}
        decision = extract_json(resp) or {}
        if not isinstance(decision, dict):
            decision = {}
        intents = decision.get("intents") or []
        if not isinstance(intents, list):
            intents = []
        # 过滤：必须有可用工具
        valid = []
        for it in intents:
            if not isinstance(it, dict) or not it.get("label"):
                continue
            tool = it.get("tool")
            if tool and not (self.tools.has_skill(tool)
                             or tool in ("command", "http")
                             or tool in ("search_all_worker_traces",
                                         "list_worker_traces", "get_worker_trace")):
                it["tool"] = None  # 工具不可用，交 Worker 决策
            valid.append(it)
        # 串行利用链：只做结构规范化，不推断语义（顺序由程序算，不由模型算）
        chain = decision.get("chain") or []
        if not isinstance(chain, list):
            chain = []
        chain_valid = []
        for idx, s in enumerate(chain):
            if not isinstance(s, dict) or not s.get("label"):
                continue
            sid = str(s.get("id") or f"s{idx+1}")
            for key in ("deps", "requires", "produces"):
                v = s.get(key)
                if isinstance(v, str):
                    v = [v] if v else []
                s[key] = v if isinstance(v, list) else []
            s["id"] = sid
            chain_valid.append(s)
        return {
            "reasoning": decision.get("reasoning", ""),
            "intents": valid[: self.max_intents],
            "chain": chain_valid,
            "finish": bool(decision.get("finish", False)),
            "summary": decision.get("summary", ""),
        }
