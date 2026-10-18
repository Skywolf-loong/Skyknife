"""
Worker —— 执行者（可多实例并行）。

领取 Planner 下发的单个 intent，调用工具执行，把新资产/事实/漏洞写回双图。
内部是一个小型 ReAct 循环：思考 -> 调工具 -> 看结果 -> 再思考，直至完成该意图。
"""
import json
from typing import Dict, List, Optional

from ..context import compress_messages, messages_tokens
from ..utils import extract_json
from ..human_gate import get_gate, assess_risk

# 单次 ReAct 会话的上下文预算（超出即压缩早期轮次，控制 token 增长）
_CTX_TOKEN_BUDGET = 6000
_CTX_KEEP_RECENT = 6

SYSTEM_TMPL = """你是一个自主渗透测试系统的 **Worker（执行者）**。你负责完成 Planner 下发的**单个攻击意图**。

## 工作方式
每一步你可以选择：
1) 调用一个工具获取信息：返回 JSON，字段含 `tool` 与 `args`；
2) 认为意图已完成：**不要**给 `tool` 字段，直接给出 `done: true` 与 `summary`。

## 可用工具清单
{tools}

## 输出（严格只输出一个 JSON 对象，不要 markdown 代码块）
{{
  "thought": "这一步的思考",
  "tool": "工具名（可选，完成时不填）",
  "args": {{...}},
  "facts": ["本步确认的事实（简短）"],
  "findings": [{{"title":"漏洞标题","severity":"危急|高|中|低","evidence":"证据","asset":"关联资产key(可选)"}}],
  "assets": [{{"kind":"port|subdomain|ip|webapp|service|endpoint","...": "..."}}],
  "done": false,
  "summary": "意图完成时的结论"
}}

## 资产结构化约定（assets 字段）
- 端口：{{"kind":"port","ip":"1.2.3.4","port":80,"service":"http"}}
- 子域：{{"kind":"subdomain","name":"a.x.com","parent":"x.com"}}
- IP  ：{{"kind":"ip","ip":"1.2.3.4","domain":"x.com"}}
- 站点：{{"kind":"webapp","url":"https://x/"}}
- 端点：{{"kind":"endpoint","url":"https://x/login","method":"POST","webapp":"https://x/"}}
- 服务：{{"kind":"service","ip":"1.2.3.4","port":80,"name":"nginx","version":"1.24"}}

## 铁律
- 只做当前意图，不要越界做别的阶段。
- 不要臆造结果；facts/findings 必须来自工具真实输出。
- 同一命令不要重复执行。
- **出网统一由工作台裁决**（直连 / 代理池 / Tor 三种模式之一）：禁止在命令里写
  `--noproxy "*"`、`--no-proxy`、`-x ""` 之类的手段去绕过代理；代理连不通时如实记录
  「代理不可用」并继续下一个可行验证，不要自行改道直连。
- 遵守当前模式：{mode_rules}
"""

MODE_RULES = {
    "SRC": "SRC：仅合规验证（XSS=alert(1)，SQLi=时间盲注，LFI=/etc/hostname，命令注入=id）；禁读业务数据/禁改数据/禁用真实凭据。",
    "HVV": "HVV：可较深利用，但禁 DoS/禁破坏数据/禁外泄，最小影响。",
    "测绘": "测绘：**只做信息收集**，禁止任何漏洞验证与利用动作。",
}

USER_TMPL = """## 当前意图
意图：{label}
建议工具：{tool}
建议参数：{args}

## 任务信息
目标：{target} | 模式：{mode}

## 已知资产态势（供参考，避免重复）
{asset_digest}
"""


class Worker:
    def __init__(self, llm, tool_registry, mode: str = "SRC", max_steps: int = 5,
                 task_id: str = None, require_approval: bool = False,
                 approval_timeout: int = 180, gate=None):
        self.llm = llm
        self.tools = tool_registry
        self.mode = mode
        self.max_steps = max_steps
        self.task_id = task_id
        self.require_approval = require_approval
        self.approval_timeout = approval_timeout
        self.gate = gate

    def _require_approval(self, tool: str, args: dict):
        """返回 None 表示放行；返回 dict 表示被人工拒绝（作为工具结果）。"""
        if not self.require_approval:
            return None
        gate = self.gate or get_gate()
        risk, reason = assess_risk(tool, args)
        if risk not in ("high", "medium"):
            return None
        decision = gate.request(self.task_id, tool, args, risk, reason,
                                timeout=self.approval_timeout)
        if decision["decision"] == "approved":
            return None
        return {"status": "blocked",
                "message": f"人工拒绝执行：{decision.get('reason', '')}",
                "request": f"[{tool}] 等待人工审批（风险：{risk}）",
                "response": decision.get("reason", "")}

    def _system(self) -> str:
        # 提示词可由「多智能体管理」覆盖
        tmpl = None
        try:
            from ..agent_admin import get_prompt
            tmpl = get_prompt("worker")
        except Exception:
            tmpl = None
        tmpl = tmpl or SYSTEM_TMPL
        try:
            return tmpl.format(
                tools=self.tools.tool_digest(max_tools=80),
                mode_rules=MODE_RULES.get(self.mode, ""),
            )
        except Exception:
            return tmpl

    def _invoke_agent(self, args: Dict) -> Dict:
        """委派给用户自定义的专家子代理（提示词由用户编写，是否调用由主 Agent 决定）。"""
        name = str((args or {}).get("agent") or "").strip()
        task = str((args or {}).get("task") or "").strip()
        if not name:
            return {"status": "error", "message": "invoke_agent 缺少 agent 名称"}
        ag = None
        try:
            from ..agent_admin import custom_agents
            ag = next((c for c in custom_agents(enabled_only=True)
                       if c.get("name") == name), None)
        except Exception:
            ag = None
        if not ag:
            return {"status": "error", "message": f"未找到启用的自定义子代理: {name}"}
        msgs = [{"role": "system", "content": str(ag.get("prompt") or "")},
                {"role": "user", "content": task or "请给出你的专业建议与结论。"}]
        try:
            out = self.llm.chat(msgs, agent=f"custom:{name}")
        except Exception as e:
            return {"status": "error", "message": f"子代理调用失败: {e}",
                    "request": f"invoke_agent({name})", "response": str(e)}
        text = str(out or "")[:4000]
        return {"status": "success", "request": f"invoke_agent({name})",
                "response": text,
                "data": {"agent": name, "task": task, "output": text}}

    def execute(self, intent: Dict, target: str, asset_digest: str,
                context: Dict = None) -> Dict:
        """执行单个 intent（intent 为探索图节点 dict），返回 observation。"""
        context = context if context is not None else {}
        label = intent.get("label", "")
        data = intent.get("data", {}) or {}
        user = USER_TMPL.format(
            label=label, tool=data.get("tool") or "(自选)", 
            args=json.dumps(data.get("args") or {}, ensure_ascii=False),
            target=target, mode=self.mode, asset_digest=asset_digest or "(空)",
        )
        messages = [{"role": "system", "content": self._system()},
                    {"role": "user", "content": user}]

        collected = {"facts": [], "findings": [], "assets": [], "tool_calls": [],
                     "summary": "", "compressed": 0}

        for step in range(self.max_steps):
            # 上下文压缩：ReAct 循环里工具回显很长，超出预算即折叠早期轮次，控制 token
            compressed_out, cstat = compress_messages(
                messages, keep_recent=_CTX_KEEP_RECENT,
                max_tokens=_CTX_TOKEN_BUDGET)
            if cstat.get("compressed"):
                messages = compressed_out
                collected["compressed"] += cstat.get("dropped", 0)
            try:
                resp = self.llm.chat(messages, agent="worker")
            except Exception as e:
                collected["summary"] = f"LLM 错误: {e}"
                break
            obj = extract_json(resp)
            if not isinstance(obj, dict):
                messages.append({"role": "assistant", "content": resp})
                messages.append({"role": "user",
                                 "content": "请只返回一个 JSON 对象（含 thought/tool/args/done）。"})
                continue

            # 收集本步产出的结构化信息
            for f in obj.get("facts") or []:
                if f:
                    collected["facts"].append(str(f)[:300])
            for fd in obj.get("findings") or []:
                if isinstance(fd, dict) and fd.get("title"):
                    collected["findings"].append(fd)
            for a in obj.get("assets") or []:
                if isinstance(a, dict) and a.get("kind"):
                    collected["assets"].append(a)

            tool = obj.get("tool")
            if not tool:
                # 无工具调用 → 视为本轮结束
                collected["summary"] = obj.get("summary") or obj.get("thought", "")
                if obj.get("done"):
                    break
                if step >= 1:
                    break

            args = obj.get("args") or {}
            if tool:
                # 把建议工具作为兜底（极少走到）
                if not tool and data.get("tool"):
                    tool = data["tool"]
                # 人在环路：危险操作先过审批门禁
                blocked = self._require_approval(tool, args)
                if blocked is not None:
                    result = blocked
                elif tool == "invoke_agent":
                    # 委派给自定义专家子代理（由主 Agent 决定是否调用）
                    result = self._invoke_agent(args)
                else:
                    result = self.tools.run(tool, args, context)
                summary = self._summarize(tool, args, result)
                collected["tool_calls"].append({"tool": tool, "args": args,
                                                 "status": result.get("status", "?"),
                                                 "summary": summary, "result": result,
                                                 "request": result.get("request"),
                                                 "response": result.get("response"),
                                                 "exit_code": result.get("exit_code")})
                messages.append({"role": "assistant", "content": json.dumps(obj, ensure_ascii=False)})
                messages.append({"role": "user",
                                 "content": f"[工具执行结果 tool={tool}]\n{summary}\n\n"
                                            "继续：若意图已完成，返回 done=true 且不给 tool；"
                                            "否则给出下一步工具调用。"})
                if obj.get("done"):
                    collected["summary"] = obj.get("summary") or collected["summary"]
                    break

        return collected

    @staticmethod
    def _summarize(tool: str, args: Dict, result: Dict) -> str:
        if not isinstance(result, dict):
            return str(result)[:1500]
        if result.get("status") == "error":
            return f"错误: {result.get('message','')}"[:800]
        data = result.get("data", result.get("output", ""))
        try:
            s = json.dumps(data, ensure_ascii=False) if not isinstance(data, str) else data
        except Exception:
            s = str(data)
        head = f"args={json.dumps(args, ensure_ascii=False)[:200]}\n"
        return (head + s)[:2500]
