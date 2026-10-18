# -*- coding: utf-8 -*-
"""攻击链复盘员（Chain Reviewer）—— 任务结束后自动复盘攻击链并写入记忆文件。

职责边界：
  1. 读取本任务的双图数据（意图 / 事实 / 漏洞 / 工具调用 / 串行链步骤）；
  2. 归纳「侦察 → 验证 → 利用」纵向攻击链，提炼**可复用打法**与**死路**；
  3. 落盘为攻击链记录 + Markdown 记忆文件（见 ``agent6/attack_chain.py``）；
  4. 下一次任务启动时由 Orchestrator 把记忆注入 Planner（作为参考，不是结论）。

**不执行任何攻击动作、不发网络请求**：纯读库 + 一次 LLM 归纳（失败降级为规则复盘）。
"""
import json
import re
from typing import Callable, Optional

from .attack_chain import collect, redact_obj, rule_review, save_chain

SYSTEM_TMPL = """你是资深红队「攻击链复盘员」。你的任务不是复述流水账，而是把一次渗透任务
还原成**可复用的纵向攻击链**，供下一次任务参考。

要求：
1. 只依据给定数据归纳，绝不臆造未出现的资产、漏洞或工具。
2. **严禁输出敏感业务数据**：不得出现真实域名、IP、URL 主机名、用户名、口令、Token、
   Cookie、邮箱、单位名称。输入已经脱敏为 <DOMAIN> / <IP> / <HOST> / <EMAIL> /
   <REDACTED> 占位符，输出必须沿用这些占位符，不得还原或猜测原值。
3. 攻击阶段用「侦察 / 漏洞验证 / 利用与横向 / 提权与持久化 / 其它」这几类归类。
4. lessons 要写「下次能直接照着做的打法」（工具序列、有效参数、判定特征），
   其中必须包含**死路**（无效打法），避免下次重复浪费轮次；参数含主机/账号时同样用占位符。
5. next_steps 写本次未完成、值得补做的验证或攻击面。
6. 结论必须标明证据强度：只有实测确认过的漏洞才可写成「已确认」。

严格输出 JSON（不要 Markdown 代码块、不要多余文字）：
{
  "summary": "80~200 字的攻击链概述（脱敏）",
  "stages": [{"stage": "侦察", "action": "用了什么、得到什么"}],
  "lessons": ["有效打法或死路，单条 60 字内"],
  "next_steps": ["下一步建议"],
  "tags": ["技术标签，如 wordpress / 弱口令 / upload"]
}"""


def _digest(m: dict, max_chars: int = 9000) -> str:
    lines = [
        f"目标：{m.get('target')}｜类型：{m.get('target_kind')}"
        f"｜指纹：{m.get('target_hint')}｜模式：{m.get('mode')}"
        f"｜任务状态：{m.get('task_status')}",
        f"指标：{json.dumps(m.get('metrics') or {}, ensure_ascii=False)}",
        "",
        f"## 意图序列（{len(m.get('intents') or [])}）",
    ]
    for i, it in enumerate(m.get("intents") or [], 1):
        s = f"{i}. [{it.get('status')}] {it.get('label')}"
        if it.get("tool"):
            s += f"（tool={it.get('tool')}）"
        if it.get("summary"):
            s += f" → {str(it['summary'])[:160]}"
        lines.append(s)

    fs = m.get("findings") or []
    lines.append("")
    lines.append(f"## 漏洞结论（{len(fs)}）")
    for f in fs:
        lines.append(f"- [{f.get('severity') or '?'}] {f.get('title')}"
                     f"｜验证状态={f.get('verify_status') or '未验证'}"
                     f"｜证据={(f.get('evidence') or '')[:160]}")

    lines.append("")
    lines.append(f"## 工具调用序列（{len(m.get('steps') or [])}）")
    for s in (m.get("steps") or [])[:45]:
        lines.append(f"{s.get('seq')}. {s.get('tool')} {s.get('args') or ''}"
                     f" → {s.get('status')}｜{s.get('summary') or ''}")

    todos = m.get("todos") or []
    if todos:
        lines.append("")
        lines.append(f"## 串行利用链步骤（{len(todos)}）")
        for t in todos:
            lines.append(f"- [{t.get('status')}] {t.get('label')}（tool={t.get('tool')}）")

    facts = m.get("facts") or []
    if facts:
        lines.append("")
        lines.append(f"## 关键事实（{len(facts)}，节选 30）")
        for f in facts[:30]:
            lines.append(f"- {str(f)[:180]}")

    out = "\n".join(lines)
    return out[:max_chars]


def _parse_json(text: str) -> Optional[dict]:
    if not text:
        return None
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    try:
        d = json.loads(t)
    except Exception:
        i, j = t.find("{"), t.rfind("}")
        if i < 0 or j <= i:
            return None
        try:
            d = json.loads(t[i:j + 1])
        except Exception:
            return None
    if not isinstance(d, dict):
        return None
    if not any(k in d for k in ("summary", "stages", "lessons")):
        return None
    return d


class ChainReviewer:
    """攻击链复盘员。所有异常均降级为规则复盘，不抛出。"""

    def __init__(self, db=None, llm=None,
                 progress: Optional[Callable[[str, str], None]] = None,
                 mode: str = "SRC"):
        self.db = db
        self.llm = llm
        self.mode = mode
        self.progress = progress or (lambda stage, msg: None)
        self.last_error = ""

    # ---------- 基础 ----------
    def _get_llm(self, allow_auto=True):
        if self.llm is not None:
            return self.llm
        if not allow_auto:
            return None
        try:
            from .llm import LLMClient
            from .settings import llm_kwargs, load_settings
            st = load_settings()
            key = (st.get("llm") or {}).get("api_key") or None
            if not key:
                self.last_error = "未配置 LLM API Key"
                return None
            self.llm = LLMClient(cfg={"llm": llm_kwargs()}, api_key=key)
        except Exception as e:
            self.llm = None
            self.last_error = f"LLM 不可用：{e}"
        return self.llm

    def _chat(self, system: str, user: str,
              max_tokens: int = 1600) -> Optional[str]:
        # 「多智能体管理」可给攻击链复盘员追加指令（前置）
        try:
            from .agent_admin import prefix as _prefix
            system = _prefix("chain_reviewer", system)
        except Exception:
            pass
        llm = self._get_llm()
        if not llm:
            return None
        try:
            return llm.chat([{"role": "system", "content": system},
                             {"role": "user", "content": user}],
                            agent="chain_reviewer", max_tokens=max_tokens,
                            temperature=0.2)
        except Exception as e:
            self.last_error = f"LLM 调用失败：{e}"
            return None

    # ---------- 复盘 ----------
    def review(self, task_id: str, source: str = "auto",
               persist: bool = True, use_llm: bool = True) -> dict:
        if not task_id:
            return {"ok": False, "error": "缺少 task_id"}
        self.progress("collect", f"读取任务 {task_id} 的攻击链数据")
        material = collect(task_id, db=self.db)
        if not material.get("intents") and not material.get("steps"):
            return {"ok": False, "error": "该任务没有可复盘的攻击链数据",
                    "task_id": task_id}

        base = rule_review(material)
        review = None
        if use_llm:
            self.progress("llm", "调用 LLM 归纳攻击链")
            out = self._chat(SYSTEM_TMPL, _digest(material))
            review = _parse_json(out or "")
            if review:
                # 双保险：即使模型"编"出了域名/IP/账号，也在落盘前再脱敏一遍
                review = redact_obj(review)
                review["model"] = "llm"
            else:
                self.progress("llm", "LLM 输出不可解析，降级规则复盘"
                                     + (f"：{self.last_error}" if self.last_error else ""))
        if not review:
            review = base
            review["model"] = "rule"

        # 规则结果兜底补全：LLM 漏掉的字段用规则值补齐
        for k in ("stages", "lessons", "next_steps", "tags"):
            if not review.get(k):
                review[k] = base.get(k) or []
        if not review.get("summary"):
            review["summary"] = base.get("summary") or ""

        if not persist:
            return {"ok": True, "task_id": task_id, "review": review,
                    "material": material}

        out = save_chain(material, review, source=source)
        self.progress("done", f"攻击链 {out['chain']['id']} 已写入记忆文件")
        return {"ok": True, "task_id": task_id, "chain": out["chain"],
                "model": review.get("model"),
                "memory_file": out["chain"].get("memory_file")}


def review_task(task_id: str, db=None, llm=None, source: str = "auto",
                progress=None) -> dict:
    """便捷入口：复盘并写记忆文件。"""
    return ChainReviewer(db=db, llm=llm, progress=progress).review(
        task_id, source=source, persist=True)
