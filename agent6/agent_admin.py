# -*- coding: utf-8 -*-
"""多智能体管理后端 —— 接入现有 Agent，并支持编辑提示词 / 新增自定义子代理。

接入的既有 Agent：
  - planner ：主 Agent 的**规划者**（``agent6/agents/planner.py``），提示词**整体可替换**。
  - worker  ：主 Agent 的**执行者**（``agent6/agents/worker.py``），提示词**整体可替换**。
  - vuln    ：漏洞审查 Agent（``agent6/vuln_agent.py``），提示词以**附加指令**形式注入。
  - logic   ：逻辑漏洞 Agent（``agent6/logic_agent.py``），提示词以**附加指令**形式注入。

自定义子代理（custom）：
  - 提示词由用户编写，作为「专家子代理」登记；主 Agent（Planner）在规划时可见，
    可下发 ``invoke_agent`` 意图把子任务委派给它（是否调用由主 Agent 决定）。

落盘 ``agent6_data/agents.json``::

    {"overrides": {"planner": "...", "worker": "...", "vuln": "...", "logic": "..."},
     "custom": [{"id","name","role","prompt","enabled","stage","keywords","tools"}]}
"""
import json
import time
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent.parent / "agent6_data"
STORE = _DATA_DIR / "agents.json"

# 内置 Agent 定义：(key, 名称, 角色说明, 注入方式)
#   注入方式 replace = 覆盖整段系统提示词；prefix = 作为附加指令前置到系统提示词
BUILTIN = [
    {"key": "planner", "name": "主 Agent · 规划者（Planner）",
     "role": "读取态势、维护攻击意图待办、有序派单（资产测绘→端口→指纹→漏洞→利用）",
     "mode": "replace"},
    {"key": "worker", "name": "主 Agent · 执行者（Worker）",
     "role": "领取单个意图，ReAct 循环调用工具执行并写回事实/漏洞/资产",
     "mode": "replace"},
    {"key": "vuln", "name": "漏洞审查 Agent（VulnAgent）",
     "role": "去重 / 写 POC / 执行验证 / AI 判误报 / 复测",
     "mode": "prefix"},
    {"key": "logic", "name": "逻辑漏洞 Agent（LogicAgent）",
     "role": "业务逻辑专项：越权 / IDOR / 改价 / 验证码复用（先验证后上报）",
     "mode": "prefix"},
    {"key": "chain_reviewer", "name": "攻击链复盘员（ChainReviewer）",
     "role": "任务结束后复盘纵向攻击链 → 提炼有效打法/死路 → 自动写入攻击链记忆文件",
     "mode": "prefix"},
]


def _load():
    try:
        d = json.loads(STORE.read_text(encoding="utf-8"))
    except Exception:
        d = {}
    d.setdefault("overrides", {})
    d.setdefault("custom", [])
    if not isinstance(d["overrides"], dict):
        d["overrides"] = {}
    if not isinstance(d["custom"], list):
        d["custom"] = []
    return d


def _save(d):
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    STORE.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    return d


def _builtin_default_prompt(key: str) -> str:
    """返回内置 Agent 的默认系统提示词（用于界面展示/对比）。"""
    try:
        if key == "planner":
            from .agents.planner import SYSTEM_TMPL
            return SYSTEM_TMPL
        if key == "worker":
            from .agents.worker import SYSTEM_TMPL
            return SYSTEM_TMPL
        if key == "vuln":
            return ("你是资深渗透测试工程师，负责把漏洞结论转成可机读的最小化验证 POC，"
                    "并对证据做误报研判（宁可存疑也不臆断）。\n（本提示词以附加指令形式前置）")
        if key == "logic":
            return ("你是业务逻辑漏洞渗透专家，依据页面/接口抓取结果发现越权、IDOR、"
                    "改价、验证码复用等逻辑缺陷。\n（本提示词以附加指令形式前置）")
        if key == "chain_reviewer":
            from .chain_reviewer import SYSTEM_TMPL
            return SYSTEM_TMPL
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# 提示词读取（供各 Agent 调用）
# ---------------------------------------------------------------------------
def get_prompt(key: str):
    """返回用户为该内置 Agent 设置的提示词；未设置返回 None。"""
    return (_load()["overrides"].get(key) or "") or None


def prefix(key: str, default: str) -> str:
    """把用户附加指令前置到系统提示词（用于 vuln / logic）。"""
    p = get_prompt(key)
    return (p.strip() + "\n\n" + default) if p else default


# ---------------------------------------------------------------------------
# 自定义子代理
# ---------------------------------------------------------------------------
def custom_agents(enabled_only=True):
    items = _load()["custom"]
    if enabled_only:
        items = [c for c in items if c.get("enabled", True)]
    return items


def agents_context() -> str:
    """返回给 Planner 的自定义子代理清单文本（供其决定是否委派）。"""
    items = custom_agents(enabled_only=True)
    if not items:
        return ""
    lines = ["## 可用自定义专家子代理（Markdown 即子代理）",
             "如需委派，请下发一个 intent：tool=\"invoke_agent\"，",
             "args={\"agent\":\"<名称>\",\"task\":\"<要它完成的子任务>\"}。是否调用由你决定。"]
    for c in items:
        trig = []
        if c.get("stage"):
            trig.append("阶段:" + str(c["stage"]))
        if c.get("keywords"):
            trig.append("关键词:" + ",".join(c["keywords"]))
        lines.append(f"- {c.get('name')}：{c.get('role','')}"
                     + (f"（{'; '.join(trig)}）" if trig else ""))
    return "\n".join(lines)


def _next_id(custom):
    mx = 0
    for c in custom:
        cid = str(c.get("id") or "")
        if cid.startswith("AG") and cid[2:].isdigit():
            mx = max(mx, int(cid[2:]))
    return f"AG{mx + 1:04d}"


# ---------------------------------------------------------------------------
# 清单 / 详情
# ---------------------------------------------------------------------------
def list_agents():
    d = _load()
    overrides = d["overrides"]
    builtin = []
    for b in BUILTIN:
        ov = (overrides.get(b["key"]) or "").strip()
        builtin.append({
            **b, "type": "builtin", "id": b["key"],
            "prompt": ov or _builtin_default_prompt(b["key"]),
            "custom_prompt": ov,
            "edited": bool(ov),
            "enabled": True,
        })
    custom = []
    for c in d["custom"]:
        custom.append({
            "id": c.get("id"), "type": "custom", "name": c.get("name"),
            "role": c.get("role", ""), "prompt": c.get("prompt", ""),
            "enabled": c.get("enabled", True), "mode": "custom",
            "stage": c.get("stage", ""), "keywords": c.get("keywords", []),
            "tools": c.get("tools", []), "created_at": c.get("created_at"),
        })
    return {"builtin": builtin, "custom": custom,
            "total": len(builtin) + len(custom)}


def get_agent(agent_id: str):
    if not agent_id:
        return {"ok": False, "error": "缺少 agent id"}
    for b in list_agents()["builtin"]:
        if b["id"] == agent_id:
            return {"ok": True, "agent": b}
    for c in list_agents()["custom"]:
        if c["id"] == agent_id:
            return {"ok": True, "agent": c}
    return {"ok": False, "error": f"Agent 不存在: {agent_id}"}


# ---------------------------------------------------------------------------
# 编辑
# ---------------------------------------------------------------------------
def set_prompt(key: str, prompt: str):
    """设置内置 Agent 的提示词（空串=恢复默认）。"""
    if key not in {b["key"] for b in BUILTIN}:
        return {"ok": False, "error": f"未知内置 Agent: {key}"}
    d = _load()
    prompt = (prompt or "").strip()
    if prompt:
        d["overrides"][key] = prompt
    else:
        d["overrides"].pop(key, None)
    _save(d)
    return {"ok": True, "key": key, "edited": bool(prompt)}


def add_custom(name, role="", prompt="", stage="", keywords=None, tools=None):
    if not name or not str(name).strip():
        return {"ok": False, "error": "缺少子代理名称"}
    if not (prompt or "").strip():
        return {"ok": False, "error": "自定义子代理必须填写提示词（由用户编写）"}
    d = _load()
    cid = _next_id(d["custom"])
    item = {"id": cid, "name": str(name).strip(), "role": role or "",
            "prompt": prompt, "enabled": True, "stage": stage or "",
            "keywords": [k for k in (keywords or []) if k],
            "tools": [t for t in (tools or []) if t],
            "created_at": int(time.time())}
    d["custom"].append(item)
    _save(d)
    return {"ok": True, "id": cid, "agent": item}


def update_custom(cid, **fields):
    d = _load()
    for c in d["custom"]:
        if c.get("id") == cid:
            for k in ("name", "role", "prompt", "stage", "enabled"):
                if k in fields and fields[k] is not None:
                    c[k] = fields[k]
            if fields.get("keywords") is not None:
                c["keywords"] = [k for k in fields["keywords"] if k]
            if fields.get("tools") is not None:
                c["tools"] = [t for t in fields["tools"] if t]
            _save(d)
            return {"ok": True, "agent": c}
    return {"ok": False, "error": f"自定义子代理不存在: {cid}"}


def delete_custom(cid):
    d = _load()
    before = len(d["custom"])
    d["custom"] = [c for c in d["custom"] if c.get("id") != cid]
    _save(d)
    return {"ok": before != len(d["custom"]), "remaining": len(d["custom"])}


def toggle_custom(cid, enabled):
    return update_custom(cid, enabled=bool(enabled))
