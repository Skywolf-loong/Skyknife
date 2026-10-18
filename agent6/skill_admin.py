# -*- coding: utf-8 -*-
"""技能管理后端 —— 把工作台内置的安全技能（可执行 / 知识型 / 索引）纳入可视化管理。

数据来源：``agent6/tools.py::ToolRegistry``（内部复用 ``core/skill_manager.py``）。

能力：
  - list_skills(kind/category/q)  ：技能清单（含类别、启用状态、来源）
  - get_skill(name)               ：技能详情（参数 / 审计 / 章节 / 工具可用性）
  - batch_toggle(names, enabled)  ：批量启停（停用后不计入工具清单，不挤占提示词预算）
  - query_skill(...)              ：知识型 Skill 检索（query / section / list_only）
  - stats()                       ：可执行 / 知识 / 索引 计数

禁用状态落盘 ``agent6_data/skill_state.json``：``{"disabled": [name, ...]}``。
被禁用的技能仍可按名字直接调用（供人工），但不进入 Planner/Worker 工具清单。
"""
import json
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent.parent / "agent6_data"
STORE = _DATA_DIR / "skill_state.json"

# 内置工具（非 skills/ 目录来源），一并展示
_BUILTIN = [
    {"name": "command", "type": "builtin", "kind": "builtin",
     "description": "执行本地 Shell 命令（nmap/nuclei/curl 等）"},
    {"name": "http", "type": "builtin", "kind": "builtin",
     "description": "轻量 HTTP 请求（method/url/headers/data）"},
    {"name": "search_all_worker_traces", "type": "builtin", "kind": "builtin",
     "description": "在本任务其它 work 的过程里做关键字检索"},
    {"name": "list_worker_traces", "type": "builtin", "kind": "builtin",
     "description": "列出本任务已跑过的 work"},
    {"name": "get_worker_trace", "type": "builtin", "kind": "builtin",
     "description": "取某个 work 的完整过程"},
]


def _load():
    try:
        d = json.loads(STORE.read_text(encoding="utf-8"))
    except Exception:
        d = {}
    d.setdefault("disabled", [])
    if not isinstance(d["disabled"], list):
        d["disabled"] = []
    return d


def _save(d):
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    STORE.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    return d


def disabled_set():
    return set(_load()["disabled"])


def is_disabled(name: str) -> bool:
    return name in disabled_set()


def _registry():
    """取全局 ToolRegistry（与任务执行共用同一实例）。"""
    from .webui import runner
    return runner.get_tools()


def _category_of(reg, name: str) -> str:
    """由来源模块路径推导分类：skills.claude_red.web.offensive_sqli -> claude_red/web。"""
    try:
        src = reg.skill_mgr.source_of(name) if reg.skill_mgr else None
    except Exception:
        src = None
    if not src:
        return "其它"
    src = str(src)
    if src.startswith("skills."):
        src = src[len("skills."):]
    parts = [p for p in src.split(".") if p]
    if len(parts) >= 2:
        return "/".join(parts[:-1])
    return parts[0] if parts else "其它"


def list_skills(kind=None, category=None, q=None, include_builtin=True):
    reg = _registry()
    disabled = disabled_set()
    out = []
    # 1) Skill 工具（含知识型）
    try:
        tools = reg.list_tools(include_knowledge=True)
    except Exception:
        tools = []
    for t in tools:
        if t.get("type") != "skill":
            continue
        name = t.get("name")
        k = t.get("kind") or "executable"
        cat = _category_of(reg, name)
        out.append({
            "name": name, "type": "skill", "kind": k, "category": cat,
            "description": t.get("description") or "",
            "required": t.get("required") or [],
            "parameters": t.get("parameters") or {},
            "source": (reg.skill_mgr.source_of(name) if reg.skill_mgr else ""),
            "enabled": name not in disabled,
        })
    # 2) 内置工具
    if include_builtin:
        for b in _BUILTIN:
            out.append({**b, "category": "内置", "enabled": True,
                        "required": [], "parameters": {}})

    def _match(x):
        if kind and x["kind"] != kind:
            return False
        if category and category not in (x["category"] or ""):
            return False
        if q:
            hay = f"{x['name']} {x['description']} {x['category']}".lower()
            if q.lower() not in hay:
                return False
        return True

    filtered = [x for x in out if _match(x)]
    filtered.sort(key=lambda x: (x["category"], x["name"]))
    return {"skills": filtered, "total": len(filtered),
            "facets": _facets(out)}


def _facets(all_items):
    cats, kinds = {}, {}
    for x in all_items:
        cats[x["category"]] = cats.get(x["category"], 0) + 1
        kinds[x["kind"]] = kinds.get(x["kind"], 0) + 1
    return {"categories": [{"name": k, "count": v}
                           for k, v in sorted(cats.items())],
            "kinds": [{"name": k, "count": v} for k, v in sorted(kinds.items())]}


def stats():
    reg = _registry()
    disabled = disabled_set()
    n = {"executable": 0, "knowledge": 0, "index": 0}
    total = 0
    try:
        for t in reg.list_tools(include_knowledge=True):
            if t.get("type") != "skill":
                continue
            total += 1
            k = t.get("kind") or "executable"
            n[k] = n.get(k, 0) + 1
    except Exception:
        pass
    return {"total": total, "executable": n.get("executable", 0),
            "knowledge": n.get("knowledge", 0), "index": n.get("index", 0),
            "disabled": len(disabled), "enabled": total - len(disabled),
            "builtin": len(_BUILTIN)}


def get_skill(name: str):
    if not name:
        return {"ok": False, "error": "缺少技能名"}
    reg = _registry()
    cls = reg.skill_mgr.get_skill(name) if reg.skill_mgr else None
    if not cls:
        return {"ok": False, "error": f"技能不存在: {name}"}
    inst = None
    try:
        inst = cls()
    except Exception:
        inst = None
    info = (reg._skill_info or {}).get(name, {})
    kind = reg._skill_kind(name)
    meta = {
        "name": name, "kind": kind, "category": _category_of(reg, name),
        "description": info.get("description") or getattr(cls, "description", "") or "",
        "parameters": info.get("parameters") or getattr(cls, "parameters", {}) or {},
        "required": info.get("required", []),
        "source": (reg.skill_mgr.source_of(name) if reg.skill_mgr else ""),
        "enabled": not is_disabled(name),
        "audit": getattr(inst or cls, "audit", None),
        "topics": getattr(inst or cls, "topics", None),
        "tools": getattr(inst or cls, "tools", None),
    }
    # 知识型附「概览」正文（消毒版，取首段）
    if kind == "knowledge":
        try:
            r = inst.execute({"list_only": True}, {})
            meta["catalog"] = (r or {}).get("data", {})
        except Exception as e:
            meta["catalog"] = {"error": str(e)}
    return {"ok": True, "skill": meta}


def batch_toggle(names, enabled: bool):
    names = [str(n) for n in (names or []) if n]
    if not names:
        return {"ok": False, "error": "缺少 names"}
    d = _load()
    cur = set(d["disabled"])
    if enabled:
        cur -= set(names)
    else:
        cur |= set(names)
    d["disabled"] = sorted(cur)
    _save(d)
    return {"ok": True, "enabled": bool(enabled), "changed": len(names),
            "disabled": len(cur)}


def query_skill(name, query=None, section=None, list_only=False, sanitize=True,
                max_chars=6000):
    """调用知识型 Skill 取方法论正文（默认消毒）。"""
    reg = _registry()
    cls = reg.skill_mgr.get_skill(name) if reg.skill_mgr else None
    if not cls:
        return {"ok": False, "error": f"技能不存在: {name}"}
    params = {}
    if query:
        params["query"] = query
    if section:
        params["section"] = section
    params["list_only"] = bool(list_only)
    params["sanitize"] = bool(sanitize)
    params["max_chars"] = int(max_chars or 6000)
    try:
        r = cls().execute(params, {})
    except Exception as e:
        return {"ok": False, "error": f"检索失败: {e}"}
    return {"ok": True, "result": r}
