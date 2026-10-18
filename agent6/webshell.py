# -*- coding: utf-8 -*-
"""WebShell 管理（项目级，落盘 agent6_data/webshells.json）。

能力：
  - 连接增删改查 / 启停 / 批量删除
  - 连通性自测（记录状态与延迟）
  - 通用命令执行（GET/POST + 参数名，兼容经典 cmd 型 WebShell）
  - **与中国蚁剑（AntSword）数据互通**：
      * import_antsword()：导入蚁剑 shell 列表（localStorage 的 shells JSON）
      * export_antsword()：导出为蚁剑可识别的 shell 列表 JSON

安全合规（重要）：
  - 默认关闭对外执行：``exec_shell`` 需显式调用并建议前端二次确认；全过程可落审计。
  - 仅可用于拥有书面授权的目标；严禁未授权使用。
  - 命令执行流量遵循统一「出网模式」（none/pool/tor）。
"""
import json
import time
import uuid
from pathlib import Path
from urllib.parse import quote

_DATA_DIR = Path(__file__).resolve().parent.parent / "agent6_data"
STORE = _DATA_DIR / "webshells.json"

_VALID_TYPES = ("php", "jsp", "asp", "aspx", "other")
DEFAULT_TIMEOUT = 10


def _load():
    try:
        d = json.loads(STORE.read_text(encoding="utf-8"))
    except Exception:
        d = {}
    d.setdefault("shells", [])
    if not isinstance(d["shells"], list):
        d["shells"] = []
    return d


def _save(d):
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    STORE.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    return d


def _mask(pwd: str) -> str:
    if not pwd:
        return ""
    if len(pwd) <= 2:
        return "•" * len(pwd)
    return pwd[:1] + "•" * (len(pwd) - 2) + pwd[-1]


def _pub(s):
    return {
        "id": s["id"], "name": s.get("name", ""), "url": s.get("url", ""),
        "method": s.get("method", "GET"), "param": s.get("param", "cmd"),
        "type": s.get("type", "php"), "os": s.get("os", ""), "note": s.get("note", ""),
        "tags": s.get("tags", ""), "source": s.get("source", "manual"),
        "enabled": s.get("enabled", True),
        "has_password": bool(s.get("password")),
        "password_masked": _mask(s.get("password", "")),
        "encoding": s.get("encoding", ""),
        "last_check": s.get("last_check", {}),
        "created_at": s.get("created_at"),
    }


def list_shells(page=1, page_size=0, q=None):
    """列出连接。page_size>0 时服务端分页，返回 page/pages/total。"""
    d = _load()
    items = [_pub(s) for s in d["shells"]]
    if q:
        ql = q.lower()
        items = [x for x in items
                 if ql in f"{x.get('name','')} {x.get('url','')} {x.get('tags','')}".lower()]
    total = len(items)
    if page_size:
        try:
            size = min(500, max(1, int(page_size)))
            page = max(1, int(page or 1))
        except Exception:
            size, page = 20, 1
        pages = (total + size - 1) // size if total else 0
        start = (page - 1) * size
        return {"shells": items[start:start + size], "count": total, "total": total,
                "page": page, "page_size": size, "pages": pages}
    return {"shells": items, "count": total, "total": total}


def add_shell(name, url, method="GET", param="cmd", password="", stype="php",
              os_="", note="", tags="", source="manual", encoding=""):
    if not url or not str(url).strip():
        return {"ok": False, "error": "缺少 webshell url"}
    if (stype or "php").lower() not in _VALID_TYPES:
        stype = "other"
    d = _load()
    item = {"id": uuid.uuid4().hex[:10], "name": name or url, "url": url.strip(),
            "method": (method or "GET").upper(), "param": param or "cmd",
            "password": password or "", "type": (stype or "php").lower(),
            "os": os_ or "", "note": note or "", "tags": tags or "",
            "source": source or "manual", "encoding": encoding or "",
            "enabled": True, "last_check": {}, "created_at": int(time.time())}
    d["shells"].append(item)
    _save(d)
    return {"ok": True, "shell": _pub(item)}


def update_shell(sid, **fields):
    d = _load()
    for s in d["shells"]:
        if s["id"] == sid:
            for k in ("name", "url", "method", "param", "password", "type",
                      "os", "note", "tags", "enabled", "encoding"):
                if k in fields and fields[k] is not None:
                    s[k] = fields[k]
            _save(d)
            return {"ok": True, "shell": _pub(s)}
    return {"ok": False, "error": "WebShell 不存在"}


def delete_shell(sid):
    d = _load()
    before = len(d["shells"])
    d["shells"] = [s for s in d["shells"] if s["id"] != sid]
    _save(d)
    return {"ok": before != len(d["shells"]), "remaining": len(d["shells"])}


def batch_delete(ids):
    ids = {str(i) for i in (ids or [])}
    if not ids:
        return {"ok": True, "deleted": 0, "remaining": len(_load()["shells"])}
    d = _load()
    before = len(d["shells"])
    d["shells"] = [s for s in d["shells"] if s["id"] not in ids]
    _save(d)
    return {"ok": True, "deleted": before - len(d["shells"]),
            "remaining": len(d["shells"])}


def get_shell(sid):
    for s in _load()["shells"]:
        if s["id"] == sid:
            return s
    return None


# ---------------------------------------------------------------------------
# 中国蚁剑（AntSword）数据互通
# ---------------------------------------------------------------------------
def _antsword_to_shell(a: dict) -> dict:
    """把一条蚁剑 shell 记录映射为工作台的 webshell 项。"""
    # 蚁剑字段：url, pwd(参数名), type/encoder, method, category, note, encoding
    url = a.get("url") or a.get("address") or ""
    return {
        "name": a.get("name") or a.get("note") or url or "(未命名)",
        "url": url,
        "method": (a.get("method") or "POST").upper(),
        "param": a.get("pwd") or a.get("param") or "pass",
        "password": a.get("password") or "",
        "type": _guess_type(a.get("type") or a.get("encoder") or url),
        "os": a.get("os") or "",
        "note": a.get("note") or "",
        "tags": a.get("category") or "",
        "encoding": a.get("encoding") or "",
        "source": "antsword",
    }


def _guess_type(t: str) -> str:
    t = (t or "").lower()
    for k in ("php", "jsp", "asp", "aspx"):
        if k in t:
            return k
    if t.endswith((".php", ".jsp", ".asp", ".aspx")):
        return t.split(".")[-1]
    return "other"


def import_antsword(shells):
    """导入蚁剑 shell 列表（list[dict] 或 JSON 串）。按 url+param 去重。"""
    if isinstance(shells, str):
        try:
            shells = json.loads(shells)
        except Exception as e:
            return {"ok": False, "error": f"解析蚁剑数据失败: {e}"}
    if isinstance(shells, dict):
        shells = shells.get("shells") or shells.get("data") or []
    if not isinstance(shells, list):
        return {"ok": False, "error": "蚁剑数据应为 shell 列表"}
    seen = {(s.get("url"), s.get("param")) for s in _load()["shells"]}
    added, skipped = 0, 0
    for a in shells:
        if not isinstance(a, dict):
            skipped += 1
            continue
        item = _antsword_to_shell(a)
        if not item["url"]:
            skipped += 1
            continue
        if (item["url"], item["param"]) in seen:
            skipped += 1
            continue
        r = add_shell(item["name"], item["url"], method=item["method"],
                      param=item["param"], password=item.get("password", ""),
                      stype=item.get("type", "php"), os_=item.get("os", ""),
                      note=item.get("note", ""), tags=item.get("tags", ""),
                      source="antsword", encoding=item.get("encoding", ""))
        if r.get("ok"):
            added += 1
            seen.add((item["url"], item["param"]))
        else:
            skipped += 1
    return {"ok": True, "added": added, "skipped": skipped}


def export_antsword():
    """导出为蚁剑可识别的 shell 列表（localStorage.shells 结构）。"""
    out = []
    for s in _load()["shells"]:
        out.append({
            "name": s.get("name", ""),
            "url": s.get("url", ""),
            "pwd": s.get("param", "cmd"),
            "method": s.get("method", "GET"),
            "type": s.get("type", "php"),
            "category": s.get("tags", ""),
            "note": s.get("note", ""),
            "encoding": s.get("encoding", ""),
            "os": s.get("os", ""),
        })
    return {"ok": True, "shells": out, "count": len(out)}


# ---------------------------------------------------------------------------
# 连通性自测 / 命令执行
# ---------------------------------------------------------------------------
def _proxies():
    try:
        from .egress_config import resolve_proxy
        return resolve_proxy() or {}
    except Exception:
        return {}


def _build_request(shell, cmd: str):
    """构造请求参数：(method, url, data, headers)。按 method 决定命令放在 query 还是 body。"""
    url = shell["url"]
    param = shell.get("param") or "cmd"
    method = (shell.get("method") or "GET").upper()
    extra = {}
    if shell.get("password"):
        extra[shell.get("param_extra") or "pass"] = shell["password"]
    data = dict(extra)
    data[param] = cmd
    if method == "GET":
        sep = "&" if ("?" in url) else "?"
        q = "&".join(f"{quote(str(k))}={quote(str(v))}" for k, v in data.items())
        return "GET", f"{url}{sep}{q}", None
    return "POST", url, data


def exec_shell(sid, cmd, timeout=DEFAULT_TIMEOUT, confirm=False):
    """执行一条命令。confirm=False 时拒绝执行（防误触）。"""
    shell = get_shell(sid)
    if not shell:
        return {"ok": False, "error": "WebShell 不存在"}
    if not shell.get("enabled", True):
        return {"ok": False, "error": "该 WebShell 已停用"}
    if not confirm:
        return {"ok": False, "error": "执行命令需显式确认（confirm=true）"}
    if not cmd or not str(cmd).strip():
        return {"ok": False, "error": "缺少命令 cmd"}
    return _do_request(shell, cmd, timeout)


def test_shell(sid, timeout=DEFAULT_TIMEOUT):
    """连通性自测：发一条无害探测（echo）并记录状态。"""
    shell = get_shell(sid)
    if not shell:
        return {"ok": False, "error": "WebShell 不存在"}
    return _do_request(shell, "echo penworkbench_probe", timeout, record=True)


def _do_request(shell, cmd, timeout=DEFAULT_TIMEOUT, record=False):
    try:
        import requests
    except Exception as e:
        return {"ok": False, "error": f"缺少 requests 依赖: {e}"}
    method, url, data = _build_request(shell, cmd)
    req_desc = f"{method} {url}" + (f"\n\n{json.dumps(data, ensure_ascii=False)}" if data else "")
    out = {"ok": False, "shell_id": shell["id"], "request": req_desc}
    t0 = time.time()
    try:
        kw = dict(timeout=timeout, verify=False)
        px = _proxies()
        if px:
            kw["proxies"] = px
        if method == "GET":
            r = requests.get(url, **kw)
        else:
            r = requests.post(url, data=data, **kw)
        body = r.text[:20000]
        out.update({"ok": True, "status_code": r.status_code, "response": body,
                    "body": body, "length": len(r.text),
                    "latency_ms": int((time.time() - t0) * 1000)})
    except Exception as e:
        out.update({"ok": False, "error": str(e),
                    "latency_ms": int((time.time() - t0) * 1000)})
    if record:
        d = _load()
        for s in d["shells"]:
            if s["id"] == shell["id"]:
                s["last_check"] = {"ok": out["ok"], "ts": int(time.time()),
                                   "latency_ms": out.get("latency_ms"),
                                   "status_code": out.get("status_code"),
                                   "error": out.get("error", "")}
                _save(d)
                break
    out["command"] = cmd
    return out
