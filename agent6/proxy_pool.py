# -*- coding: utf-8 -*-
"""代理池管理（项目级，落盘于 agent6_data/proxy_pool.json）。

提供：
  - 代理增删改查 / 启用停用 / 设为活动
  - 连通性自测（记录延迟与状态）
  - 导出 requests 可用的 proxies 字典（供 _run_http 等 HTTP 工具统一走代理）

安全说明：
  - 默认 use_proxy=False，绝不静默把所有流量导到外部代理
  - 仅在用户于界面显式开启「通过代理测试」并指定活动代理后才生效
  - 密码在列表中脱敏回显，落盘为明文（本地文件，提示用户勿提交到公开仓库）
"""
import json
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# 落盘位置：与 agent6 其它状态一致放在 agent6_data 下
_DATA_DIR = Path(__file__).resolve().parent.parent / "agent6_data"
STORE = _DATA_DIR / "proxy_pool.json"

_VALID_TYPES = ("http", "https", "socks5")

DEFAULT_CHECK_URL = "http://example.com"

# 自动验证默认探测地址（与下方示例一致）
VERIFY_URL = "http://httpbin.org/ip"
VERIFY_TIMEOUT = 5
VERIFY_MAX_WORKERS = 100


def _load():
    try:
        d = json.loads(STORE.read_text(encoding="utf-8"))
    except Exception:
        d = {}
    d.setdefault("use_proxy", False)
    d.setdefault("active_id", None)
    d.setdefault("proxies", [])
    d.setdefault("rotation_enabled", False)
    d.setdefault("rotation_seconds", 60)
    return d


def _save(state):
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    STORE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    return state


def _mask(pwd: str) -> str:
    if not pwd:
        return ""
    if len(pwd) <= 2:
        return "•" * len(pwd)
    return pwd[:1] + "•" * (len(pwd) - 2) + pwd[-1]


def _build_url(p):
    scheme = p.get("type", "http")
    host = p.get("host", "")
    port = p.get("port", "")
    if not host or not port:
        return ""
    auth = ""
    u, pw = p.get("username", ""), p.get("password", "")
    if u:
        auth = f"{u}:{pw}@" if pw else f"{u}@"
    return f"{scheme}://{auth}{host}:{port}"


def _pub(p, active_id):
    return {
        "id": p["id"],
        "type": p.get("type", "http"),
        "host": p.get("host", ""),
        "port": p.get("port", ""),
        "username": p.get("username", ""),
        "has_password": bool(p.get("password")),
        "password_masked": _mask(p.get("password", "")),
        "tags": p.get("tags", ""),
        "note": p.get("note", ""),
        "enabled": p.get("enabled", True),
        "active": p["id"] == active_id,
        "last_check": p.get("last_check", {}),
    }


def list_proxies():
    s = _load()
    return {"use_proxy": s["use_proxy"], "active_id": s["active_id"],
            "count": len(s["proxies"]),
            "rotation_enabled": s["rotation_enabled"],
            "rotation_seconds": s["rotation_seconds"],
            "proxies": [_pub(p, s["active_id"]) for p in s["proxies"]]}


def add_proxy(ptype, host, port, username="", password="", tags="", note=""):
    s = _load()
    ptype = (ptype or "http").lower()
    if ptype not in _VALID_TYPES:
        return {"ok": False, "error": f"不支持的代理类型: {ptype}（仅 {_VALID_TYPES}）"}
    if not host or not str(port):
        return {"ok": False, "error": "缺少 host 或 port"}
    try:
        int(port)
    except Exception:
        return {"ok": False, "error": "port 必须为整数"}
    p = {"id": uuid.uuid4().hex[:10], "type": ptype, "host": host.strip(),
         "port": int(port), "username": username or "", "password": password or "",
         "tags": tags or "", "note": note or "", "enabled": True, "last_check": {}}
    s["proxies"].append(p)
    _save(s)
    return {"ok": True, "proxy": _pub(p, s["active_id"])}


def remove_proxy(pid):
    s = _load()
    before = len(s["proxies"])
    s["proxies"] = [p for p in s["proxies"] if p["id"] != pid]
    if s["active_id"] == pid:
        s["active_id"] = s["proxies"][0]["id"] if s["proxies"] else None
    _save(s)
    return {"ok": before != len(s["proxies"]), "remaining": len(s["proxies"])}


def batch_delete(ids):
    """批量删除：ids 为代理 id 列表，返回删除条数。"""
    ids = [str(i) for i in (ids or [])]
    if not ids:
        return {"ok": True, "deleted": 0, "remaining": len(_load()["proxies"])}
    s = _load()
    before = len(s["proxies"])
    s["proxies"] = [p for p in s["proxies"] if p["id"] not in set(ids)]
    after = len(s["proxies"])
    if s["active_id"] and s["active_id"] not in {p["id"] for p in s["proxies"]}:
        s["active_id"] = s["proxies"][0]["id"] if s["proxies"] else None
    _save(s)
    return {"ok": True, "deleted": before - after, "remaining": after}


def delete_failed():
    """一键删除「验证失败」的代理（last_check.ok is False）。

    从未检测的代理（last_check 为空）不会被删除——「验证失败」特指已探测且不通过。
    返回删除条数与被删 id 列表（供前端回显）。
    """
    s = _load()
    removed = []
    kept = []
    for p in s["proxies"]:
        if p.get("last_check", {}).get("ok") is False:
            removed.append(p["id"])
        else:
            kept.append(p)
    s["proxies"] = kept
    if s["active_id"] and s["active_id"] not in {p["id"] for p in kept}:
        s["active_id"] = kept[0]["id"] if kept else None
    _save(s)
    return {"ok": True, "deleted": len(removed), "ids": removed,
            "remaining": len(kept)}


def set_enabled(pid, enabled):
    s = _load()
    for p in s["proxies"]:
        if p["id"] == pid:
            p["enabled"] = bool(enabled)
            _save(s)
            return {"ok": True, "proxy": _pub(p, s["active_id"])}
    return {"ok": False, "error": "代理不存在"}


def activate(pid):
    s = _load()
    found = any(p["id"] == pid for p in s["proxies"])
    if not found:
        return {"ok": False, "error": "代理不存在"}
    s["active_id"] = pid
    _save(s)
    return {"ok": True, "active_id": pid, "list": list_proxies()}


def set_use_proxy(on):
    s = _load()
    s["use_proxy"] = bool(on)
    _save(s)
    return {"ok": True, "use_proxy": s["use_proxy"]}


def get_active_proxies_dict(force: bool = False):
    """供 HTTP 工具调用：返回 requests 的 proxies 字典。

    - 自动轮切关闭：返回「设为活动」的单个代理。
    - 自动轮切开启：按 rotation_seconds 时间片从「可用代理」中循环取一个
      （自动跳过禁用 / 最近检测不通过的代理），实现自动切能用的。
    未启用或无可活动代理时返回 {}。

    force=True 时跳过「use_proxy 总开关」的闸门（由上层「出网模式=代理池」
    显式授权，无需再依赖 per-feature 的 use_proxy 勾选），仍会尊重「无可用
    代理则直连」的安全默认。
    """
    s = _load()
    if not force and not s["use_proxy"]:
        return {}
    # 自动轮切模式
    if s.get("rotation_enabled"):
        cands = _rotation_candidates(s)
        if not cands:
            return {}
        secs = max(1, int(s.get("rotation_seconds", 60)))
        slot = int(time.time()) // secs % len(cands)
        p = cands[slot]
        url = _build_url(p)
        return {"http": url, "https": url} if url else {}
    # 单活动代理模式（原逻辑）
    if not s["active_id"]:
        return {}
    p = next((x for x in s["proxies"] if x["id"] == s["active_id"]), None)
    if not p or not p.get("enabled"):
        return {}
    url = _build_url(p)
    if not url:
        return {}
    return {"http": url, "https": url}


def _rotation_candidates(s):
    """自动轮切候选：启用且最近检测通过的代理；若尚无任何检测记录则退化为全部启用代理。"""
    enabled = [p for p in s["proxies"] if p.get("enabled", True)]
    if not enabled:
        return []
    working = [p for p in enabled
               if p.get("last_check", {}).get("ok") is True]
    return working if working else enabled


def test_proxy(pid, check_url=DEFAULT_CHECK_URL):
    s = _load()
    p = next((x for x in s["proxies"] if x["id"] == pid), None)
    if not p:
        return {"ok": False, "error": "代理不存在"}
    url = _build_url(p)
    if not url:
        return {"ok": False, "error": "代理地址不完整"}
    proxies = {"http": url, "https": url}
    rec = {"url": url, "ts": int(time.time()), "ok": False}
    try:
        import requests
        t0 = time.time()
        r = requests.get(check_url, proxies=proxies, timeout=10, verify=False)
        rec["status_code"] = r.status_code
        rec["latency_ms"] = int((time.time() - t0) * 1000)
        rec["ok"] = True
        rec["error"] = ""
    except Exception as e:
        rec["error"] = str(e)
    p["last_check"] = rec
    _save(s)
    return {"ok": rec["ok"], "proxy_id": pid, "check": rec}


# ----------------------------------------------------------------------------
#  解析 / 批量导入 / 自动验证 / 自动轮切设置
# ----------------------------------------------------------------------------
def _parse_proxy_line(line: str):
    """解析一行代理文本，返回 (type, host, port, username, password) 或 None。

    支持格式：
      - 带协议：http://1.2.3.4:8080 / socks5://u:p@1.2.3.4:1080
      - ip:port：1.2.3.4:8080
      - 空格分隔（一键导入规范）：ip port [username] [password]
      - 含认证：1.2.3.4:8080 user pass
    """
    if not line:
        return None
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    typ = "http"
    user = ""
    pwd = ""
    m = re.match(r"^(https?|socks[45])://(.+)$", line, re.I)
    if m:
        typ = m.group(1).lower()
        if typ == "socks4":
            typ = "socks5"
        line = m.group(2)
    if "@" in line:
        ui, line = line.split("@", 1)
        if ":" in ui:
            user, pwd = ui.split(":", 1)
        else:
            user = ui
    if " " in line:
        parts = line.split()
        if ":" in parts[0] and len(parts) >= 2:
            # 形如 "ip:port user pass" 或 "ip:port user"：首 token 含端口
            host, _, port = parts[0].rpartition(":")
            user = parts[1] if len(parts) > 1 else ""
            pwd = parts[2] if len(parts) > 2 else ""
        else:
            # 形如 "ip port [user] [pass]"（规范一键导入格式）
            host = parts[0]
            port = parts[1] if len(parts) > 1 else ""
            user = parts[2] if len(parts) > 2 else ""
            pwd = parts[3] if len(parts) > 3 else ""
    else:
        if ":" in line:
            host, _, port = line.rpartition(":")
        else:
            host, port = line, ""
    if not host or not port:
        return None
    return typ, host, port, user, pwd


def _import_lines(lines, default_type="http", tags="", seen=None):
    """批量解析并写入代理行，返回 {added, skipped}；seen 为已存在的 (host,port) 集合。"""
    added = 0
    skipped = 0
    if seen is None:
        seen = {(p.get("host"), str(p.get("port")))
                for p in _load().get("proxies", [])}
    for raw in lines:
        parsed = _parse_proxy_line(raw)
        if not parsed:
            continue
        typ, host, port, user, pwd = parsed
        if typ == "http" and default_type and default_type != "http":
            typ = default_type
        key = (host, str(port))
        if key in seen:
            skipped += 1
            continue
        r = add_proxy(typ, host, port, user, pwd, tags, "")
        if r.get("ok"):
            added += 1
            seen.add(key)
        else:
            skipped += 1
    return {"added": added, "skipped": skipped}


def import_text(text: str, default_type="http", tags="", dedupe=True):
    """一键导入：解析粘贴的 txt（每行 ip port [user] [pass] 或 ip:port 等）。"""
    if dedupe:
        seen = {(p.get("host"), str(p.get("port")))
                for p in _load().get("proxies", [])}
    else:
        seen = set()
    res = _import_lines((text or "").splitlines(), default_type, tags, seen)
    return {"ok": True, **res}


def import_from_urls(urls, default_type="http", tags="", timeout=20):
    """自动导入：从给定的 URL（如 GitHub raw）拉取代理列表并解析写入。"""
    urls = urls or []
    added = 0
    skipped = 0
    failed = []
    seen = {(p.get("host"), str(p.get("port")))
            for p in _load().get("proxies", [])}
    for u in urls:
        try:
            import requests
            resp = requests.get(u, timeout=timeout, verify=False)
            text = resp.text
        except Exception as e:
            failed.append({"url": u, "error": str(e)})
            continue
        # 兼容单条字符串或整个文本块
        blob = text if isinstance(text, str) else "\n".join(str(x) for x in text)
        r = _import_lines(blob.splitlines(), default_type, tags, seen)
        added += r["added"]
        skipped += r["skipped"]
    return {"ok": True, "added": added, "skipped": skipped, "failed": failed}


def verify_all(check_url=VERIFY_URL, timeout=VERIFY_TIMEOUT,
               max_workers=VERIFY_MAX_WORKERS):
    """自动验证：并发探测所有启用代理，写回 last_check，返回统计与逐条结果。

    示例实现要点：requests + ThreadPoolExecutor，探测 http://httpbin.org/ip，
    超时 5s，最大并发 100。无需外部依赖（requests 缺失时优雅降级为串行）。
    """
    s = _load()
    proxies = [p for p in s["proxies"] if p.get("enabled", True)]
    if not proxies:
        return {"ok": True, "checked": 0, "working": 0, "results": []}

    def _check(p):
        url = _build_url(p)
        rec = {"id": p["id"], "url": url, "ok": False}
        if not url:
            rec["error"] = "地址不完整"
            return rec
        pd = {"http": url, "https": url}
        try:
            import requests
            t0 = time.time()
            r = requests.get(check_url, proxies=pd, timeout=timeout, verify=False)
            rec["status_code"] = r.status_code
            rec["latency_ms"] = int((time.time() - t0) * 1000)
            rec["ok"] = True
        except Exception as e:
            rec["error"] = str(e)
        return rec

    try:
        with ThreadPoolExecutor(
                max_workers=max(1, min(max_workers, len(proxies)))) as ex:
            res = list(ex.map(_check, proxies))
    except Exception:
        res = [_check(p) for p in proxies]

    by_id = {p["id"]: p for p in s["proxies"]}
    for r in res:
        p = by_id.get(r["id"])
        if p:
            p["last_check"] = {k: v for k, v in r.items() if k != "id"}
    _save(s)
    return {"ok": True, "checked": len(res),
            "working": sum(1 for r in res if r["ok"]),
            "results": res}


def set_rotation(enabled, seconds=60):
    """设置自动轮切：开关 + 轮换时长（秒）。"""
    s = _load()
    s["rotation_enabled"] = bool(enabled)
    try:
        seconds = int(seconds)
    except Exception:
        seconds = 60
    s["rotation_seconds"] = max(1, seconds)
    _save(s)
    return {"ok": True, "rotation_enabled": s["rotation_enabled"],
            "rotation_seconds": s["rotation_seconds"]}
