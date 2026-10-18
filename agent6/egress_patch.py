# -*- coding: utf-8 -*-
"""把「统一出网模式」下沉到进程级，覆盖技能自建的 HTTP 客户端。

背景：`skills/` 里的技能大多直接 `requests.get(...)` / `requests.Session()` /
`aiohttp.ClientSession()`，不读工作台的出网配置；`command` 里跑的 curl 也只认环境变量。
结果是「只有 tools 里自带的 http 工具走了代理，其余直连」——在诱捕平台/目标日志里就会看到
本机真实出口 IP 与代理 IP 混杂。

本模块在进程内做两件事（幂等，只装一次）：
  1. 补 `requests.Session.request`：未显式指定 proxies 时，按当前出网模式注入；
  2. 补 `aiohttp.ClientSession._request`：未显式指定 proxy 时，按当前出网模式注入。
环境变量侧由 ``egress_config.apply_env()`` 负责（curl/wget/requests 默认会话都会读）。

**不代理**：本机回环（localhost/127.0.0.1）与 LLM 接口主机（见
``egress_config.bypass_hosts()``），避免本地服务、模型调用被绕到代理上。
**无法代理**：socket 直连类工具（nmap / 端口扫描 / TLS 握手）——HTTP 代理只能转发
HTTP(S)，这类流量必然是真实出口，属于协议限制，不是配置漏洞。
"""
import threading

_INSTALLED = False
_LOCK = threading.RLock()
_PXY = {"ts": 0.0, "proxies": {}}


def _proxy_dict() -> dict:
    """当前出网模式的 proxies（1 秒缓存，避免每个请求都读盘）。"""
    import time
    now = time.time()
    if (now - _PXY["ts"]) < 1.0:
        return _PXY["proxies"]
    try:
        from .egress_config import resolve_proxy
        p = resolve_proxy() or {}
    except Exception:
        p = {}
    _PXY.update({"ts": now, "proxies": p})
    return p


def _host_of(url) -> str:
    try:
        from urllib.parse import urlparse
        h = urlparse(str(url)).hostname or ""
        return h.lower()
    except Exception:
        return ""


def bypass(url) -> bool:
    """本机回环 / LLM 接口 / 非 HTTP(S) 一律不代理。"""
    u = str(url or "").lower()
    if not (u.startswith("http://") or u.startswith("https://")):
        return True
    h = _host_of(u)
    if not h:
        return True
    try:
        from .egress_config import bypass_hosts
        for b in bypass_hosts():
            b = (b or "").lower()
            if b and (h == b or h.endswith("." + b)):
                return True
    except Exception:
        pass
    return False


def _patch_requests():
    try:
        import requests  # noqa: F401
        from requests.sessions import Session
    except Exception:
        return False
    if getattr(Session, "_egress_patched", False):
        return True
    orig = Session.request

    def _request(self, method, url, **kwargs):
        try:
            if kwargs.get("proxies") is None and not bypass(url):
                p = _proxy_dict()
                if p:
                    kwargs["proxies"] = p
        except Exception:
            pass
        return orig(self, method, url, **kwargs)

    Session.request = _request
    Session._egress_patched = True
    return True


def _patch_aiohttp():
    try:
        import aiohttp
        from aiohttp import ClientSession
    except Exception:
        return False
    if getattr(ClientSession, "_egress_patched", False):
        return True
    orig = ClientSession._request

    async def _request(self, method, url, **kwargs):
        try:
            if not kwargs.get("proxy") and not bypass(url):
                p = _proxy_dict()
                if p:
                    kwargs["proxy"] = p.get("http") or p.get("https")
        except Exception:
            pass
        return await orig(self, method, url, **kwargs)

    ClientSession._request = _request
    ClientSession._egress_patched = True
    return True


def install() -> dict:
    """安装补丁 + 同步环境变量。幂等；失败只记录，不影响主流程。"""
    global _INSTALLED
    with _LOCK:
        req_ok = _patch_requests()
        aio_ok = _patch_aiohttp()
        _INSTALLED = True
        env = {}
        try:
            from .egress_config import apply_env
            env = apply_env(force=True)
        except Exception:
            env = {}
        return {"ok": True, "requests": req_ok, "aiohttp": aio_ok,
                "egress": env}


def status() -> dict:
    st = {"installed": _INSTALLED, "requests": False, "aiohttp": False}
    try:
        from requests.sessions import Session
        st["requests"] = bool(getattr(Session, "_egress_patched", False))
    except Exception:
        pass
    try:
        from aiohttp import ClientSession
        st["aiohttp"] = bool(getattr(ClientSession, "_egress_patched", False))
    except Exception:
        pass
    return st
