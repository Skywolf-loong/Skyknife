# -*- coding: utf-8 -*-
"""统一出网模式（egress mode）配置。

把「代理路由」收敛为单一控制权，避免代理池 / Tor 两套开关互相打架：

  - "none" 不使用代理      —— 所有对外探测直连，绝不经任何代理。
  - "pool" 使用代理池      —— 经代理池（单一活动代理 或 自动轮切）。
  - "tor"  使用 Tor 出口    —— 经 Tor 出口代理（需先确认《安全合规声明》）。

该模式是 HTTP 工具路由的唯一裁决者（见 tools.py::_run_http）。
保存该模式时会同步底层模块的开关（proxy_pool.use_proxy / tor.enabled），
保证界面各处的勾选状态保持一致。
"""
import json
import os
import threading
import time
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent.parent / "agent6_data"
STORE = _DATA_DIR / "egress_config.json"

VALID_MODES = ("none", "pool", "tor")
DEFAULT_MODE = "none"

# 各模式对应的中文/英文展示名（供前端与日志使用）
MODE_LABELS = {
    "none": {"zh": "不使用代理", "en": "No Proxy"},
    "pool": {"zh": "使用代理池", "en": "Proxy Pool"},
    "tor":  {"zh": "使用 Tor 出口", "en": "Tor Egress"},
}


def _load():
    try:
        d = json.loads(STORE.read_text(encoding="utf-8"))
    except Exception:
        d = {}
    d.setdefault("mode", DEFAULT_MODE)
    if d["mode"] not in VALID_MODES:
        d["mode"] = DEFAULT_MODE
    return d


def _save(cfg):
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    STORE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    return cfg


def get_egress_mode() -> str:
    """返回当前出网模式：none / pool / tor。"""
    return _load()["mode"]


def get_config() -> dict:
    return {"mode": _load()["mode"]}


def set_egress_mode(mode: str) -> dict:
    """设置出网模式，并同步底层模块开关。

    返回 {"ok", "mode"} 或 {"ok": False, "error"}（tor 模式未确认合规时拒绝）。
    """
    if mode not in VALID_MODES:
        return {"ok": False, "error": f"非法出网模式: {mode}（仅 {VALID_MODES}）"}
    from . import proxy_pool
    from . import tor_proxy

    if mode == "tor":
        tc = tor_proxy.get_config()
        if not tc.get("enabled") or not tc.get("compliance_ack"):
            return {"ok": False,
                    "error": "开启 Tor 出网前必须先确认《安全合规声明》并在 Tor 配置中启用"}
        # 关闭代理池，避免双路叠加
        proxy_pool.set_use_proxy(False)
    elif mode == "pool":
        # 开启代理池（前提：代理池至少存在一个代理才真正生效）
        proxy_pool.set_use_proxy(True)
        # 关闭 Tor
        tor_proxy.set_config(False)
    else:  # none
        proxy_pool.set_use_proxy(False)
        tor_proxy.set_config(False)

    c = _load()
    c["mode"] = mode
    _save(c)
    # 立刻把新模式落到进程环境变量（技能里的 requests/aiohttp、curl 等子进程都靠它）
    try:
        apply_env(force=True)
    except Exception:
        pass
    return {"ok": True, "mode": mode}


def resolve_proxy() -> dict:
    """供 HTTP 工具调用：按当前出网模式返回 requests 的 proxies 字典。

    返回 {} 表示直连（不使用代理）。
    """
    mode = get_egress_mode()
    if mode == "tor":
        try:
            from .tor_proxy import get_egress
            return get_egress() or {}
        except Exception:
            return {}
    if mode == "pool":
        try:
            from .proxy_pool import get_active_proxies_dict
            return get_active_proxies_dict(force=True) or {}
        except Exception:
            return {}
    return {}


# ---------------------------------------------------------------------------
# 进程级落地：环境变量（覆盖 requests 默认会话 / aiohttp / curl 等子进程）
# ---------------------------------------------------------------------------
_ENV_PROXY_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                   "http_proxy", "https_proxy", "all_proxy")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_ENV_LOCK = threading.RLock()
_ENV_CACHE = {"ts": 0.0, "mode": "", "url": "", "bypass": "", "applied": False}


def _llm_hosts() -> set:
    """LLM 接口主机：绝不走代理（避免占代理带宽 / 代理断连导致任务失败）。"""
    try:
        from urllib.parse import urlparse
        from .settings import load_settings
        base = ((load_settings().get("llm") or {}).get("base_url") or "")
        h = urlparse(str(base)).hostname
        return {h.lower()} if h else set()
    except Exception:
        return set()


def bypass_hosts() -> list:
    """不走代理的主机：本机回环 + LLM 接口。"""
    return sorted(_LOCAL_HOSTS | _llm_hosts())


def apply_env(force: bool = False) -> dict:
    """把当前出网模式写入进程环境变量，供所有 HTTP 客户端与子进程继承。

    - pool/tor：设置 HTTP_PROXY/HTTPS_PROXY/ALL_PROXY（含认证信息）
    - none    ：清除这些变量（含系统里预设的），保证「直连」语义一致
    - NO_PROXY 始终包含本机回环与 LLM 主机，避免把本地服务/模型调用也代理出去

    1 秒内重复调用直接复用缓存；切换模式时用 force=True 立即生效。
    """
    with _ENV_LOCK:
        now = time.time()
        if not force and (now - (_ENV_CACHE.get("ts") or 0)) < 1.0:
            return dict(_ENV_CACHE)
        mode = get_egress_mode()
        try:
            proxies = resolve_proxy() or {}
        except Exception:
            proxies = {}
        url = str(proxies.get("http") or proxies.get("https") or "")
        for k in _ENV_PROXY_KEYS:
            try:
                if url:
                    os.environ[k] = url
                else:
                    os.environ.pop(k, None)
            except Exception:
                pass
        bypass = ",".join(bypass_hosts())
        for k in ("NO_PROXY", "no_proxy"):
            try:
                os.environ[k] = bypass
            except Exception:
                pass
        _ENV_CACHE.update({"ts": now, "mode": mode, "url": url,
                           "bypass": bypass, "applied": bool(url)})
        return dict(_ENV_CACHE)


def env_state() -> dict:
    """当前进程的出网环境快照（供界面/日志展示，proxy url 里的密码不脱敏，勿外传）。"""
    return dict(_ENV_CACHE)
