# -*- coding: utf-8 -*-
"""速率限制（避免批量扫描暴露行踪 / 打挂业务）。

三档预设 + 自定义：

| 预设 | 全局 RPS | 单主机 RPS | 并发 | 抖动 | 扫描线程上限 |
|------|---------|-----------|------|------|-------------|
| stealth（隐蔽） | 2  | 1  | 2 | 60% | 4  |
| standard（标准）| 8  | 3  | 4 | 35% | 12 |
| fast（快速）    | 25 | 10 | 8 | 15% | 30 |

实现要点：
- **令牌桶**（全局 + 单主机各一个），取不到令牌就 sleep，天然平滑；
- **随机抖动**：在等待上叠加 0~jitter*间隔 的随机量，避免固定节奏被识别；
- **并发闸门**：同时执行的工具数受限（含长时间扫描），防止 worker 并行把目标打爆；
- **扫描线程上限**：对 dir_scan / port_scan 等自带线程数的技能做参数封顶；
- **命令限速**：nmap --max-rate、nuclei -rate-limit、ffuf -rate、gobuster --delay。

配置落盘 ``agent6_data/rate_limit.json``，改动即时生效（1 秒内）。
"""
import json
import random
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Optional

_ROOT = Path(__file__).resolve().parent.parent
STORE = _ROOT / "agent6_data" / "rate_limit.json"

PRESETS = {
    "stealth": {"global_rps": 2, "per_host_rps": 1, "burst": 2, "jitter": 0.6,
                "max_concurrency": 2, "scan_threads_cap": 4, "command_max_rate": 10,
                "skill_rps": 3},
    "standard": {"global_rps": 8, "per_host_rps": 3, "burst": 6, "jitter": 0.35,
                 "max_concurrency": 4, "scan_threads_cap": 12, "command_max_rate": 40,
                 "skill_rps": 10},
    "fast": {"global_rps": 25, "per_host_rps": 10, "burst": 20, "jitter": 0.15,
             "max_concurrency": 8, "scan_threads_cap": 30, "command_max_rate": 150,
             "skill_rps": 40},
}

DEFAULT = {
    "enabled": True,
    "preset": "standard",
    "global_rps": 8,
    "per_host_rps": 3,
    "burst": 6,
    "jitter": 0.35,
    "max_concurrency": 4,
    "scan_threads_cap": 12,
    "command_max_rate": 40,
    "skill_rps": 10,        # 扫描类技能「内部每个请求」的上限（目录爆破等）
    "allow_direct": False,   # 允许无法代理的裸 TCP 工具直连（会暴露真实 IP，默认禁止）
}

_LOCK = threading.RLock()
_CACHE = {"mtime": 0.0, "cfg": dict(DEFAULT)}
_STATS = {"calls": 0, "wait_s": 0.0, "active": 0, "peak": 0, "last_wait": 0.0}


def _load() -> Dict:
    try:
        mt = STORE.stat().st_mtime
    except Exception:
        mt = 0.0
    if mt and mt == _CACHE["mtime"]:
        return _CACHE["cfg"]
    cfg = dict(DEFAULT)
    try:
        raw = json.loads(STORE.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            for k, v in raw.items():
                if k in DEFAULT:
                    cfg[k] = v
    except Exception:
        pass
    _CACHE.update({"mtime": mt, "cfg": cfg})
    return cfg


def config() -> Dict:
    return dict(_load())


def set_config(**kw) -> Dict:
    cfg = dict(_load())
    preset = kw.get("preset")
    if preset and preset in PRESETS:
        cfg["preset"] = preset
        cfg.update(PRESETS[preset])
    for k in DEFAULT:
        if k in kw and kw[k] is not None and k != "preset":
            v = kw[k]
            if isinstance(DEFAULT[k], bool):
                cfg[k] = bool(v)
            elif isinstance(DEFAULT[k], (int, float)):
                try:
                    cfg[k] = float(v) if isinstance(DEFAULT[k], float) else int(float(v))
                except Exception:
                    continue
            else:
                cfg[k] = v
    # 约束
    cfg["global_rps"] = max(0.2, float(cfg.get("global_rps") or 1))
    cfg["per_host_rps"] = max(0.2, float(cfg.get("per_host_rps") or 1))
    cfg["burst"] = max(1, int(cfg.get("burst") or 1))
    cfg["jitter"] = min(1.0, max(0.0, float(cfg.get("jitter") or 0)))
    cfg["max_concurrency"] = max(1, int(cfg.get("max_concurrency") or 1))
    cfg["scan_threads_cap"] = max(1, int(cfg.get("scan_threads_cap") or 1))
    cfg["command_max_rate"] = max(1, int(cfg.get("command_max_rate") or 1))
    cfg["skill_rps"] = max(0.5, float(cfg.get("skill_rps") or 1))
    STORE.parent.mkdir(parents=True, exist_ok=True)
    STORE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    with _LOCK:
        _CACHE.update({"mtime": STORE.stat().st_mtime, "cfg": cfg})
        _reset_buckets(cfg)
    return cfg


def presets() -> Dict:
    return {k: dict(v) for k, v in PRESETS.items()}


# ---------------------------------------------------------------------------
# 令牌桶
# ---------------------------------------------------------------------------
class _Bucket:
    def __init__(self, rate: float, burst: int):
        self.rate = max(0.05, float(rate))
        self.cap = max(1, int(burst))
        self.tokens = float(self.cap)
        self.ts = time.time()
        self.lock = threading.Lock()

    def take(self) -> float:
        """取一个令牌；返回需要等待的秒数（并预支）。"""
        with self.lock:
            now = time.time()
            self.tokens = min(self.cap, self.tokens + (now - self.ts) * self.rate)
            self.ts = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return 0.0
            need = (1.0 - self.tokens) / self.rate
            self.tokens = 0.0
            self.ts = now + need
            return need


_GLOBAL = {"bucket": None, "hosts": {}, "sem": None, "cfg": None}


def _reset_buckets(cfg: Dict = None):
    cfg = cfg or _load()
    _GLOBAL["bucket"] = _Bucket(cfg["global_rps"], cfg["burst"])
    _GLOBAL["hosts"] = {}
    _GLOBAL["sem"] = threading.BoundedSemaphore(int(cfg["max_concurrency"]))
    _GLOBAL["cfg"] = cfg


def _host_bucket(host: str) -> _Bucket:
    cfg = _GLOBAL["cfg"] or _load()
    h = (host or "_").lower()
    b = _GLOBAL["hosts"].get(h)
    if b is None:
        # 单主机桶容量与全局一致，速率用 per_host_rps
        b = _Bucket(cfg["per_host_rps"], min(cfg["burst"], 3))
        _GLOBAL["hosts"][h] = b
    return b


def _ensure():
    if _GLOBAL["bucket"] is None:
        _reset_buckets(_load())


def gate(host: str = "", tool: str = "") -> float:
    """按当前限速配置等待（阻塞）；返回实际等待秒数。"""
    _ensure()
    cfg = config()
    if not cfg.get("enabled", True):
        return 0.0
    wait = _GLOBAL["bucket"].take()
    if host:
        wait = max(wait, _host_bucket(host).take())
    # 抖动：在等待上再加 0~jitter/rate 的随机量，打散节奏
    base = 1.0 / max(0.2, float(cfg["per_host_rps"]))
    if cfg["jitter"] > 0:
        wait += random.uniform(0, cfg["jitter"] * base)
    if wait > 0:
        time.sleep(min(wait, 30.0))
    with _LOCK:
        _STATS["calls"] += 1
        _STATS["wait_s"] += wait
        _STATS["last_wait"] = round(wait, 3)
    return wait


@contextmanager
def limit_scope(host: str = "", tool: str = ""):
    """限速 + 并发闸门。用法：``with limit_scope(host, tool): ...``"""
    _ensure()
    cfg = config()
    sem = _GLOBAL["sem"]
    if not cfg.get("enabled", True):
        yield
        return
    acquired = False
    try:
        # 等并发名额（最多等 120s，避免把 worker 永久卡死）
        acquired = sem.acquire(timeout=120)
        with _LOCK:
            _STATS["active"] += 1
            _STATS["peak"] = max(_STATS["peak"], _STATS["active"])
        gate(host, tool)
        yield
    finally:
        if acquired:
            with _LOCK:
                _STATS["active"] = max(0, _STATS["active"] - 1)
            try:
                sem.release()
            except Exception:
                pass


def cap_threads(tool: str, args: Dict) -> Dict:
    """给自带并发参数的扫描技能封顶（避免技能内部一次性打满）。"""
    cfg = config()
    if not cfg.get("enabled", True):
        return args
    cap = int(cfg.get("scan_threads_cap") or 12)
    for key in ("threads", "concurrency", "workers"):
        if key in (args or {}):
            try:
                cur = int(float(args[key]))
            except Exception:
                continue
            if cur > cap:
                args = dict(args)
                args[key] = cap
                return args
    return args


def command_rate() -> int:
    cfg = config()
    if not cfg.get("enabled", True):
        return 0
    return int(cfg.get("command_max_rate") or 0)


def skill_delay() -> float:
    """扫描类技能内部「每请求」间隔（秒）；限速关闭时返回 0。"""
    cfg = config()
    if not cfg.get("enabled", True):
        return 0.0
    rps = max(0.5, float(cfg.get("skill_rps") or 1))
    d = 1.0 / rps
    if cfg.get("jitter", 0) > 0:
        d *= 1.0 + random.uniform(0, cfg["jitter"])
    return d


def stats() -> Dict:
    with _LOCK:
        st = dict(_STATS)
    cfg = config()
    st.update({"config": cfg, "presets": list(PRESETS)})
    return st
