# -*- coding: utf-8 -*-
"""Tor 链路出口代理（默认关闭，需显式开启并确认合规声明）。

设计要点（来自集成需求）：
  - 链路：本机 → 出口 HTTP 代理(默认 127.0.0.1:8080) → Tor 入口 → 中间节点 → 出口节点 → 目标
  - 出口代理端口（示例 8080）可配置，也可「不使用」；一旦启用，本工作台对外探测流量
    全部经该出口端口转发，因为只有该端口能访问互联网 / 进入 Tor 网络。
  - 另提供 socket 劫持助手（enable_proxy_chain），使本地 Tor 客户端自身（如 hypertor/arti）
    的出站连接也经由出口代理——该助手依赖可选包 pyChainedProxy，缺失时优雅降级并提示。

安全合规（重要）：
  Tor 匿名网络仅可用于合法授权的安全测试与研究。严禁在法律法规禁止的国家或地区使用本功能，
  严禁用于任何非法目的；使用者须自行确认所在司法管辖区允许此类用途，并仅对拥有书面授权的
  目标进行测试。违反上述规定所产生的一切法律后果由使用者自行承担。
"""
import json
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent.parent / "agent6_data"
STORE = _DATA_DIR / "tor_config.json"

DEFAULT_EGRESS_HOST = "127.0.0.1"
DEFAULT_EGRESS_PORT = 8080

# 合规声明（首次开启前必须勾选确认）
COMPLIANCE_TEXT = (
    "安全合规声明：Tor 匿名网络仅可用于合法授权的安全测试与研究。\n"
    "严禁在法律法规禁止的国家或地区使用本功能，严禁用于任何非法目的。\n"
    "使用者须自行确认其所在司法管辖区允许此类用途，并仅对拥有书面授权的目标进行测试。\n"
    "违反上述规定所产生的一切法律后果由使用者自行承担。"
)


def _load():
    try:
        d = json.loads(STORE.read_text(encoding="utf-8"))
    except Exception:
        d = {}
    d.setdefault("enabled", False)
    d.setdefault("egress_host", DEFAULT_EGRESS_HOST)
    d.setdefault("egress_port", DEFAULT_EGRESS_PORT)
    d.setdefault("compliance_ack", False)
    return d


def _save(cfg):
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    STORE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    return cfg


def get_compliance_text():
    return COMPLIANCE_TEXT


def get_config():
    c = _load()
    return {
        "enabled": c["enabled"],
        "egress_host": c["egress_host"],
        "egress_port": c["egress_port"],
        "compliance_ack": c["compliance_ack"],
        "compliance_text": COMPLIANCE_TEXT,
    }


def set_config(enabled: bool, egress_host: str = None, egress_port: int = None,
               compliance_ack: bool = False):
    """保存配置。开启 Tor 前必须已确认合规声明（compliance_ack=True），否则拒绝开启。"""
    c = _load()
    if egress_host is not None:
        c["egress_host"] = egress_host.strip() or DEFAULT_EGRESS_HOST
    if egress_port is not None:
        try:
            c["egress_port"] = int(egress_port)
        except Exception:
            c["egress_port"] = DEFAULT_EGRESS_PORT
    if enabled:
        if not c.get("compliance_ack") and not compliance_ack:
            return {"ok": False,
                    "error": "开启 Tor 前必须先阅读并确认《安全合规声明》"}
        c["compliance_ack"] = True
        c["enabled"] = True
    else:
        c["enabled"] = False
    _save(c)
    return {"ok": True, **{k: c[k] for k in
            ("enabled", "egress_host", "egress_port", "compliance_ack")}}


def get_egress():
    """供 HTTP 工具调用：返回 requests 的 proxies 字典（出口代理）。未开启或配置不完整返回 {}。"""
    c = _load()
    if not c.get("enabled"):
        return {}
    host = c.get("egress_host") or DEFAULT_EGRESS_HOST
    port = c.get("egress_port") or DEFAULT_EGRESS_PORT
    if not host or not port:
        return {}
    url = f"http://{host}:{port}"
    return {"http": url, "https": url}


def enable_proxy_chain(egress_host: str = None, egress_port: int = None):
    """（可选）劫持全局 socket，使本地 Tor 客户端（hypertor/arti 等）出站也经出口代理。

    依赖可选包 pyChainedProxy（pip install pyChainedProxy）。缺失时返回失败并说明。
    必须在初始化任何 Tor 客户端「之前」调用。
    """
    c = _load()
    host = (egress_host or c.get("egress_host") or DEFAULT_EGRESS_HOST)
    port = int(egress_port or c.get("egress_port") or DEFAULT_EGRESS_PORT)
    try:
        import socket
        import pyChainedProxy as socks
    except Exception as e:
        return {"ok": False,
                "error": f"缺少可选依赖 pyChainedProxy（pip install pyChainedProxy）：{e}"}
    socks.setdefaultproxy()
    socks.adddefaultproxy(socks.PROXY_TYPE_HTTP, host, port, rdns=True)
    socks.setproxy("localhost", socks.PROXY_TYPE_NONE)
    socks.setproxy("127.0.0.1", socks.PROXY_TYPE_NONE)
    socket.socket = socks.socksocket
    return {"ok": True, "egress": f"{host}:{port}",
            "note": "全局 socket 已劫持，Tor 客户端出站将经出口代理；建议仅在独立进程中执行。"}


def fetch_via_tor(target_url: str = "https://check.torproject.org/api/ip"):
    """（可选）经出口代理 → Tor → 互联网 拉取目标，用于自检匿名性。依赖 hypertor。"""
    try:
        import hypertor
    except Exception as e:
        return {"ok": False, "error": f"缺少可选依赖 hypertor（pip install hypertor）：{e}"}
    try:
        client = hypertor.Client(timeout=120.0, isolation="per_request")
        resp = client.get(target_url)
        return {"ok": True, "status_code": resp.status_code, "text": resp.text[:500]}
    except Exception as e:
        return {"ok": False, "error": str(e)}
