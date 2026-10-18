# -*- coding: utf-8 -*-
"""TCP 层出网：把 socket 连接也送进代理（HTTP CONNECT 隧道）。

HTTP 代理只能转发 HTTP(S)；nmap、端口扫描、banner 抓取、TLS 握手这类裸 TCP 流量
若直接 `socket.connect()`，目标侧看到的就是本机真实 IP。本模块用 **HTTP CONNECT 隧道**
把这些连接也接到代理上：

    本机 socket ──CONNECT host:port──► 代理 ──► 目标
                                      （目标只看到代理出口 IP）

- ``open_tcp()``      同步：端口扫描/服务识别/SSL 检测
- ``open_tcp_async()`` 异步：port_scan 的 asyncio 版本
- ``proxy_tunnel()``  当前是否走隧道（none 模式返回 False）
- ``guard_command()`` 拦截无法代理的网络扫描命令（masscan/nc/hping3…），
  以及把 nmap 改造成可代理的 ``-sT --proxies`` 形式

**失败即失败**：隧道建不起来时抛错，绝不静默回落到直连（否则就泄露真实 IP 了）。
"""
import base64
import socket
import ssl
from typing import Optional
from urllib.parse import unquote, urlparse

_CONNECT_TIMEOUT = 8.0


# ---------------------------------------------------------------------------
# 代理信息
# ---------------------------------------------------------------------------
def proxy_parts() -> Optional[dict]:
    """返回当前可用的代理（host/port/认证），无代理返回 None。"""
    try:
        from .egress_config import get_egress_mode, resolve_proxy
        mode = get_egress_mode()
        p = resolve_proxy() or {}
    except Exception:
        return None
    url = str(p.get("http") or p.get("https") or "")
    if not url:
        return None
    u = urlparse(url)
    if not u.hostname:
        return None
    return {"mode": mode, "host": u.hostname, "port": u.port or 8080,
            "user": unquote(u.username) if u.username else "",
            "pwd": unquote(u.password) if u.password else "",
            "url": url}


def proxy_tunnel() -> bool:
    return proxy_parts() is not None


def allow_direct() -> bool:
    """是否允许「无法代理」的流量直连（默认禁止；由限速/隐蔽设置控制）。"""
    try:
        from .rate_limit import config as rl_cfg
        return bool(rl_cfg().get("allow_direct", False))
    except Exception:
        return False


def _auth_header(pp: dict) -> str:
    if not pp.get("user"):
        return ""
    raw = f"{pp['user']}:{pp.get('pwd') or ''}".encode("utf-8")
    return "Proxy-Authorization: Basic " + base64.b64encode(raw).decode() + "\r\n"


def _connect_request(host: str, port: int, pp: dict) -> bytes:
    return (f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"{_auth_header(pp)}"
            f"Proxy-Connection: keep-alive\r\n\r\n").encode("latin-1")


# ---------------------------------------------------------------------------
# 同步 TCP
# ---------------------------------------------------------------------------
def open_tcp(host: str, port: int, timeout: float = _CONNECT_TIMEOUT):
    """建立到 host:port 的 TCP 连接；有代理时经 CONNECT 隧道。失败抛 OSError。"""
    host = str(host or "").strip()
    port = int(port)
    pp = proxy_parts()
    if not pp:
        return socket.create_connection((host, port), timeout=timeout)
    s = socket.create_connection((pp["host"], pp["port"]), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(_connect_request(host, port, pp))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
        line = buf.split(b"\r\n", 1)[0].decode("latin-1", "ignore").strip()
        if " 200" not in line:
            raise OSError(f"代理 CONNECT {host}:{port} 失败（{line or '无响应'}）")
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        raise


def ssl_wrap(sock, host: str, verify: bool = False):
    """把已建好的 socket 包成 TLS（默认不校验证书，与技能原有行为一致）。"""
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
    return ctx.wrap_socket(sock, server_hostname=host)


# ---------------------------------------------------------------------------
# 异步 TCP（port_scan 用）
# ---------------------------------------------------------------------------
async def open_tcp_async(host: str, port: int, timeout: float = _CONNECT_TIMEOUT):
    """异步版：返回 (reader, writer)；有代理时经 CONNECT 隧道。"""
    import asyncio
    host = str(host or "").strip()
    port = int(port)
    pp = proxy_parts()
    if not pp:
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(pp["host"], pp["port"]), timeout)
    try:
        writer.write(_connect_request(host, port, pp))
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout)
        status = line.decode("latin-1", "ignore").strip()
        # 吃掉剩余响应头
        while True:
            h = await asyncio.wait_for(reader.readline(), timeout)
            if h in (b"\r\n", b"\n", b""):
                break
        if " 200" not in status:
            raise OSError(f"代理 CONNECT {host}:{port} 失败（{status}）")
        return reader, writer
    except Exception:
        try:
            writer.close()
        except Exception:
            pass
        raise


# ---------------------------------------------------------------------------
# 命令守卫：无法代理的扫描器一律拦下；nmap 改造成可代理形式
# ---------------------------------------------------------------------------
# 这些工具是原始包/裸 socket 扫描，HTTP 代理无法承载，且没有原生代理参数
_BLOCK_BINARIES = {
    "masscan": "masscan 发原始 SYN 包，无法经 HTTP 代理",
    "zmap": "zmap 发原始包，无法经 HTTP 代理",
    "hping3": "hping3 发原始包，无法经 HTTP 代理",
    "rustscan": "rustscan 直接建连扫描，无代理参数",
    "nc": "nc/netcat 是裸 TCP，无代理参数",
    "netcat": "nc/netcat 是裸 TCP，无代理参数",
    "telnet": "telnet 是裸 TCP，无代理参数",
    "arp-scan": "arp-scan 在链路层，无法经代理",
}

_BLOCK_RATE = ("禁止使用发包类/裸 TCP 扫描器（会暴露真实 IP）。"
               "请改用 nmap -sT（经代理隧道）、port_scan / service_detect 技能。")


def guard_command(cmd: str) -> Optional[str]:
    """返回拦截原因；可执行返回 None。"""
    from .tools import ToolRegistry  # 复用命令名解析，避免重复实现
    root = ToolRegistry._cmd_root(cmd)
    if root in _BLOCK_BINARIES and proxy_tunnel() and not allow_direct():
        return (f"{_BLOCK_BINARIES[root]}；当前出网模式已启用代理，"
                f"为隐藏真实 IP 已拦截。{_BLOCK_RATE}")
    return None


def rewrite_command(cmd: str, proxy_url: str, max_rate: int = 0) -> tuple:
    """给命令补代理/限速参数（nmap 额外改成 TCP connect 扫描）。

    返回 (新命令, 说明列表)。
    """
    import re
    notes = []
    if not proxy_url:
        return cmd, notes
    root = ""
    try:
        from .tools import ToolRegistry
        root = ToolRegistry._cmd_root(cmd)
    except Exception:
        pass

    if root == "nmap":
        new = cmd
        # 原始包扫描无法经代理：去掉 -sS/-sU/-O/-A，补 -sT
        if re.search(r"\s-sS\b", new) or re.search(r"\s-sU\b", new):
            new = re.sub(r"\s-sS\b", "", new)
            new = re.sub(r"\s-sU\b", "", new)
            notes.append("已把原始包扫描改为 -sT（才能经代理）")
        if re.search(r"\s-O\b", new):
            new = re.sub(r"\s-O\b", "", new)
            notes.append("已移除 -O（OS 检测需原始包）")
        if not re.search(r"\s-sT\b", new):
            new = re.sub(r"^(\s*nmap\b)", r"\1 -sT", new)
            notes.append("已补 -sT（TCP connect 扫描）")
        if "--proxies" not in new:
            new += f' --proxies "{proxy_url}"'
            notes.append("已注入 nmap --proxies（走 CONNECT 隧道）")
        if max_rate and "--max-rate" not in new:
            new += f" --max-rate {int(max_rate)}"
            notes.append(f"已限速 --max-rate {int(max_rate)}")
        return new, notes

    new = cmd
    rate_flag = {
        "nuclei": (f"-rate-limit {int(max_rate)}", "-rate-limit"),
        "ffuf": (f"-rate {int(max_rate)}", "-rate "),
        "gobuster": (f"--delay {max(1, int(1000 / max(1, max_rate)))}ms", "--delay"),
        "dirsearch": (f"--delay {max(0.05, round(1.0 / max(1, max_rate), 2))}", "--delay"),
    }
    frag = rate_flag.get(root)
    if max_rate and frag and frag[1] not in new:
        new += " " + frag[0]
        notes.append(f"已限速（{frag[0]}）")
    return new, notes
