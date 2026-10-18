"""
服务识别技能
对开放端口进行智能 banner 抓取和服务类型识别
"""
import socket
import asyncio
import ssl
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from skills.base import BaseSkill

# 已知服务的默认端口映射（用于快速识别）
KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
    # 常见 Web 替代端口
    8080: "HTTP",
    8443: "HTTPS",
    8000: "HTTP",
    8888: "HTTP",
}

# [新增] 这些端口即使无 banner 也认为是"识别成功"（因为服务类型明确）
WELL_KNOWN_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 27017,
    8080, 8443, 8000, 8888,
}

# 未指定 ports 时的默认探测端口（精选高频端口，控制耗时）
DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445,
                 1433, 3306, 3389, 5432, 6379, 8080, 8443]


class ServiceDetectSkill(BaseSkill):
    name = "service_detect"
    description = "对开放端口进行智能服务识别，支持 HTTP/HTTPS/SSH/FTP/SMTP/MySQL/Redis 等常见协议"
    parameters = {
        "target": {"type": "string", "required": True, "description": "目标 IP 或域名"},
        "ports": {
            "type": "array",
            "items": {"type": "integer"},
            "description": "端口列表（若未提供，则从 context 中的 open_ports 读取）"
        },
        "timeout": {"type": "number", "default": 3.0, "description": "连接超时（秒）"},
        "max_concurrency": {"type": "integer", "default": 20, "description": "最大并发探测数"},
        "ssl": {"type": "boolean", "default": False, "description": "是否对 443 端口强制使用 SSL（默认自动检测）"}
    }

    async def _probe_tcp(
        self,
        target: str,
        port: int,
        timeout: float,
        ssl_context: Optional[ssl.SSLContext] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        # 代理模式下走 CONNECT 隧道（否则会暴露本机真实 IP）
        try:
            from agent6.egress_net import proxy_tunnel
            if proxy_tunnel():
                return await self._probe_tcp_tunnel(target, port, timeout, ssl_context)
        except Exception:
            pass
        try:
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if ssl_context:
                sock = ssl_context.wrap_socket(sock, server_hostname=target)
            try:
                await loop.sock_connect(sock, (target, port))
            except asyncio.TimeoutError:
                return None, "连接超时"
            except Exception as e:
                return None, f"连接失败: {str(e)}"

            banner = await self._get_banner_by_port(sock, port, target, loop, timeout)
            sock.close()
            return banner, None
        except Exception as e:
            return None, str(e)

    async def _probe_tcp_tunnel(
        self, target: str, port: int, timeout: float,
        ssl_context: Optional[ssl.SSLContext] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        """经代理 CONNECT 隧道做服务识别（同步 socket 放进线程池，避免阻塞事件循环）。"""
        import asyncio as _aio
        from agent6.egress_net import open_tcp, ssl_wrap

        def _do() -> str:
            s = open_tcp(target, port, timeout=timeout)
            try:
                s.settimeout(timeout)
                if ssl_context is not None or port in (443, 8443):
                    try:
                        s = ssl_wrap(s, target, verify=False)
                    except Exception:
                        pass          # 非 TLS 端口，继续按明文读
                payload = b""
                if port in (80, 443, 8080, 8443, 8000, 8888):
                    payload = (b"HEAD / HTTP/1.0\r\nHost: " + target.encode()
                               + b"\r\nConnection: close\r\n\r\n")
                elif port in (21, 22, 25, 110, 143, 587, 993, 995):
                    payload = b"\r\n"
                if payload:
                    s.sendall(payload)
                try:
                    data = s.recv(2048)
                except Exception:
                    data = b""
                return data.decode("utf-8", errors="ignore").strip()
            finally:
                try:
                    s.close()
                except Exception:
                    pass

        try:
            loop = _aio.get_event_loop()
            banner = await loop.run_in_executor(None, _do)
            return (banner or None), None
        except Exception as e:
            return None, f"隧道连接失败: {e}"

    async def _get_banner_by_port(
        self,
        sock: socket.socket,
        port: int,
        target: str,
        loop: asyncio.AbstractEventLoop,
        timeout: float
    ) -> Optional[str]:
        try:
            sock.setblocking(False)
            if port in [21, 22, 25, 110, 143, 587, 993, 995]:
                pass
            elif port in [80, 443, 8080, 8443, 8000, 8888]:
                request = (
                    b"HEAD / HTTP/1.0\r\nHost: "
                    + target.encode()
                    + b"\r\nConnection: close\r\n\r\n"
                )
                await loop.sock_sendall(sock, request)
            elif port == 3306:
                pass
            elif port == 6379:
                await loop.sock_sendall(sock, b"PING\r\n")
            elif port == 5432:
                pass
            elif port == 25:
                await loop.sock_sendall(sock, b"HELO localhost\r\n")
            else:
                await loop.sock_sendall(sock, b"\r\n")

            banner = b""
            while True:
                try:
                    data = await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=1.0)
                    if not data:
                        break
                    banner += data
                    if len(banner) > 4096:
                        break
                except asyncio.TimeoutError:
                    break
                except Exception:
                    break

            if banner:
                for encoding in ['utf-8', 'latin-1', 'gbk']:
                    try:
                        text = banner.decode(encoding)
                        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
                        return text.strip()
                    except UnicodeDecodeError:
                        continue
                return banner.hex()
            return ""
        except Exception:
            return ""

    async def _probe_service(
        self,
        target: str,
        port: int,
        timeout: float,
        ssl_context: Optional[ssl.SSLContext]
    ) -> Dict:
        service_name = KNOWN_SERVICES.get(port, "unknown")
        banner = None
        error = None
        is_ssl = False

        if port in (443, 993, 995, 8443):
            if not ssl_context:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            try:
                banner, error = await self._probe_tcp(target, port, timeout, ssl_context)
                if banner is not None:
                    is_ssl = True
                    if port == 443 or port == 8443:
                        service_name = "HTTPS"
                    elif port == 993:
                        service_name = "IMAPS"
                    elif port == 995:
                        service_name = "POP3S"
            except Exception as e:
                error = str(e)

        if banner is None and not is_ssl:
            banner, error = await self._probe_tcp(target, port, timeout, None)

        version = ""
        if banner and service_name != "unknown":
            patterns = {
                "SSH": r"SSH-([\d.]+)",
                "HTTP": r"Server: ([^\r\n]+)",
                "HTTPS": r"Server: ([^\r\n]+)",
                "FTP": r"([\w\s]+) FTP server",
                "MySQL": r"(\d+\.\d+\.\d+)",
                "Redis": r"redis_version:(\d+\.\d+\.\d+)",
                "PostgreSQL": r"PostgreSQL ([\d.]+)",
            }
            if service_name in patterns:
                match = re.search(patterns[service_name], banner, re.I)
                if match:
                    version = match.group(1)

        result = {
            "port": port,
            "service": service_name,
            "banner": banner if banner else None,
            "version": version if version else None,
            "ssl": is_ssl,
            "error": error
        }
        return result

    async def _run_probes(
        self,
        target: str,
        ports: List[int],
        timeout: float,
        max_concurrency: int,
        ssl: bool
    ) -> List[Dict]:
        sem = asyncio.Semaphore(max_concurrency)
        ssl_context = None
        if ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        async def probe_with_sem(port):
            async with sem:
                return await self._probe_service(target, port, timeout, ssl_context)

        tasks = [probe_with_sem(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid = []
        for r in results:
            if isinstance(r, Exception):
                continue
            if r.get("error") is None:
                valid.append(r)
        return valid

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        if not isinstance(params, dict):
            return self.err(f"参数必须为对象，收到 {type(params).__name__}")
        context = context if isinstance(context, dict) else {}

        target = params.get("target")
        if not target:
            return self.err("缺少参数 'target'")

        # 端口来源优先级：显式 ports > context.open_ports > 内置常见端口
        ports = params.get("ports")
        if ports is None or not ports:
            open_ports = context.get("open_ports") or []
            ports = open_ports if open_ports else list(DEFAULT_PORTS)
            defaulted = not open_ports
        else:
            defaulted = False

        # 兼容 "80,443" / "80" 这类字符串写法
        if isinstance(ports, str):
            try:
                import json as _json
                v = _json.loads(ports)
                ports = v if isinstance(v, list) else [ports]
            except Exception:
                ports = [p.strip() for p in ports.split(",") if p.strip()]
        try:
            ports = [int(p) for p in ports]
        except (ValueError, TypeError):
            return self.err("端口列表格式错误，应为整数列表")

        try:
            timeout = float(params.get("timeout", 3.0))
        except (TypeError, ValueError):
            timeout = 3.0
        try:
            max_concurrency = int(params.get("max_concurrency", 20))
        except (TypeError, ValueError):
            max_concurrency = 20
        # 注意：不要命名为 ssl，否则会遮蔽模块级 ssl 导入
        use_ssl = bool(params.get("ssl", False))

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(
                self._run_probes(target, ports, timeout, max_concurrency, use_ssl)
            )
        finally:
            loop.close()

        service_data = {}
        for r in results:
            port = r["port"]
            service_data[port] = {
                "service": r["service"],
                "banner": r["banner"],
                "version": r["version"],
                "ssl": r["ssl"],
                "error": r["error"]
            }

        context.setdefault("services", {}).update(service_data)
        if defaulted:
            context.setdefault("notes", []).append(
                "未指定 ports，已默认使用内置常见端口列表")

        # ----------------------------------------------------------------
        # 结果分类
        # ----------------------------------------------------------------

        # 情形 1：完全未获取到任何服务信息
        if not service_data:
            return {
                "status": "error",
                "message": (
                    f"service_detect 未能在 {target}:{ports} 获取任何服务信息。\n"
                    "常见原因：目标端口开放但立即关闭连接，或探测超时。\n"
                    "建议：改用 `nmap -sV -p<ports> <target>` 获取版本信息；"
                    "或对 Web 端口使用 `curl -i` / `web_fingerprint`。"
                )
            }

        # [改动] 情形 2：是否有"已知服务端口"被识别
        # —— 已知端口即使无 banner 也算成功（服务类型已明确）
        known_ports_found = {
            p for p, v in service_data.items()
            if p in WELL_KNOWN_PORTS or v.get("service") not in (None, "unknown")
        }
        if known_ports_found:
            # 有已知端口 → 视为成功，但提示哪些端口需要额外探测
            unknown_ports = [
                p for p, v in service_data.items()
                if p not in known_ports_found and not v.get("banner")
            ]
            msg = f"已识别 {len(known_ports_found)} 个已知服务端口"
            if unknown_ports:
                msg += f"；{unknown_ports} 无 banner，建议用 nmap -sV 补充"
            return {
                "status": "success",
                "message": msg,
                "data": {
                    "services": service_data,
                    "count": len(service_data),
                    "known_ports": sorted(known_ports_found),
                    "unknown_ports": unknown_ports
                }
            }

        # 情形 3：所有端口都完全未知且无 banner
        return {
            "status": "error",
            "message": (
                f"service_detect 探测到 {len(service_data)} 个端口，"
                "但全部为未知服务且无 banner。\n"
                f"端口列表: {list(service_data.keys())}\n"
                "建议：改用 `nmap -sV -p<ports> <target>` 获取服务版本。"
            ),
            "data": {"services": service_data, "count": len(service_data)}
        }
