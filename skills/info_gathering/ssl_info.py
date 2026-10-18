import ssl
import socket
from datetime import datetime
from typing import Dict, Any
from skills.base import BaseSkill


class SslInfoSkill(BaseSkill):
    name = "ssl_info"
    description = "获取 SSL/TLS 证书信息（主体/颁发者/有效期/SAN/过期天数/协议与套件）"
    parameters = {
        "host": {"type": "string", "required": True},
        "port": {"type": "integer", "default": 443}
    }

    @staticmethod
    def _parse_cert_date(value: str):
        """证书日期格式：'Jun  1 12:00:00 2026 GMT'（注意可能是单空格填充的日）。"""
        if not value:
            return None
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        return None

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        if not isinstance(params, dict):
            return self.err(f"参数必须为对象，收到 {type(params).__name__}")
        context = context if isinstance(context, dict) else {}

        host = params.get("host")
        if not host or not isinstance(host, str):
            return self.err("缺少必需参数 host（字符串）")
        host = host.strip()
        # 允许传 URL，自动取主机名
        if "://" in host:
            from urllib.parse import urlparse
            p = urlparse(host)
            host = p.hostname or host
        try:
            port = int(params.get("port", 443))
        except (TypeError, ValueError):
            port = 443
        port = max(1, min(port, 65535))

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            from agent6.egress_net import open_tcp
            with open_tcp(host, port, timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert() or {}
                    not_before = self._parse_cert_date(cert.get('notBefore'))
                    not_after = self._parse_cert_date(cert.get('notAfter'))
                    now = datetime.now()

                    subject = {}
                    for rdn in cert.get('subject', ()):
                        for k, v in rdn:
                            subject[k] = v
                    issuer = {}
                    for rdn in cert.get('issuer', ()):
                        for k, v in rdn:
                            issuer[k] = v

                    days_left = (not_after - now).days if not_after else None
                    result = {
                        "host": host,
                        "port": port,
                        "subject": subject,
                        "issuer": issuer,
                        "common_name": subject.get("commonName", ""),
                        "san": cert.get('subjectAltName', []),
                        "not_before": not_before.isoformat() if not_before else None,
                        "not_after": not_after.isoformat() if not_after else None,
                        "days_remaining": days_left,
                        "expired": bool(not_after and not_after < now),
                        "expiring_soon": bool(days_left is not None and 0 <= days_left <= 30),
                        "serial": cert.get('serialNumber'),
                        "protocol": ssock.version(),
                        "cipher": (ssock.cipher() or [None, None, None])[0],
                        "cipher_bits": (ssock.cipher() or [None, None, None])[2],
                    }
                    context.setdefault("ssl_info", result)
                    return self.ok(result)
        except socket.timeout:
            return self.err(f"连接 {host}:{port} 超时")
        except ConnectionRefusedError:
            return self.err(f"{host}:{port} 连接被拒绝（端口未开放或非 TLS 服务）")
        except ssl.SSLError as e:
            return self.err(f"TLS 握手失败: {e}")
        except Exception as e:
            return self.err(f"获取证书失败: {e}")