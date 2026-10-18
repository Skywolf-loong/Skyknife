import whois
from typing import Dict, Any
from skills.base import BaseSkill

class WhoisLookupSkill(BaseSkill):
    name = "whois_lookup"
    description = "WHOIS 查询域名注册信息"
    parameters = {"domain": {"type": "string", "required": True}}

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        if not isinstance(params, dict):
            return self.err(f"参数必须为对象，收到 {type(params).__name__}")
        context = context if isinstance(context, dict) else {}

        domain = params.get("domain")
        if not domain or not isinstance(domain, str):
            return self.err("缺少必需参数 domain（字符串）")
        domain = domain.strip()
        # 允许传 URL，自动取主机名
        if "://" in domain:
            from urllib.parse import urlparse
            domain = urlparse(domain).hostname or domain
        try:
            w = whois.whois(domain)
            def _first(v):
                """whois 字段常为 list 或 None，统一取首个值。"""
                if isinstance(v, list):
                    return str(v[0]) if v else ""
                return "" if v is None else str(v)

            data = {
                "domain": domain,
                "registrar": _first(w.registrar),
                "creation_date": _first(w.creation_date),
                "expiration_date": _first(w.expiration_date),
                "updated_date": _first(w.updated_date),
                "name_servers": w.name_servers if isinstance(w.name_servers, list) else (
                    [w.name_servers] if w.name_servers else []),
                "emails": w.emails if isinstance(w.emails, list) else (
                    [w.emails] if w.emails else []),
                "org": _first(getattr(w, "org", None)),
                "country": _first(getattr(w, "country", None)),
            }
            if not any(data.get(k) for k in ("registrar", "creation_date", "emails", "name_servers")):
                return self.err(f"WHOIS 未返回有效信息（域名可能不存在，或本机缺少 whois 命令）: {domain}")
            context.setdefault("whois", data)
            return self.ok(data)
        except Exception as e:
            return self.err(f"WHOIS 查询失败: {e}")