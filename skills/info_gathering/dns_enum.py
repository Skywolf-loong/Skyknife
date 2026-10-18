import dns.resolver
import dns.zone
import dns.query
from typing import Dict, Any, List
from skills.base import BaseSkill
import concurrent.futures

class DnsEnumSkill(BaseSkill):
    name = "dns_enum"
    description = "DNS 枚举：获取 A/AAAA/MX/NS/TXT 记录，可进行子域爆破"
    parameters = {
        "domain": {"type": "string", "required": True},
        "wordlist": {"type": "string", "default": "common"},  # 或内置列表
        "threads": {"type": "integer", "default": 50}
    }

    def _get_wordlist(self) -> List[str]:
        # 内置常见子域
        return ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns', 'test', 'admin',
                'blog', 'dev', 'api', 'secure', 'vpn', 'mobile', 'shop', 'app', 'cdn', 'm',
                'email', 'portal', 'support', 'forum', 'news', 'media', 'static', 'docs',
                'store', 'shop', 'db', 'sql', 'backup', 'old', 'new', 'beta', 'staging']

    def _resolve(self, hostname: str) -> List[str]:
        try:
            answers = dns.resolver.resolve(hostname, 'A')
            return [str(r) for r in answers]
        except:
            return []

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        if not isinstance(params, dict):
            return self.err(f"参数必须为对象，收到 {type(params).__name__}")
        context = context if isinstance(context, dict) else {}

        domain = params.get("domain")
        if not domain or not isinstance(domain, str):
            return self.err("缺少必需参数 domain（字符串）")
        domain = domain.strip()
        if "://" in domain:
            from urllib.parse import urlparse
            domain = urlparse(domain).hostname or domain
        wordlist = params.get("wordlist", "common")
        threads = params.get("threads", 50)

        # 获取基本记录
        records = {'A': [], 'AAAA': [], 'MX': [], 'NS': [], 'TXT': []}
        for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, qtype)
                records[qtype] = [str(r) for r in answers]
            except:
                pass

        # 子域爆破
        subdomains = []
        if wordlist == "common" or not wordlist:
            words = self._get_wordlist()
        else:
            try:
                with open(wordlist, 'r', encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip()]
            except Exception as e:
                return self.err(f"无法读取词表 {wordlist}: {e}")

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_sub = {executor.submit(self._resolve, f"{w}.{domain}"): w for w in words}
            for future in concurrent.futures.as_completed(future_to_sub):
                w = future_to_sub[future]
                ips = future.result()
                if ips:
                    found.append({'subdomain': w, 'ips': ips})

        result = {
            "domain": domain,
            "records": records,
            "subdomains": found,
            "subdomain_count": len(found)
        }
        context.setdefault("dns_enum", result)
        return {"status": "success", "data": result}