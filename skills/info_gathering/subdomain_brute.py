import dns.resolver
import concurrent.futures
from typing import Dict, Any, List
from skills.base import BaseSkill

class SubdomainBruteSkill(BaseSkill):
    name = "subdomain_brute"
    description = "子域名字典爆破，使用公共后缀列表"
    parameters = {
        "domain": {"type": "string", "required": True},
        "wordlist": {"type": "string", "default": "common"}
    }

    def _get_wordlist(self) -> List[str]:
        return ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns', 'test', 'admin',
                'blog', 'dev', 'api', 'secure', 'vpn', 'mobile', 'shop', 'app', 'cdn', 'm',
                'email', 'portal', 'support', 'forum', 'news', 'media', 'static', 'docs',
                'store', 'shop', 'db', 'sql', 'backup', 'old', 'new', 'beta', 'staging']

    def _resolve(self, hostname: str) -> bool:
        try:
            dns.resolver.resolve(hostname, 'A')
            return True
        except:
            return False

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
        if wordlist == "common" or not wordlist:
            sub_list = self._get_wordlist()
        else:
            try:
                with open(wordlist, 'r', encoding="utf-8", errors="ignore") as f:
                    sub_list = [line.strip() for line in f if line.strip()]
            except Exception as e:
                return self.err(f"无法读取词表 {wordlist}: {e}")

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_sub = {executor.submit(self._resolve, f"{w}.{domain}"): w for w in sub_list}
            for future in concurrent.futures.as_completed(future_to_sub):
                w = future_to_sub[future]
                if future.result():
                    found.append(w)
        context.setdefault("subdomains", []).extend(found)
        return {"status": "success", "data": {"domain": domain, "subdomains": found, "count": len(found)}}