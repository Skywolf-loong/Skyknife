import aiohttp
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urljoin, urlparse
from skills.base import BaseSkill

# 内置字典（取自常见渗透测试词表的 Top 100 目录/文件）
DEFAULT_WORDLIST = [
    "admin", "admin/", "administrator", "backup", "backup/", "bak", "bin",
    "cgi-bin", "config", "css", "data", "db", "docs", "download", "downloads",
    "dump", "files", "fonts", "images", "img", "include", "includes", "js",
    "lib", "logs", "media", "modules", "old", "pdf", "phpmyadmin", "plugins",
    "private", "public", "robots.txt", "scripts", "secure", "server-status",
    "sitemap.xml", "sql", "src", "stat", "static", "temp", "tmp", "upload",
    "uploads", "user", "users", "web", "www", "wwwroot", "xml", "zip",
    # WordPress 特定
    "wp-admin", "wp-content", "wp-includes", "wp-json", "xmlrpc.php",
    "wp-login.php", "wp-signup.php", "wp-register.php", "wp-cron.php",
    "wp-links-opml.php", "wp-settings.php", "wp-config.php", "wp-config-sample.php",
    "readme.html", "license.txt", "wp-activate.php", "wp-mail.php", "wp-trackback.php",
    "wp-app.php", "wp-blog-header.php", "wp-comments-post.php", "wp-load.php",
    "wp-login", "wp-admin/install.php", "wp-admin/upgrade.php"
]

class DirScanSkill(BaseSkill):
    name = "dir_scan"
    description = "增强型异步目录爆破，支持自定义词表、扩展名、请求头、状态码过滤等"
    parameters = {
        "url": {"type": "string", "required": True, "description": "目标基础URL（如 http://example.com/）"},
        "wordlist": {"type": "string", "description": "自定义字典文件路径，若未提供则使用内置字典"},
        "extensions": {"type": "array", "default": [".php", ".html", ".txt", ".bak", ".old", ".sql"], "description": "要尝试的文件扩展名列表"},
        "threads": {"type": "integer", "default": 30, "description": "并发请求数"},
        "timeout": {"type": "number", "default": 5, "description": "请求超时时间（秒）"},
        "follow_redirects": {"type": "boolean", "default": False, "description": "是否跟随重定向"},
        "headers": {"type": "object", "description": "自定义请求头（JSON对象）"},
        "status_codes": {"type": "array", "default": [200, 301, 302, 403, 500], "description": "需要记录的状态码列表"},
        "max_paths": {"type": "integer", "default": 0, "description": "最大扫描路径数（0表示不限制）"},
        "cache_key": {"type": "string", "description": "上下文中的缓存键，用于避免重复扫描"}
    }

    def __init__(self):
        self.builtin_wordlist = DEFAULT_WORDLIST
        self.session = None
        self.semaphore = None

    def _load_wordlist_from_file(self, file_path: str) -> List[str]:
        """从文件加载词表，每行一个条目"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return words
        except Exception as e:
            print(f"[dir_scan] 读取词表文件失败: {e}，使用内置词表")
            return self.builtin_wordlist

    def _get_wordlist(self, wordlist_param: Optional[str]) -> List[str]:
        """根据参数获取词表"""
        if wordlist_param and Path(wordlist_param).exists():
            return self._load_wordlist_from_file(wordlist_param)
        return self.builtin_wordlist

    def _build_paths(self, base_words: List[str], extensions: List[str]) -> Set[str]:
        """生成所有路径组合（去重）"""
        paths = set()
        for word in base_words:
            paths.add(word)
            for ext in extensions:
                paths.add(f"{word}{ext}")
            if word.endswith('/'):
                paths.add(word.rstrip('/'))
            else:
                paths.add(word + '/')
        return paths

    async def _check_path(self, session: aiohttp.ClientSession, base_url: str, path: str,
                          timeout: float, follow_redirects: bool, status_codes: List[int]) -> Optional[Dict]:
        """检查单个路径（按限速配置做请求间隔，避免目录爆破过密）"""
        full_url = urljoin(base_url, path)
        # 技能内部限速：仅靠工具层「每次调用」限速挡不住一次几百个请求的爆破
        try:
            from agent6.rate_limit import skill_delay
            d = skill_delay()
            if d > 0:
                await asyncio.sleep(d)
        except Exception:
            pass
        try:
            async with session.get(full_url, timeout=aiohttp.ClientTimeout(total=timeout),
                                   allow_redirects=follow_redirects) as resp:
                if resp.status in status_codes:
                    content = await resp.read()
                    content_type = resp.headers.get('Content-Type', '')
                    redirect_url = str(resp.url) if resp.history else None
                    return {
                        "path": path,
                        "url": full_url,
                        "status": resp.status,
                        "size": len(content),
                        "content_type": content_type,
                        "redirect": redirect_url if redirect_url != full_url else None
                    }
        except asyncio.TimeoutError:
            pass
        except aiohttp.ClientError:
            pass
        return None

    async def _run_scan(self, base_url: str, paths: List[str], threads: int,
                        timeout: float, follow_redirects: bool, status_codes: List[int],
                        max_paths: int, headers: Optional[Dict] = None) -> List[Dict]:
        """异步扫描主函数，接收 headers 参数"""
        if max_paths > 0:
            paths = paths[:max_paths]

        sem = asyncio.Semaphore(threads)
        found = []

        connector = aiohttp.TCPConnector(limit=threads, limit_per_host=threads)
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        if headers:
            default_headers.update(headers)

        async with aiohttp.ClientSession(connector=connector, headers=default_headers) as session:
            tasks = []
            for p in paths:
                tasks.append(self._check_path(session, base_url, p, timeout, follow_redirects, status_codes))
            chunk_size = 1000
            for i in range(0, len(tasks), chunk_size):
                chunk = tasks[i:i+chunk_size]
                results = await asyncio.gather(*chunk, return_exceptions=True)
                for r in results:
                    if isinstance(r, dict) and r is not None:
                        found.append(r)
        return found

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        # 提取参数
        base_url = params.get("url")
        if not base_url:
            return {"status": "error", "message": "缺少参数 'url'"}
        if not base_url.endswith('/'):
            base_url += '/'

        wordlist_path = params.get("wordlist")
        extensions = params.get("extensions", [".php", ".html", ".txt", ".bak", ".old", ".sql"])
        threads = params.get("threads", 30)
        timeout = params.get("timeout", 5)
        follow_redirects = params.get("follow_redirects", False)
        status_codes = params.get("status_codes", [200, 301, 302, 403, 500])
        max_paths = params.get("max_paths", 0)
        cache_key = params.get("cache_key", "dir_scan_results")
        headers = params.get("headers")  # 获取自定义 headers

        # 检查缓存
        if cache_key in context:
            cached = context[cache_key]
            if cached.get("base_url") == base_url:
                return {"status": "success", "data": cached.get("found", []), "cached": True}

        # 获取词表
        words = self._get_wordlist(wordlist_path)
        path_set = self._build_paths(words, extensions)
        paths = list(path_set)

        if max_paths > 0:
            paths = paths[:max_paths]

        # 异步运行
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            found = loop.run_until_complete(
                self._run_scan(base_url, paths, threads, timeout, follow_redirects, status_codes, max_paths, headers)
            )
        finally:
            loop.close()

        context[cache_key] = {
            "base_url": base_url,
            "found": found,
            "count": len(found)
        }

        return {
            "status": "success",
            "data": {
                "found": found,
                "count": len(found)
            }
        }
