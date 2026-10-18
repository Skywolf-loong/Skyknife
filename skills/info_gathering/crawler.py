import os
import re
import json
import hashlib
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Dict, List, Set, Any, Optional
from pathlib import Path
from datetime import datetime
from skills.base import BaseSkill, CRAWLER_CACHE_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CrawlerSkill(BaseSkill):
    name = "crawler"
    description = "爬取网站：获取标题、递归爬取最多3层，缓存页面内容并智能摘要。自动使用多 User-Agent 轮换以绕过反爬提示。"
    parameters = {
        "url": {"type": "string", "required": True},
        "max_depth": {"type": "integer", "default": 3},
        "max_pages": {"type": "integer", "default": 50},
        "same_domain": {"type": "boolean", "default": True}
    }

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    ]

    ANTI_BOT_KEYWORDS = [
        "浏览器版本过低", "浏览器下载建议", "您的浏览器版本过低",
        "Please update your browser", "Your browser is outdated",
        "Access Denied", "blocked", "captcha", "验证码"
    ]

    def __init__(self):
        self.cache_dir = CRAWLER_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": self.USER_AGENTS[0],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })

    def _get_cache_path(self, url: str, ua_index: int = 0) -> Path:
        url_hash = hashlib.md5(f"{url}_{ua_index}".encode()).hexdigest()
        return self.cache_dir / f"{url_hash}.html"

    def _save_page(self, url: str, html: str, ua_index: int = 0):
        cache_path = self._get_cache_path(url, ua_index)
        with open(cache_path, 'w', encoding='utf-8') as f:
            f.write(html)

    def _load_page(self, url: str, ua_index: int = 0) -> Optional[str]:
        cache_path = self._get_cache_path(url, ua_index)
        if cache_path.exists():
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except:
                pass
        return None

    def _is_valid_page(self, html: str) -> bool:
        if not html or len(html) < 100:
            return False
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.title.string if soup.title else ""
            body_text = soup.get_text(separator=' ', strip=True)
            combined = (title + " " + body_text).lower()
            for keyword in self.ANTI_BOT_KEYWORDS:
                if keyword.lower() in combined:
                    return False
            return True
        except:
            return False

    def _fetch_with_ua_retry(self, url: str, timeout: int = 10) -> tuple:
        for idx, ua in enumerate(self.USER_AGENTS):
            cached = self._load_page(url, idx)
            if cached is not None and self._is_valid_page(cached):
                return cached, True, idx
            self.session.headers.update({"User-Agent": ua})
            try:
                resp = self.session.get(url, timeout=timeout, allow_redirects=True)
                if resp.status_code != 200:
                    continue
                html = resp.text
                self._save_page(url, html, idx)
                if self._is_valid_page(html):
                    return html, True, idx
            except Exception as e:
                print(f"[-] 请求 {url} 使用 UA {idx} 失败: {e}")
                continue
        # 尝试返回最后一个缓存（即使无效）
        for idx in range(len(self.USER_AGENTS)):
            cached = self._load_page(url, idx)
            if cached is not None:
                return cached, False, idx
        return "", False, -1

    def _extract_info(self, html: str, url: str) -> Dict:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.title.string.strip() if soup.title else "无标题"
            for script in soup(["script", "style"]):
                script.decompose()
            text = soup.get_text(separator=' ', strip=True)
            summary = text[:2000] if text else ""
            links = []
            for a in soup.find_all('a', href=True):
                href = urljoin(url, a['href'])
                if href.startswith(('http://', 'https://')):
                    links.append(href)
            return {"url": url, "title": title, "summary": summary, "links": links}
        except Exception as e:
            print(f"[-] 提取信息失败 {url}: {e}")
            return {"url": url, "title": "提取失败", "summary": "", "links": []}

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        try:
            start_url = context.get("final_url") or params.get("url") or params.get("target")
            if not start_url:
                return {"status": "error", "message": "缺少必需参数 'url' 或 'target'，请提供目标网址。"}

            if not start_url.startswith(('http://', 'https://')):
                start_url = 'https://' + start_url

            max_depth = params.get("max_depth", 3)
            max_pages = params.get("max_pages", 50)
            same_domain = params.get("same_domain", True)

            domain = urlparse(start_url).netloc
            visited = set()
            to_visit = [(start_url, 0)]
            results = []
            total_size = 0
            max_total_size = 1 * 1024 * 1024

            while to_visit and len(visited) < max_pages and total_size < max_total_size:
                url, depth = to_visit.pop(0)
                if url in visited:
                    continue
                visited.add(url)

                html, success, ua_idx = self._fetch_with_ua_retry(url, timeout=10)
                if not html:
                    continue

                context.setdefault("crawled_html", {})[url] = html
                info = self._extract_info(html, url)
                results.append(info)

                total_size += len(html.encode('utf-8'))

                if depth < max_depth:
                    for link in info["links"]:
                        if same_domain and urlparse(link).netloc != domain:
                            continue
                        if link not in visited and (link, depth+1) not in to_visit:
                            to_visit.append((link, depth+1))

                if len(results) % 5 == 0:
                    print(f"[*] 已爬取 {len(results)} 页，缓存大小约 {total_size//1024}KB")

            if len(results) == 0:
                return {"status": "error", "message": "无法爬取任何页面，请检查目标URL是否可达或服务是否正常运行。"}

            summary = {
                "total_pages": len(results),
                "bypass_anti_bot": any(self._is_valid_page(context.get("crawled_html", {}).get(r["url"], "")) for r in results),
                "pages": [
                    {"url": r["url"], "title": r["title"], "summary": r["summary"][:200] + "..."}
                    for r in results
                ]
            }
            context["crawler_results"] = summary
            return {"status": "success", "data": summary}
        except Exception as e:
            # 捕获所有异常，返回错误
            return {"status": "error", "message": f"爬虫执行异常: {str(e)}"}
