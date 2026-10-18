import requests
import hashlib
import re
import urllib3
from typing import Dict, Any
from skills.base import BaseSkill

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EMPTY_FAVICON_MD5 = "d41d8cd98f00b204e9800998ecf8427e"


class WebFingerprintSkill(BaseSkill):
    name = "web_fingerprint"
    description = "Web 指纹识别：获取响应头、标题、favicon hash，支持重定向和常见 User-Agent"
    parameters = {
        "url": {"type": "string", "required": True, "description": "目标URL（带协议）"}
    }

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        if not isinstance(params, dict):
            return self.err(f"参数必须为对象，收到 {type(params).__name__}")
        context = context if isinstance(context, dict) else {}

        url = params.get("url")
        if not url or not isinstance(url, str):
            return self.err("缺少必需参数 url（字符串）")
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if context.get("final_url"):
            url = context["final_url"]

        session = requests.Session()
        session.verify = False
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })

        try:
            resp = session.get(url, timeout=10, allow_redirects=True)
            headers_dict = dict(resp.headers)

            # [改动] 用更鲁棒的标题提取：不限 content-type，支持大小写、属性
            title = ""
            html = resp.text or ""
            m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
            if m:
                title = m.group(1).strip()

            # favicon
            favicon_url = url.rstrip('/') + '/favicon.ico'
            favicon_hash = ""
            try:
                ico = session.get(favicon_url, timeout=5)
                if ico.status_code == 200 and ico.content:
                    favicon_hash = hashlib.md5(ico.content).hexdigest()
            except Exception:
                pass

            tech = {
                "url": resp.url,  # [改动] 记录最终 URL（可能有重定向）
                "status_code": resp.status_code,  # [改动] 记录状态码
                "server": headers_dict.get('server', ''),
                "powered_by": headers_dict.get('x-powered-by', ''),
                "framework": headers_dict.get('x-generator', ''),
                "title": title,
                "favicon_hash": favicon_hash,
                "content_length": headers_dict.get('content-length', ''),
                "content_type": headers_dict.get('content-type', '')
            }
            context.setdefault("web_fingerprint", tech)
            context["final_url"] = resp.url

            # [改动] 若抓不到任何信息 → 返回 error 而非 success
            title_empty = not tech["title"]
            server_empty = not tech["server"] and not tech["powered_by"] and not tech["framework"]
            favicon_empty = not tech["favicon_hash"] or tech["favicon_hash"] == EMPTY_FAVICON_MD5

            if title_empty and server_empty and favicon_empty:
                # 但如果是 302，明确告知目标有重定向
                if 300 <= resp.status_code < 400:
                    location = headers_dict.get('location', '')
                    return {
                        "status": "error",
                        "message": (
                            f"目标返回 {resp.status_code} 重定向（Location: {location}），"
                            "未获取到页面内容。建议直接访问重定向后的 URL。"
                        ),
                        "data": tech
                    }
                return {
                    "status": "error",
                    "message": (
                        f"无法从 {resp.url} 提取有效指纹（title/server/powered_by/favicon 均为空）。"
                        "可能原因：目标返回空页面、非 HTML、或需要特定 Header。"
                        "建议改用 `curl -i <URL>` 查看原始响应头。"
                    ),
                    "data": tech
                }

            return {"status": "success", "data": tech}
        except requests.exceptions.Timeout:
            return {"status": "error", "message": "请求超时"}
        except requests.exceptions.ConnectionError as e:
            return {"status": "error", "message": f"连接错误: {e}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
