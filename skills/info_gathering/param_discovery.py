import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from typing import Dict, List, Any
from skills.base import BaseSkill

class ParamDiscoverySkill(BaseSkill):
    name = "param_discovery"
    description = "自动识别URL中的GET参数和HTML表单中的POST参数（如果未提供HTML，自动请求页面）"
    parameters = {
        "url": {"type": "string", "required": True, "description": "目标URL（带协议）"},
        "html": {"type": "string", "required": False, "description": "页面HTML内容（可选）"}
    }

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        if not isinstance(params, dict):
            return self.err(f"参数必须为对象，收到 {type(params).__name__}")
        context = context if isinstance(context, dict) else {}

        url = params.get("url")
        if not url or not isinstance(url, str):
            return self.err("缺少必需参数 url（字符串）")
        html = params.get("html")

        # 如果没有提供 HTML，尝试请求页面
        if not html:
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                }
                resp = requests.get(url, timeout=10, verify=False, allow_redirects=True, headers=headers)
                if resp.status_code == 200:
                    html = resp.text
                else:
                    # 即使状态码非200，仍可能包含信息，尝试使用
                    html = resp.text
            except Exception as e:
                return {"status": "error", "message": f"无法获取页面内容: {str(e)}"}

        get_params = {}
        parsed = urlparse(url)
        if parsed.query:
            get_params = parse_qs(parsed.query)
            # 将列表值转为逗号分隔字符串
            get_params = {k: ','.join(v) if len(v) > 1 else v[0] for k, v in get_params.items()}

        post_forms = []
        if html:
            soup = BeautifulSoup(html, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = []
                for inp in form.find_all('input'):
                    name = inp.get('name')
                    if name:
                        inputs.append({
                            "name": name,
                            "type": inp.get('type', 'text'),
                            "value": inp.get('value', '')
                        })
                # 也检查 textarea
                for ta in form.find_all('textarea'):
                    name = ta.get('name')
                    if name:
                        inputs.append({
                            "name": name,
                            "type": "textarea",
                            "value": ta.get_text(strip=True)
                        })
                post_forms.append({
                    "action": action,
                    "method": method,
                    "inputs": inputs
                })

        result = {
            "url": url,
            "get_params": get_params,
            "post_forms": post_forms,
            "all_get_params": list(get_params.keys()),
            "all_post_params": list(set(
                inp["name"] for form in post_forms for inp in form["inputs"]
            ))
        }
        context["param_discovery"] = result
        return {"status": "success", "data": result}
