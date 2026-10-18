"""
Shodan API 查询技能（修复编码问题）
需要安装 shodan 库 (pip install shodan)
并配置 API Key：环境变量 SHODAN_API_KEY 或 config.yaml 中的 shodan_api_key
"""
import os
import yaml
import socket
import json
from pathlib import Path
from typing import Dict, Any, Optional
from skills.base import BaseSkill

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False


class ShodanAPISkill(BaseSkill):
    name = "shodan_api"
    description = "通过 Shodan API 查询目标 IP 的开放端口、服务、漏洞等信息。自动解析域名。需配置 API Key。"
    parameters = {
        "target": {"type": "string", "required": True, "description": "目标 IP 或域名"},
        "verbose": {"type": "boolean", "default": False, "description": "是否输出详细日志"}
    }

    def _get_api_key(self) -> Optional[str]:
        key = os.environ.get("SHODAN_API_KEY")
        if key:
            return key
        config_file = Path("config.yaml")
        if config_file.exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
            return config.get("shodan_api_key")
        return None

    def _resolve_domain(self, target: str) -> Optional[str]:
        try:
            ip = socket.gethostbyname(target)
            return ip
        except:
            return None

    def _safe_str(self, value: Any) -> str:
        """安全地将值转换为字符串，处理字节数据和非 UTF-8 编码"""
        if value is None:
            return ""
        if isinstance(value, bytes):
            # 尝试 UTF-8 解码，忽略无效字节
            return value.decode('utf-8', errors='ignore')
        if isinstance(value, (dict, list)):
            # 对于复杂类型，尝试 JSON 序列化后再解码
            try:
                json_str = json.dumps(value, ensure_ascii=False, default=str)
                return json_str
            except:
                return str(value)
        return str(value)

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        if not SHODAN_AVAILABLE:
            return {"status": "error", "message": "请安装 shodan 库: pip install shodan"}

        target = params.get("target")
        if not target:
            return {"status": "error", "message": "缺少参数 'target'"}
        verbose = params.get("verbose", False)

        api_key = self._get_api_key()
        if not api_key:
            return {"status": "error", "message": "未找到 Shodan API Key，请设置环境变量 SHODAN_API_KEY 或在 config.yaml 中配置 shodan_api_key"}

        # 解析域名
        ip = target
        if not self._is_ip(target):
            resolved = self._resolve_domain(target)
            if resolved:
                ip = resolved
            else:
                return {"status": "error", "message": f"无法解析域名: {target}"}

        try:
            api = shodan.Shodan(api_key)
            host_info = api.host(ip)
            # 安全提取数据，所有字段使用 _safe_str 处理
            data = {
                "ip": self._safe_str(host_info.get("ip_str", ip)),
                "org": self._safe_str(host_info.get("org", "")),
                "isp": self._safe_str(host_info.get("isp", "")),
                "country": self._safe_str(host_info.get("country_name", "")),
                "city": self._safe_str(host_info.get("city", "")),
                "ports": host_info.get("ports", []),  # 端口列表直接使用，json.dumps 可处理
                "vulns": host_info.get("vulns", []),
                "hostnames": host_info.get("hostnames", []),
                "os": self._safe_str(host_info.get("os", "")),
                "data": []
            }
            # 取前5个端口信息，安全处理每个字段
            for item in host_info.get("data", [])[:5]:
                port_info = {
                    "port": item.get("port"),
                    "service": self._safe_str(item.get("service", {}).get("name", "unknown")),
                    "banner": self._safe_str(item.get("banner", "")),
                    "http_title": self._safe_str(item.get("http", {}).get("title", ""))
                }
                data["data"].append(port_info)

            if verbose:
                print(f"[shodan_api] 查询 {ip} 成功，发现 {len(data['ports'])} 个端口")
            context.setdefault("shodan", data)
            return {"status": "success", "data": data}
        except shodan.APIError as e:
            return {"status": "error", "message": f"Shodan API 错误: {e}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _is_ip(self, target: str) -> bool:
        import re
        return re.match(r'^\d+\.\d+\.\d+\.\d+$', target) is not None
