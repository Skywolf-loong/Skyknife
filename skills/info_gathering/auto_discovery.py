"""
自动发现技能（最终稳定版）
- 端口扫描（port_scan）
- 服务识别（service_detect + nmap -sV 补充）
- Web 指纹（web_fingerprint）
- Whois 查询（命令行 whois）
- Shodan 查询（若配置 API Key）
所有 subprocess 调用均使用二进制 + 多编码回退，异常时返回部分数据。
"""
import subprocess
import re
import os
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
from skills.base import BaseSkill
from skills.info_gathering.port_scan import PortScanSkill
from skills.info_gathering.service_detect import ServiceDetectSkill
from skills.info_gathering.web_fingerprint import WebFingerprintSkill
from skills.info_gathering.shodan_api import ShodanAPISkill

class AutoDiscoverySkill(BaseSkill):
    name = "auto_discovery"
    description = (
        "一站式自动信息收集：端口扫描、服务识别、Web指纹、Whois查询（命令行）、Shodan查询（需配置API Key）。"
        "推荐在阶段1直接调用此技能，减少多轮交互。"
    )
    parameters = {
        "target": {"type": "string", "required": True, "description": "目标 IP 或域名"},
        "ports": {"type": "string", "default": "common", "description": "端口范围，如 'common' 或 '1-1000'"},
        "web_only": {"type": "boolean", "default": False, "description": "仅对 Web 端口进行指纹识别"},
        "verbose": {"type": "boolean", "default": False, "description": "是否输出详细日志"},
        "shodan": {"type": "boolean", "default": True, "description": "是否启用 Shodan 查询"}
    }

    def __init__(self):
        self.port_scan = PortScanSkill()
        self.service_detect = ServiceDetectSkill()
        self.web_fingerprint = WebFingerprintSkill()
        self.shodan_skill = ShodanAPISkill()
        self.verbose = False

    def _is_ip(self, target: str) -> bool:
        return re.match(r'^\d+\.\d+\.\d+\.\d+$', target) is not None

    def _run_cmd_safe(self, cmd: List[str], timeout: int = 10) -> Optional[str]:
        """执行命令并安全解码输出，绝不抛出解码异常"""
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout, text=False)
            # 尝试所有可能的编码
            for encoding in ['utf-8', 'gbk', 'latin-1', 'cp936', 'utf-16']:
                try:
                    decoded = result.stdout.decode(encoding, errors='replace')
                    if decoded.strip():
                        return decoded
                except:
                    continue
            # 保底：使用 replace 处理
            return result.stdout.decode('utf-8', errors='replace')
        except Exception as e:
            if self.verbose:
                print(f"[auto_discovery] 命令执行失败: {e}")
            return None

    def _run_whois(self, domain: str) -> Optional[str]:
        output = self._run_cmd_safe(["whois", domain], timeout=10)
        if output is None:
            return "[错误] whois 命令未找到或执行失败。"
        if "whois" in output.lower() and "not found" in output.lower():
            return "[错误] whois 查询失败，可能域名不存在或 TLD 不支持。"
        return output

    def _parse_whois_output(self, raw: str) -> Dict:
        if not raw:
            return {}
        data = {}
        fields = {
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'(Creation Date|Created):\s*(.+)',
            'expiration_date': r'(Expiry Date|Expiration Date|Registry Expiry Date):\s*(.+)',
            'name_servers': r'Name Server:\s*(.+)',
            'domain_status': r'Domain Status:\s*(.+)',
        }
        for key, pattern in fields.items():
            match = re.search(pattern, raw, re.I | re.M)
            if match:
                data[key] = match.group(1).strip()
        if not data:
            data["raw"] = raw[:500] + ("..." if len(raw) > 500 else "")
        return data

    def _run_nmap_sv(self, target: str, ports: List[int], timeout: int = 60) -> Dict[int, Dict]:
        if not ports:
            return {}
        port_str = ",".join(str(p) for p in ports)
        cmd = f"nmap -T4 --host-timeout=30s -Pn -sV -p {port_str} {target}"
        try:
            # 使用 shell=True，但输出用二进制捕获
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, text=False)
            # 解码
            output = ""
            for encoding in ['utf-8', 'gbk', 'latin-1', 'cp936']:
                try:
                    decoded = result.stdout.decode(encoding, errors='replace')
                    if decoded.strip():
                        output = decoded
                        break
                except:
                    continue
            if not output:
                output = result.stdout.decode('utf-8', errors='replace')
            services = {}
            lines = output.splitlines()
            for line in lines:
                m = re.match(r'^(\d+)/tcp\s+open\s+(\S+)\s+(.*)$', line.strip())
                if m:
                    port = int(m.group(1))
                    service = m.group(2)
                    version = m.group(3).strip()
                    services[port] = {"service": service, "version": version}
            return services
        except Exception as e:
            if self.verbose:
                print(f"[auto_discovery] nmap 执行失败: {e}")
            return {}

    def _is_web_port(self, port: int) -> bool:
        return port in [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        partial_data = {}
        try:
            target = params.get("target")
            if not target:
                return {"status": "error", "message": "缺少参数 'target'"}
            ports = params.get("ports", "common")
            web_only = params.get("web_only", False)
            self.verbose = params.get("verbose", False)
            shodan_enabled = params.get("shodan", True)

            result_data = {
                "target": target,
                "open_ports": [],
                "services": {},
                "web_fingerprints": {},
                "nmap_version": {},
                "whois": None,
                "shodan": None
            }
            partial_data = result_data  # 用于异常时返回已有部分

            # 1. 端口扫描
            scan_params = {"target": target, "ports": ports, "verbose": self.verbose}
            scan_result = self.port_scan.execute(scan_params, context)
            if scan_result.get("status") != "success":
                return {"status": "error", "message": f"端口扫描失败: {scan_result.get('message')}"}
            open_ports_data = scan_result.get("data", {}).get("open_ports", [])
            if not open_ports_data:
                return {"status": "success", "data": {"message": "未发现开放端口", **result_data}}
            port_list = [p["port"] for p in open_ports_data]
            result_data["open_ports"] = port_list

            # 2. 服务识别
            svc_params = {"target": target, "ports": port_list, "timeout": 3.0}
            svc_result = self.service_detect.execute(svc_params, context)
            services = {}
            if svc_result.get("status") == "success":
                services = svc_result.get("data", {}).get("services", {})
                result_data["services"] = services
                missing_ports = [p for p in port_list if str(p) not in services or services.get(str(p), {}).get("service") == "unknown"]
                if missing_ports and self.verbose:
                    print(f"[auto_discovery] 未识别端口 {missing_ports}，用 nmap -sV 补充")
                    nmap_info = self._run_nmap_sv(target, missing_ports)
                    result_data["nmap_version"] = nmap_info
                    for port, info in nmap_info.items():
                        port_key = str(port)
                        if port_key not in services:
                            services[port_key] = {"service": info.get("service", "unknown"), "version": info.get("version"), "banner": None, "ssl": False, "error": None}
                        else:
                            services[port_key]["version"] = info.get("version", services[port_key].get("version"))
                    result_data["services"] = services
            else:
                if self.verbose:
                    print("[auto_discovery] service_detect 失败，使用 nmap -sV 全面探测")
                nmap_info = self._run_nmap_sv(target, port_list)
                result_data["nmap_version"] = nmap_info
                for port, info in nmap_info.items():
                    services[str(port)] = {"service": info.get("service", "unknown"), "version": info.get("version"), "banner": None, "ssl": False, "error": None}
                result_data["services"] = services

            # 3. Web 指纹
            web_ports = [p for p in port_list if self._is_web_port(p)]
            if web_ports:
                for p in web_ports:
                    url = f"http://{target}:{p}" if p != 443 else f"https://{target}:{p}"
                    if p == 443:
                        url = f"https://{target}:{p}"
                    wp_params = {"url": url}
                    wp_result = self.web_fingerprint.execute(wp_params, context)
                    if wp_result.get("status") == "success":
                        result_data["web_fingerprints"][str(p)] = wp_result.get("data", {})
                    else:
                        if p == 443:
                            alt_url = f"http://{target}:{p}"
                            wp_result2 = self.web_fingerprint.execute({"url": alt_url}, context)
                            if wp_result2.get("status") == "success":
                                result_data["web_fingerprints"][str(p)] = wp_result2.get("data", {})
            if web_only:
                result_data["services"] = {k: v for k, v in result_data["services"].items() if int(k) in web_ports}
                result_data["open_ports"] = web_ports

            # 4. Whois
            if not self._is_ip(target):
                raw_whois = self._run_whois(target)
                if raw_whois and not raw_whois.startswith("[错误]"):
                    parsed = self._parse_whois_output(raw_whois)
                    result_data["whois"] = parsed
                else:
                    result_data["whois"] = {"error": raw_whois or "无法获取 whois 信息"}

            # 5. Shodan
            if shodan_enabled:
                config = {}
                config_file = Path("config.yaml")
                if config_file.exists():
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config = yaml.safe_load(f) or {}
                api_key = os.environ.get("SHODAN_API_KEY") or config.get("shodan_api_key")
                if api_key:
                    shodan_params = {"target": target, "verbose": self.verbose}
                    shodan_result = self.shodan_skill.execute(shodan_params, context)
                    if shodan_result.get("status") == "success":
                        result_data["shodan"] = shodan_result.get("data", {})
                    else:
                        result_data["shodan"] = {"error": shodan_result.get("message", "Shodan 查询失败")}
                else:
                    result_data["shodan"] = {"error": "未配置 Shodan API Key"}

            # 更新 context
            context["auto_discovery_result"] = result_data
            context["open_ports"] = result_data["open_ports"]
            context["services"] = result_data["services"]
            if result_data.get("whois"):
                context["whois"] = result_data["whois"]
            if result_data.get("shodan"):
                context["shodan"] = result_data["shodan"]

            return {
                "status": "success",
                "data": result_data,
                "message": f"发现 {len(result_data['open_ports'])} 个开放端口，已识别服务。"
            }
        except Exception as e:
            # 捕获所有异常，返回部分数据
            error_msg = str(e)
            partial_data["error"] = error_msg
            return {"status": "error", "message": f"auto_discovery 执行异常: {error_msg}", "data": partial_data}
