"""
端口扫描 Skill
增强 DNS 解析：异步失败后自动回退到同步解析
增强批量处理：分批 gather 避免 Windows asyncio 高并发丢包
新增 CIDR/范围检测：明确拒绝并引导用户使用 nmap
"""
import asyncio
import socket
import argparse
import sys
import time
import random
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any, Optional

from skills.base import BaseSkill, PORTSCAN_DIR

# ==================== 常量 ====================
UDP_DEFAULT_PORTS = [53, 161, 500, 5060, 123, 137, 138, 67, 68, 111]

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 27017: "MongoDB",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP",
    137: "NetBIOS", 138: "NetBIOS", 161: "SNMP", 162: "SNMP",
    500: "ISAKMP", 514: "Syslog", 520: "RIP", 1434: "MSSQL",
    1900: "UPnP", 4500: "IPsec", 5060: "SIP",
    5357: "WSDAPI",
}

NMAP_TOP_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113,
    81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000,
    513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128,
    444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
    6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001,
    5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19,
    8031, 1041, 255, 2967, 1049, 1048, 1053, 3703, 1056, 1065, 1064, 1054,
    17, 808, 3689, 1031, 1044, 1071, 5901, 9102, 100, 8010, 2869, 1039,
    5120, 4001, 9000, 2105, 636, 1038, 2601, 7000, 1, 1066, 1069, 625, 311,
    280, 254, 4000, 5003, 1761, 2002, 2005, 1998, 1032, 1050, 6112, 1521,
    2161, 6002, 2401, 902, 4045, 787, 7937, 1058, 2383, 32771, 1033, 1040,
    3268, 4444, 999, 32770, 5985, 8002, 9001, 8082, 512, 1080, 2048, 888,
    1100, 2375, 1001, 2003, 464, 1047, 387, 3031, 8001, 1042, 9200, 1234,
    9300, 259, 2718, 5999, 10080, 8089, 8649, 30001, 11211, 563, 50000,
    5151, 2041, 5998, 9101, 163, 5672, 648, 146, 1666, 2006, 6666, 2065,
    31337, 2010, 7100, 8873, 801, 6689, 5801, 4022, 901, 6025, 1090, 300,
    9917, 4111, 6789, 7095, 7144, 20002, 20001, 1098, 520, 20000, 4321,
    1074, 384, 3847, 11720, 9010, 9020, 2222, 3333, 4445, 5555, 6667, 8003,
    8083, 8088, 8444, 9091, 10001, 10002, 11214, 11215, 27018, 28017, 49158,
    49159, 49160, 50030, 50060, 50070, 50075, 50090, 60010, 60030
]

WEB_PORTS = [80, 443, 8080, 8443]
for wp in WEB_PORTS:
    if wp not in NMAP_TOP_PORTS:
        NMAP_TOP_PORTS.insert(0, wp)

# [新增] 分批处理大小，避免 Windows ProactorEventLoop 高并发丢包
BATCH_SIZE = 500


class RateController:
    def __init__(self, max_concurrency: int, window_size: int = 100):
        self.max_concurrency = max_concurrency
        self.current_concurrency = max_concurrency
        self.window_size = window_size
        self.rtt_history = []
        self.timeout_history = []
        self.min_concurrency = 1

    def update(self, rtt: Optional[float], timed_out: bool = False):
        if timed_out:
            self.timeout_history.append(True)
            if len(self.timeout_history) > self.window_size:
                self.timeout_history.pop(0)
        elif rtt is not None:
            self.rtt_history.append(rtt)
            if len(self.rtt_history) > self.window_size:
                self.rtt_history.pop(0)

        if len(self.timeout_history) >= 50:
            timeout_rate = sum(self.timeout_history) / len(self.timeout_history)
            if timeout_rate > 0.05:
                self.current_concurrency = max(self.min_concurrency, int(self.current_concurrency * 0.5))
            elif timeout_rate < 0.01 and len(self.rtt_history) >= 50:
                avg_rtt = sum(self.rtt_history) / len(self.rtt_history)
                if avg_rtt < 1.0:
                    self.current_concurrency = min(self.max_concurrency, self.current_concurrency + 10)


class PortScanner:
    def __init__(self, target: str, ports: List[int], threads: int = 50,
                 timeout: float = 5.0, show_banner: bool = False,
                 udp_scan: bool = False, output_json: str = None,
                 output_xml: str = None, verbose: bool = False):
        self.target = target
        self.ports = ports
        self.max_concurrency = threads
        self.timeout = timeout
        self.show_banner = show_banner
        self.udp_scan = udp_scan
        self.output_json = output_json
        self.output_xml = output_xml
        self.verbose = verbose

        self.results = []
        self.rate_controller = RateController(threads)
        self.resolved_ip = None

    def resolve_sync(self) -> Optional[str]:
        try:
            resolved = socket.gethostbyname(self.target)
            if self.verbose:
                print(f"[+] 同步解析成功: {self.target} -> {resolved}")
            return resolved
        except Exception as e:
            print(f"[-] 同步解析失败: {e}")
            return None

    async def resolve_target(self) -> Optional[str]:
        try:
            socket.inet_aton(self.target)
            self.resolved_ip = self.target
            return self.target
        except socket.error:
            pass

        for attempt in range(3):
            try:
                loop = asyncio.get_event_loop()
                ip = await asyncio.wait_for(
                    loop.getaddrinfo(self.target, None, family=socket.AF_INET),
                    timeout=5.0
                )
                if ip:
                    resolved = ip[0][4][0]
                    if self.verbose:
                        print(f"[+] 异步解析: {self.target} -> {resolved}")
                    self.resolved_ip = resolved
                    return resolved
            except asyncio.TimeoutError:
                if self.verbose:
                    print(f"[-] DNS 解析超时 (尝试 {attempt+1}/3)")
            except Exception as e:
                if self.verbose:
                    print(f"[-] 解析尝试 {attempt+1} 失败: {e}")
                await asyncio.sleep(0.5)

        loop = asyncio.get_event_loop()
        try:
            resolved = await loop.run_in_executor(None, self.resolve_sync)
            if resolved:
                self.resolved_ip = resolved
                return resolved
        except Exception as e:
            print(f"[-] 同步解析异常: {e}")

        return None

    async def get_service_banner(self, ip: str, port: int) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            if port in [21, 22, 25, 110, 143, 587, 993, 995]:
                writer.write(b"\r\n")
                await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            decoded_banner = banner.decode('utf-8', errors='ignore').strip()
            return decoded_banner if decoded_banner else "No banner"
        except Exception:
            return "No banner"

    async def scan_tcp_port(self, port: int, semaphore: asyncio.Semaphore) -> Optional[Dict]:
        async with semaphore:
            await asyncio.sleep(random.uniform(0, 0.05))
            start_time = time.time()
            # 出网模式=代理池/Tor 时，TCP 连接也走代理 CONNECT 隧道（否则会暴露本机 IP）
            try:
                from agent6.egress_net import open_tcp_async, proxy_tunnel
                tunnel = proxy_tunnel()
            except Exception:
                tunnel = False
            if tunnel:
                writer = None
                try:
                    reader, writer = await open_tcp_async(
                        self.resolved_ip, port, self.timeout)
                    self.rate_controller.update(time.time() - start_time)
                    banner = ""
                    if self.show_banner:
                        try:
                            if port in [21, 22, 25, 110, 143, 587, 993, 995]:
                                writer.write(b"\r\n")
                                await writer.drain()
                            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                            banner = data.decode("utf-8", errors="ignore").strip()
                        except Exception:
                            banner = ""
                    return {"port": port,
                            "service": COMMON_SERVICES.get(port, "Unknown"),
                            "banner": banner, "timestamp": time.time(),
                            "protocol": "tcp"}
                except Exception:
                    self.rate_controller.update(None, timed_out=True)
                    return None
                finally:
                    try:
                        if writer:
                            writer.close()
                    except Exception:
                        pass
            sock = None
            try:
                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setblocking(False)
                try:
                    await asyncio.wait_for(
                        loop.sock_connect(sock, (self.resolved_ip, port)),
                        timeout=self.timeout
                    )
                    rtt = time.time() - start_time
                    self.rate_controller.update(rtt)
                    service = COMMON_SERVICES.get(port, "Unknown")
                    banner = ""
                    if self.show_banner:
                        banner = await self.get_service_banner(self.resolved_ip, port)
                    result = {
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "timestamp": time.time(),
                        "protocol": "tcp"
                    }
                    if self.verbose:
                        status = f"{port}/tcp 开放 - {service}"
                        if banner and self.show_banner:
                            status += f" | {banner[:60]}"
                        print(f"[+] {status}")
                    return result
                except asyncio.TimeoutError:
                    self.rate_controller.update(None, timed_out=True)
                    return None
                except Exception:
                    self.rate_controller.update(None, timed_out=True)
                    return None
            except Exception:
                return None
            finally:
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass

    async def scan_udp_port(self, port: int, semaphore: asyncio.Semaphore) -> Optional[Dict]:
        async with semaphore:
            await asyncio.sleep(random.uniform(0, 0.05))
            try:
                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(b"", (self.resolved_ip, port))
                try:
                    data, addr = sock.recvfrom(1024)
                    service = COMMON_SERVICES.get(port, "Unknown")
                    result = {
                        "port": port,
                        "service": service,
                        "banner": "UDP Response",
                        "timestamp": time.time(),
                        "protocol": "udp"
                    }
                    if self.verbose:
                        print(f"[+] {port}/udp 开放 - {service}")
                    return result
                except socket.timeout:
                    return None
                except socket.error as e:
                    if getattr(e, 'errno', None) == 10054:
                        return None
                    return None
            except Exception:
                return None
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

    async def run_scan(self) -> List[Dict]:
        """[改动] 分批 gather，避免大批量端口丢包"""
        if not self.resolved_ip:
            print("[-] 目标 IP 无效，扫描终止")
            return []
        print(f"[+] 开始扫描 {self.target} ({self.resolved_ip})")
        print(f"[+] 扫描端口: {len(self.ports)} 个")
        print(f"[+] 并发数: {self.max_concurrency}")
        print(f"[+] 超时: {self.timeout}s")
        print(f"[+] 协议: {'UDP' if self.udp_scan else 'TCP'}")
        print("-" * 60)
        start_time = time.time()
        random.shuffle(self.ports)
        semaphore = asyncio.Semaphore(self.rate_controller.current_concurrency)

        # [改动] 分批处理
        all_open_ports = []
        total = len(self.ports)
        for batch_start in range(0, total, BATCH_SIZE):
            batch_ports = self.ports[batch_start:batch_start + BATCH_SIZE]
            tasks = []
            for port in batch_ports:
                if self.udp_scan:
                    tasks.append(self.scan_udp_port(port, semaphore))
                else:
                    tasks.append(self.scan_tcp_port(port, semaphore))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if r is not None and not isinstance(r, Exception):
                    all_open_ports.append(r)
            if self.verbose and batch_start + BATCH_SIZE < total:
                print(f"[*] 已扫 {min(batch_start+BATCH_SIZE, total)}/{total} 端口，"
                      f"已发现 {len(all_open_ports)} 个开放")

        end_time = time.time()
        print("-" * 60)
        print(f"[+] 扫描完成! 耗时: {end_time - start_time:.2f} 秒")
        print(f"[+] 发现 {len(all_open_ports)} 个开放端口")
        self.results = all_open_ports
        return all_open_ports

    def save_results(self):
        if self.output_json:
            with open(self.output_json, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"[+] JSON 结果已保存到: {self.output_json}")
        if self.output_xml:
            self._generate_nmap_xml(self.output_xml)
            print(f"[+] XML 结果已保存到: {self.output_xml}")

    def _generate_nmap_xml(self, filename: str):
        root = ET.Element("nmaprun")
        root.set("scanner", "port_scanner")
        root.set("start", str(int(time.time())))
        root.set("version", "1.0")
        scaninfo = ET.SubElement(root, "scaninfo")
        scaninfo.set("type", "udp" if self.udp_scan else "tcp")
        scaninfo.set("protocol", "udp" if self.udp_scan else "tcp")
        host = ET.SubElement(root, "host")
        status = ET.SubElement(host, "status")
        status.set("state", "up")
        address = ET.SubElement(host, "address")
        address.set("addr", self.target)
        address.set("addrtype", "ipv4")
        ports_elem = ET.SubElement(host, "ports")
        for result in self.results:
            port_elem = ET.SubElement(ports_elem, "port")
            port_elem.set("protocol", "udp" if self.udp_scan else "tcp")
            port_elem.set("portid", str(result["port"]))
            state = ET.SubElement(port_elem, "state")
            state.set("state", "open")
            service = ET.SubElement(port_elem, "service")
            service.set("name", result["service"].lower())
            service.set("product", result["banner"])
        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)


def port_range(port_str: str) -> List[int]:
    ports = set()
    parts = port_str.split(',')
    for part in parts:
        if '-' in part:
            start, end = part.split('-')
            try:
                start_port = int(start.strip())
                end_port = int(end.strip())
                if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                    ports.update(range(start_port, end_port + 1))
                else:
                    raise ValueError("端口范围无效")
            except ValueError:
                raise argparse.ArgumentTypeError(f"无效的端口范围: {part}")
        else:
            try:
                port = int(part.strip())
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    raise ValueError("端口号超出范围")
            except ValueError:
                raise argparse.ArgumentTypeError(f"无效的端口号: {part}")
    return sorted(ports)


def get_top_ports(count: int) -> List[int]:
    if count >= len(NMAP_TOP_PORTS):
        return NMAP_TOP_PORTS[:]
    result = []
    for wp in WEB_PORTS:
        if wp not in result:
            result.append(wp)
    for p in NMAP_TOP_PORTS:
        if p not in result:
            result.append(p)
        if len(result) >= count:
            break
    return result


# ==================== Skill 封装 ====================
class PortScanSkill(BaseSkill):
    name = "port_scan"
    description = "TCP/UDP 端口扫描，支持异步高并发。端口参数可使用 'common' 表示常见端口（前100个）。注意：仅支持单个 IP/域名，不支持 CIDR 或 IP 范围（请用 nmap）。"
    parameters = {
        "target": {"type": "string", "required": True, "description": "目标 IP 或域名（不支持 CIDR/范围）"},
        "ports": {"type": "string", "default": "common", "description": "端口范围如 '1-1000' 或 'common'"},
        "threads": {"type": "integer", "default": 50, "description": "最大并发连接数"},
        "timeout": {"type": "number", "default": 5.0, "description": "连接超时（秒）"},
        "banner": {"type": "boolean", "default": False, "description": "是否获取服务 banner"},
        "udp": {"type": "boolean", "default": False, "description": "是否进行 UDP 扫描"},
        "top_ports": {"type": "integer", "default": 0, "description": "使用前 N 个常见端口（覆盖 ports 参数）"},
        "output_json": {"type": "string", "description": "保存结果为 JSON 文件路径"},
        "output_xml": {"type": "string", "description": "保存结果为 XML 文件路径"},
        "verbose": {"type": "boolean", "default": False, "description": "显示详细输出"}
    }

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        try:
            target = params.get("target")
            if not target:
                return {"status": "error", "message": "缺少必需参数 'target'"}

            # [改动] 拒绝 CIDR / IP 范围
            if re.search(r'/\d{1,2}\s*$', str(target)):
                return {
                    "status": "error",
                    "message": (
                        f"port_scan **不支持 CIDR 网段**（{target}）。\n"
                        "请改用 nmap：`nmap -T4 -Pn -sT --open -p<ports> <CIDR>`\n"
                        "**注意**：CIDR 扫描耗时较长，系统会自动延长超时。\n"
                        "建议先用 `nmap -sn <CIDR>` 做主机发现，再对存活主机扫端口。"
                    )
                }
            if re.search(r'\d+\.\d+\.\d+\.\d+\s*-\s*\d', str(target)):
                return {
                    "status": "error",
                    "message": (
                        f"port_scan **不支持 IP 范围**（{target}）。\n"
                        "请改用 nmap：`nmap -T4 -Pn -sT --open -p<ports> <start>-<end>`"
                    )
                }

            ports_str = params.get("ports", "common")
            threads = params.get("threads", 50)
            timeout = params.get("timeout", 5.0)
            banner = params.get("banner", False)
            udp = params.get("udp", False)
            top_ports = params.get("top_ports", 0)
            output_json = params.get("output_json")
            output_xml = params.get("output_xml")
            # 未显式指定输出路径时，默认落盘到统一输出目录（避免文件散落各处）
            if not output_json:
                output_json = str(PORTSCAN_DIR / f"portscan-{int(time.time())}.json")
            verbose = params.get("verbose", False)

            if ports_str == "common":
                ports = get_top_ports(100)
                if verbose:
                    print("[*] 使用常见端口列表（前100个，包含Web端口）")
            elif top_ports > 0:
                ports = get_top_ports(top_ports)
                if verbose:
                    print(f"[*] 使用前 {top_ports} 个常见端口")
            elif udp and ports_str == "1-1000":
                ports = UDP_DEFAULT_PORTS
                if verbose:
                    print("[*] 使用 UDP 默认端口列表")
            else:
                ports = port_range(ports_str)

            if not ports:
                return {"status": "error", "message": "端口列表为空"}

            scanner = PortScanner(
                target=target, ports=ports, threads=threads, timeout=timeout,
                show_banner=banner, udp_scan=udp,
                output_json=output_json, output_xml=output_xml, verbose=verbose
            )

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                resolved = loop.run_until_complete(scanner.resolve_target())
                if not resolved:
                    return {"status": "error", "message": f"无法解析目标: {target}"}
                open_ports = loop.run_until_complete(scanner.run_scan())
            except Exception as e:
                return {"status": "error", "message": f"扫描过程异常: {str(e)}"}
            finally:
                loop.close()

            if output_json or output_xml:
                scanner.save_results()

            context.setdefault("open_ports", []).extend([p["port"] for p in open_ports])

            return {
                "status": "success",
                "data": {
                    "target": target,
                    "open_ports": open_ports,
                    "count": len(open_ports)
                }
            }

        except Exception as e:
            return {"status": "error", "message": f"端口扫描失败: {str(e)}"}
