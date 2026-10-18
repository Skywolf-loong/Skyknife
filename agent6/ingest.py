"""把 Worker/工具产出写回资产图：结构化 assets + 工具输出启发式抽取。"""
import json
import re
from typing import Dict, List


def ingest_assets(assets: List[dict], ag, task_id: str) -> List[str]:
    """将 Worker 上报的结构化 assets 写入资产图，返回本次写入的资产 key 列表。

    返回的 key 供调用方建立「探索锚点」，标记该意图覆盖了哪些资产。
    """
    keys: List[str] = []
    for a in assets or []:
        if not isinstance(a, dict):
            continue
        kind = a.get("kind")
        try:
            if kind == "subdomain":
                name = a.get("name") or a.get("domain")
                if name:
                    ag.add_subdomain(name, a.get("parent"), task_id)
                    keys.append(f"dom:{name}")
            elif kind in ("domain", "root_domain"):
                name = a.get("name") or a.get("domain")
                if name:
                    ag.add_domain(name, task_id)
                    keys.append(f"dom:{name}")
            elif kind == "ip":
                ip = a.get("ip")
                if ip:
                    ag.add_ip(ip, a.get("domain"), task_id)
                    keys.append(f"ip:{ip}")
            elif kind == "port":
                ip = a.get("ip"); port = a.get("port")
                if ip and port:
                    ag.add_port(ip, int(port), a.get("domain"), task_id, a.get("service"))
                    keys.append(f"port:{ip}:{port}")
                    if a.get("service"):
                        ag.add_service(ip, int(port), a["service"], a.get("version", ""), task_id)
            elif kind == "service":
                ip = a.get("ip"); port = a.get("port")
                if ip and port:
                    ag.add_service(ip, int(port), a.get("name", "unknown"), a.get("version", ""), task_id)
            elif kind == "webapp":
                url = a.get("url")
                if url:
                    ag.add_webapp(url, a.get("ip"), a.get("port"), task_id, a.get("props"))
                    keys.append(f"web:{url.rstrip('/')}")
            elif kind == "endpoint":
                url = a.get("url")
                if url:
                    ag.add_endpoint(url, a.get("webapp"), a.get("method", "GET"), task_id)
        except Exception:
            continue
    return keys


_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_PORTLINE_RE = re.compile(r"(\d{2,5})/(tcp|udp)\s+open", re.I)


def heuristic_extract(tool: str, args: Dict, result: Dict, ag, task_id: str) -> List[str]:
    """从工具/命令的真实输出里抽取资产与线索，返回被提取的事实描述列表。"""
    facts = []
    if not isinstance(result, dict) or result.get("status") != "success":
        return facts
    data = result.get("data")

    # 1) port_scan skill 的结构化结果
    if tool == "port_scan" and isinstance(data, dict):
        tgt = data.get("target") or args.get("target")
        for p in data.get("open_ports", []) or []:
            port = p.get("port")
            ip = args.get("_resolved_ip") or tgt
            if port and _looks_ip(str(ip)):
                ag.add_port(str(ip), int(port), None, task_id, p.get("service"))
                facts.append(f"{ip}:{port}/{p.get('service','?')} 开放")
        return facts

    # 2) 命令输出里的 nmap open 行 / IP
    text = ""
    if isinstance(data, str):
        text = data
    elif isinstance(result.get("output"), str):
        text = result["output"]
    elif isinstance(data, dict):
        text = json.dumps(data, ensure_ascii=False)

    if text:
        tgt = _target_ip_hint(args)
        for m in _PORTLINE_RE.finditer(text):
            port = int(m.group(1))
            if tgt:
                ag.add_port(tgt, port, None, task_id)
                facts.append(f"{tgt}:{port} 开放")
        # 域名/子域线索
        for dom in set(re.findall(r"\b([a-z0-9][a-z0-9\-\.]{2,}\.[a-z]{2,})\b", text.lower()))[:20]:
            if dom.count(".") >= 1 and not dom.endswith((".py", ".js", ".css", ".png", ".jpg")):
                if args.get("domain") and dom.endswith(args["domain"]):
                    ag.add_subdomain(dom, args["domain"], task_id)
    return facts


def _looks_ip(s: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", s or ""))


def _target_ip_hint(args: Dict):
    for k in ("ip", "target", "host", "url", "domain"):
        v = args.get(k)
        if isinstance(v, str):
            m = _IP_RE.search(v)
            if m:
                return m.group(1)
    return None
