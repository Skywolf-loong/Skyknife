"""
服务渗透知识库查询技能。

供 Planner / Worker 在**识别到服务指纹后**按图索骥地取用三类情报，避免重复思考也避免臆造口令：

    {"tool": "service_kb", "args": {"services": ["Redis", "Jenkins"], "action": "all"}}

支持三种用法：
  1. 传 services 列表（通常是资产 technologies / banner 识别结果）→ 精准取该服务的情报；
  2. 传 query 字符串          → 在名称与类目中做子串检索，用于"这里像是什么服务"的推测阶段；
  3. 传 port                  → 按端口反查可能是哪些服务。

action 取值（默认 all）：
  - all      返回全部字段
  - creds    仅返回默认凭据候选
  - paths    仅返回备份/敏感文件路径候选
  - approach 仅返回渗透思路

设计约束：**没有公开默认凭据的服务不产出任何口令**（`creds` 为空列表），
宁可少给候选，也不让 Agent 拿臆造口令去试错、触发账户锁定、污染结论。
"""
import sys
from pathlib import Path
from typing import Any, Dict, List

from skills.base import BaseSkill

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    # 知识库实际位置：knowledge/profiles/service_kb.py
    from knowledge.profiles import service_kb
except ImportError:  # 兼容旧路径 knowledge/service_kb.py，最后按文件路径兜底
    try:
        from knowledge import service_kb  # type: ignore
    except ImportError:
        import importlib.util
        service_kb = None
        for _p in (_ROOT / "knowledge" / "profiles" / "service_kb.py",
                   _ROOT / "knowledge" / "service_kb.py"):
            if not _p.exists():
                continue
            _spec = importlib.util.spec_from_file_location("service_kb", _p)
            if _spec and _spec.loader:
                _mod = importlib.util.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
                service_kb = _mod
                break
        if service_kb is None:
            raise ImportError(
                "未找到服务知识库：knowledge/profiles/service_kb.py（请检查 knowledge 目录）")


class ServiceKBSkill(BaseSkill):
    name = "service_kb"
    description = ("服务渗透知识库查询：按识别到的服务/指纹返回渗透思路、备份与敏感文件路径候选、"
                   "已知默认凭据。未知默认口令不臆造。参数：services(列表) 或 query(字符串) 或 port，"
                   "action=all|creds|paths|approach")

    parameters = {
        "services": {"type": "array", "required": False,
                     "description": "已识别的服务/指纹名列表，如 ['Redis','Jenkins','Spring Boot Actuator']"},
        "query": {"type": "string", "required": False,
                  "description": "名称或类目子串检索词，如 'Redis'、'CMS'、'数据库'"},
        "port": {"type": "string", "required": False,
                 "description": "按常见端口反查服务，如 '6379'"},
        "action": {"type": "string", "required": False, "default": "all",
                   "description": "all / creds / paths / approach"},
        "limit": {"type": "integer", "required": False, "default": 5,
                  "description": "query 检索返回的最大条目数"},
    }

    # ------------------------------------------------------------------
    @staticmethod
    def _iter_names(services: Any, query: str, port: Any) -> List[str]:
        """把 services / query / port 三种输入统一解析成一组服务名候选。"""
        names: List[str] = []

        from skills.base import coerce_list
        for item in coerce_list(services):
            if isinstance(item, str) and item.strip():
                names.append(item.strip())
            elif isinstance(item, dict):
                # 允许直接传资产 dict（含 name / product / banner / technologies）
                for key in ("name", "product", "service", "banner"):
                    v = item.get(key)
                    if isinstance(v, str) and v.strip():
                        names.append(v.strip())

        if query and not names:
            names = [e["name"] for e in service_kb.search(query, limit=20)]

        if port and not names:
            names = [e["name"] for e in service_kb.by_port(str(port))]

        # 去重且保持顺序
        out, seen = [], set()
        for n in names:
            if n.lower() not in seen:
                seen.add(n.lower())
                out.append(n)
        return out

    # ------------------------------------------------------------------
    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        if not isinstance(params, dict):
            return {"status": "error", "message": f"参数必须为对象，收到 {type(params).__name__}"}

        action = str(params.get("action") or "all").lower()
        if action not in ("all", "creds", "paths", "approach", "vulns"):
            action = "all"

        query = str(params.get("query") or "").strip()
        port = params.get("port")
        names = self._iter_names(params.get("services"), query, port)

        if not names:
            return {"status": "error",
                    "message": "未识别到服务：请传 services（列表）、query（检索词）或 port（端口）之一"}

        matched, unknown = [], []
        for n in names:
            e = service_kb.get(n)
            if e:
                matched.append(e)
            else:
                unknown.append(n)

        if not matched:
            return {"status": "success",
                    "data": {
                        "matched": [],
                        "unknown_services": unknown,
                        "creds": [], "backup_paths": [], "approaches": [],
                        "message": "知识库中暂无这些服务的条目（可后续补充，不要用猜测的口令代替）",
                    }}

        creds = service_kb.default_creds_for([e["name"] for e in matched])
        paths = service_kb.backup_paths_for([e["name"] for e in matched])

        if action == "creds":
            data = {"matched": [e["name"] for e in matched], "creds": creds}
        elif action == "paths":
            data = {"matched": [e["name"] for e in matched], "backup_paths": paths}
        elif action == "approach":
            data = {"matched": [e["name"] for e in matched],
                    "approaches": [{"service": e["name"], "category": e["category"],
                                    "ports": e["ports"], "approach": e["approach"]}
                                   for e in matched]}
        elif action == "vulns":
            data = {"matched": [e["name"] for e in matched],
                    "vulns": [{"service": e["name"], "items": e.get("vulns") or []}
                              for e in matched],
                    "sensitive_paths": service_kb.paths_from_entries(
                        [e.get("sensitive_paths") or [] for e in matched])}
        else:
            data = {
                "matched": [e["name"] for e in matched],
                "matched_services": [
                    {"name": e["name"], "category": e["category"], "ports": e["ports"],
                     "approach": e["approach"], "backup_paths": e["backup_paths"],
                     "default_creds": e["creds"],
                     "sensitive_paths": e.get("sensitive_paths") or [],
                     "vulns": e.get("vulns") or []} for e in matched],
                "unknown_services": unknown,
                "creds": creds,
                "backup_paths": paths,
            }

        # 关键安全提示：不要让 Agent 把「候选」当「已验证」
        data["note"] = ("以上默认凭据均为**候选**，必须实际验证；"
                        "没有记录默认凭据的服务表示无公开默认值，禁止臆造口令尝试。")
        data["no_default_credential_services"] = [e["name"] for e in matched if not e["creds"]]
        return {"status": "success", "data": data}
