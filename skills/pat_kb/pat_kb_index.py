# -*- coding: utf-8 -*-
"""pat_kb_index：PayloadsAllTheThings 知识库检索入口（kind="index"）。

不返回正文，只负责"按关键词找到合适的漏洞分类"，供 Planner/Worker 发现后
再调用 pat_kb 取正文。默认进入工具清单（include_knowledge=True 时使用），
不挤占可执行工具。
"""
import json
import re
from pathlib import Path
from typing import Any, Dict

try:
    from skills.base import BaseSkill
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from skills.base import BaseSkill

_BASE = Path(__file__).resolve().parent
_INDEX_FILE = _BASE / "_index.json"
try:
    _INDEX = json.loads(_INDEX_FILE.read_text(encoding="utf-8"))
except Exception:
    _INDEX = []

_CAT_BY_SLUG = {c["slug"]: c for c in _INDEX}

# 中文 / 常见别名 -> 分类 slug（提升中文检索命中率）
_ALIASES = {
    "反序列化": "insecure_deserialization",
    "序列化": "insecure_deserialization",
    "命令注入": "command_injection",
    "代码注入": "command_injection",
    "sql注入": "sql_injection",
    "sql": "sql_injection",
    "xss": "xss_injection",
    "跨站脚本": "xss_injection",
    "ssrf": "server_side_request_forgery",
    "服务端请求伪造": "server_side_request_forgery",
    "xxe": "xxe_injection",
    "外部实体": "xxe_injection",
    "文件上传": "upload_insecure_files",
    "上传漏洞": "upload_insecure_files",
    "越权": "insecure_direct_object_references",
    "逻辑漏洞": "business_logic_errors",
    "业务逻辑": "business_logic_errors",
    "模版注入": "server_side_template_injection",
    "模板注入": "server_side_template_injection",
    "ssti": "server_side_template_injection",
    "重定向": "open_redirect",
    "文件包含": "file_inclusion",
    "目录遍历": "directory_traversal",
    "路径遍历": "directory_traversal",
    "csrf": "cross_site_request_forgery",
    "跨站请求伪造": "cross_site_request_forgery",
    "cors": "cors_misconfiguration",
    "提示注入": "prompt_injection",
    "提示词注入": "prompt_injection",
    "提示攻击": "prompt_injection",
    "JWT": "json_web_token",
    "jwt": "json_web_token",
    "反序列化": "insecure_deserialization",
}


def _search(q: str):
    q = q.strip().lower()
    if not q:
        return []
    # 别名优先
    alias_hits = []
    for key, slug in _ALIASES.items():
        if key in q or q in key:
            c = _CAT_BY_SLUG.get(slug)
            if c:
                alias_hits.append(c)
    keys = [k for k in re.split(r"[\s,，;；]+", q) if len(k) > 1]
    scored = []
    for c in _INDEX:
        blob = " ".join([c["title"].lower(), c["slug"], " ".join(c.get("keywords", []))]).lower()
        sc = sum(blob.count(k) for k in keys)
        if sc:
            scored.append((sc, c))
    scored.sort(key=lambda x: -x[0])
    out = list(alias_hits)
    for _sc, c in scored:
        if c not in out:
            out.append(c)
    return out[:10]


class PatKbIndexSkill(BaseSkill):
    kind = "index"
    name = "pat_kb_index"
    description = ("PayloadsAllTheThings 漏洞载荷知识库检索入口。按漏洞名/关键词找到对应分类"
                   "（如 sql注入 / xss / ssrf / 反序列化 / 上传），返回分类名与可用章节，"
                   "随后调用 pat_kb 取正文。")
    category = "knowledge-base"
    source = "PayloadsAllTheThings-master (swisskyrepo)"
    audit = {"grade": "P2", "hits": []}
    parameters = {
        "query": {"type": "string", "description": "漏洞类型/关键词，如 'SQL注入' / 'ssrf' / 'xss' / '反序列化'"},
        "list": {"type": "boolean", "default": False, "description": "列出全部分类"},
    }

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        params = params if isinstance(params, dict) else {}
        q = str(params.get("query") or "").strip()
        if params.get("list"):
            return self.ok({"count": len(_INDEX),
                            "categories": [{"slug": c["slug"], "title": c["title"],
                                            "sections": len(c.get("sections", []))} for c in _INDEX]})
        if q:
            hits = _search(q)
            if not hits:
                return self.ok({"query": q, "found": False,
                                "available": [c["title"] for c in _INDEX][:40]})
            return self.ok({"query": q, "found": True, "count": len(hits),
                            "categories": [{"slug": c["slug"], "title": c["title"],
                                            "keywords": c.get("keywords", [])[:10],
                                            "sections": c.get("sections", [])[:8]} for c in hits],
                            "next": "调用 pat_kb(category=<slug 或 title>) 取正文"})
        # 默认返回概览
        return self.ok({"hint": "传 query=<漏洞关键词> 检索，或 list=true 列出全部 66 个分类",
                        "count": len(_INDEX),
                        "sample": [c["title"] for c in _INDEX[:20]]})
