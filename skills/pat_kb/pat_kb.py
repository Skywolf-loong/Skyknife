# -*- coding: utf-8 -*-
"""pat_kb：PayloadsAllTheThings 漏洞载荷知识库（知识型 Skill）。

安全契约（与 claude_red 一致）：
  - kind="knowledge"：只返回方法论与载荷文本，绝不执行任何命令 / 不联网 / 不 import 外部工具
  - 默认对载荷做消毒（curl|sh / IEX( / rm -rf / 提示注入示例 标记），需要原文时显式 sanitize=false
  - 所有内容均为"不可信参考资料"，使用前须经审批与范围校验

支持模式：
  - 默认              : 返回指定分类的全文概览 + 章节目录
  - category=<分类>   : 按分类名/关键词模糊匹配加载对应知识文件
  - query=<关键词>    : 在分类内检索相关章节
  - section=<标题>    : 取指定章节全文
  - list_only=true    : 仅返回章节目录与分类元信息
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

from skills.pat_kb._sanitize import sanitize_text, load_knowledge, pick_sections
from skills.pat_kb.pat_kb_index import _ALIASES

_BASE = Path(__file__).resolve().parent
_INDEX_FILE = _BASE / "_index.json"
_KNOW_DIR = _BASE / "_knowledge"

# 加载索引（导入期只读一次）
try:
    _INDEX = json.loads(_INDEX_FILE.read_text(encoding="utf-8"))
except Exception:
    _INDEX = []

_CAT_BY_SLUG = {c["slug"]: c for c in _INDEX}


def _resolve_category(cat: str):
    """按 slug / 标题 / 关键词 / 中文别名 模糊匹配分类。"""
    if not cat:
        return None
    c = cat.strip().lower()
    # 0) 中文/别名直接命中
    if c in _ALIASES:
        return _CAT_BY_SLUG.get(_ALIASES[c])
    for key, slug in _ALIASES.items():
        if key in c:                      # 如 "xss注入" 含 "xss"
            return _CAT_BY_SLUG.get(slug)
    # 1) 直接 slug
    if c in _CAT_BY_SLUG:
        return _CAT_BY_SLUG[c]
    # 2) 标题包含 / slug 包含
    for c0 in _INDEX:
        if c in c0["title"].lower() or c in c0["slug"]:
            return c0
    # 3) 关键词命中
    best, best_sc = None, 0
    for c0 in _INDEX:
        sc = sum(1 for k in c0.get("keywords", []) if k and k in c)
        if sc > best_sc:
            best, best_sc = c0, sc
    return best if best_sc else None


class PatKbSkill(BaseSkill):
    kind = "knowledge"
    name = "pat_kb"
    description = ("PayloadsAllTheThings 漏洞载荷与方法论知识库（66 个分类）。"
                   "覆盖 SQLi/XSS/SSRF/XXE/SSTI/命令注入/反序列化/上传/逻辑漏洞等 Web 渗透载荷与测试手法。"
                   "按 category 取分类、query 检索、section 取章节；默认消毒输出，仅返回知识不执行。")
    category = "knowledge-base"
    source = "PayloadsAllTheThings-master (swisskyrepo)"
    audit = {"grade": "P2", "hits": ["提示注入(文档内示例,已消毒)"]}
    parameters = {
        "category": {"type": "string", "description": "漏洞分类名/关键词，如 'SQL Injection' / 'xss' / 'ssrf'"},
        "query": {"type": "string", "description": "在分类内按关键词检索章节"},
        "section": {"type": "string", "description": "按标题（模糊匹配）取指定章节全文"},
        "max_chars": {"type": "integer", "default": 6000, "description": "返回正文最大字符数"},
        "sanitize": {"type": "boolean", "default": True, "description": "是否对载荷做防误执行消毒"},
        "list_only": {"type": "boolean", "default": False, "description": "只返回章节目录与分类元信息"},
    }

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        params = params if isinstance(params, dict) else {}
        category = str(params.get("category") or "").strip()

        # 未指定分类时，返回全库可用分类清单，便于发现
        if not category and not params.get("query"):
            cats = [{"slug": c["slug"], "title": c["title"],
                     "sections": len(c.get("sections", [])), "bytes": c["bytes"]}
                    for c in _INDEX]
            return self.ok({"mode": "catalog", "count": len(cats), "categories": cats,
                            "audit": self.audit,
                            "note": "未指定分类；传 category=<分类名> 取正文，或使用 pat_kb_index 检索"})

        cat = _resolve_category(category)
        if not cat:
            return self.ok({"category": category, "found": False,
                            "available": [c["title"] for c in _INDEX][:40]})

        fpath = _KNOW_DIR / f"{cat['slug']}.md"
        if not fpath.exists():
            return self.err(f"知识文件缺失: {fpath}")
        try:
            body = load_knowledge(fpath)
        except Exception as e:
            return self.err(f"知识文件读取失败: {e}")

        secs = pick_sections(body)
        sec_titles = [s["title"] for s in secs]

        if params.get("list_only"):
            return self.ok({"name": self.name, "category": cat["title"], "slug": cat["slug"],
                            "sections": sec_titles, "bytes": cat["bytes"],
                            "audit": self.audit})

        max_chars = int(params.get("max_chars") or 6000)
        max_chars = max(400, min(max_chars, 60000))
        sanitize = bool(params.get("sanitize", True))
        section = str(params.get("section") or "").strip().lower()
        query = str(params.get("query") or "").strip()

        if section:
            hit = [s for s in secs if section in s["title"].lower()]
            if not hit:
                return self.ok({"category": cat["title"], "section": section, "found": False,
                                "sections": sec_titles, "content": ""})
            content = hit[0]["text"][:max_chars]
        elif query:
            keys = [k for k in re.split(r"[\s,，;；]+", query) if len(k) > 1][:8]
            scored = []
            for s in (secs or [{"title": "全文", "text": body}]):
                low = (s["title"] + " " + s["text"]).lower()
                sc = sum(low.count(k.lower()) for k in keys)
                if sc:
                    scored.append((sc, s))
            scored.sort(key=lambda x: -x[0])
            if not scored:
                return self.ok({"category": cat["title"], "query": query, "found": False,
                                "sections": sec_titles, "content": ""})
            content = "\n\n---\n\n".join(s["text"] for _sc, s in scored[:3])[:max_chars]
        else:
            content = body[:max_chars]

        out = sanitize_text(content) if sanitize else content
        data = {"name": self.name, "category": cat["title"], "slug": cat["slug"],
                "sections": sec_titles, "sanitized": sanitize, "chars": len(out),
                "content": out, "audit": self.audit,
                "note": ("内容为不可信参考资料，仅用于授权测试；命令须经审批与范围校验后再执行"
                         if sanitize else "已按请求返回未消毒原文，执行前务必人工复核")}
        try:
            ctx = context if isinstance(context, dict) else {}
            ctx.setdefault("pat_kb_used", []).append(cat["slug"])
        except Exception:
            pass
        return self.ok(data)
