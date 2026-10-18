# -*- coding: utf-8 -*-
"""知识库管理后端 —— 汇总工作台现有两块知识资产，供界面浏览 / 检索。

数据来源（均为项目内已有内容，不新增外部依赖）：
  - claude_red  ：``skills/claude_red/_knowledge/*.md``（77 篇方法论）
                  索引取自 ``skills/claude_red/claude_red_index.py`` 的 ``_INDEX``
  - pat_kb      ：``skills/pat_kb/_knowledge/*.md``（66 个载荷分类）
                  索引取自 ``skills/pat_kb/_index.json``

安全：正文默认经各自 ``_sanitize`` 消毒（curl|sh / IEX( / rm -rf / 与提示注入行标记），
需原文时显式 sanitize=false。仅读本地文件，不执行、不联网。
"""
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CR_KNOW = _ROOT / "skills" / "claude_red" / "_knowledge"
_PAT_KNOW = _ROOT / "skills" / "pat_kb" / "_knowledge"

# ---------- 索引加载（导入期只读一次） ----------
try:
    from skills.claude_red.claude_red_index import _INDEX as _CR_INDEX  # type: ignore
except Exception:
    _CR_INDEX = []
try:
    from skills.pat_kb.pat_kb_index import _INDEX as _PAT_INDEX  # type: ignore
except Exception:
    _PAT_INDEX = []


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _sanitize(text: str, source: str) -> str:
    try:
        if source == "claude_red":
            from skills.claude_red._sanitize import sanitize_text  # type: ignore
        else:
            from skills.pat_kb._sanitize import sanitize_text  # type: ignore
        return sanitize_text(text)
    except Exception:
        return text


def _cr_docs():
    out = []
    for c in _CR_INDEX:
        name = c.get("name")
        if not name:
            continue
        out.append({
            "id": f"claude_red:{name}", "source": "claude_red",
            "name": name, "title": name, "category": c.get("category", ""),
            "description": c.get("description", "") or "",
            "sections": c.get("sections", []), "topics": c.get("topics", []),
            "tools": c.get("tools", []), "bytes": c.get("bytes", 0),
            "grade": c.get("grade", ""), "hits": c.get("hits", []),
        })
    return out


def _pat_docs():
    out = []
    for c in _PAT_INDEX:
        slug = c.get("slug")
        if not slug:
            continue
        out.append({
            "id": f"pat_kb:{slug}", "source": "pat_kb",
            "name": slug, "title": c.get("title", slug), "category": "载荷库",
            "description": "", "keywords": c.get("keywords", []),
            "sections": c.get("sections", []), "topics": [],
            "tools": [], "bytes": c.get("bytes", 0),
            "grade": "", "hits": [],
        })
    return out


def stats():
    return {"claude_red": len(_CR_INDEX), "pat_kb": len(_PAT_INDEX),
            "total": len(_CR_INDEX) + len(_PAT_INDEX)}


def list_docs(source=None, q=None, category=None):
    docs = _cr_docs() + _pat_docs()

    def _match(d):
        if source and d["source"] != source:
            return False
        if category and category not in (d.get("category") or ""):
            return False
        if q:
            hay = " ".join([
                d.get("name", ""), d.get("title", ""), d.get("category", ""),
                d.get("description", ""), " ".join(d.get("keywords", []) or []),
                " ".join(d.get("topics", []) or []),
            ]).lower()
            if q.lower() not in hay:
                return False
        return True

    filtered = [d for d in docs if _match(d)]
    cats = {}
    for d in docs:
        cats[d["source"]] = cats.get(d["source"], 0) + 1
    return {"docs": filtered, "total": len(filtered),
            "sources": [{"name": k, "count": v} for k, v in sorted(cats.items())]}


def get_doc(doc_id, sanitize=True, max_chars=20000):
    if not doc_id or ":" not in doc_id:
        return {"ok": False, "error": "缺少或不合法 doc_id（应形如 claude_red:offensive-sqli）"}
    source, _, name = doc_id.partition(":")
    if source == "claude_red":
        fpath = _CR_KNOW / f"{name}.md"
    elif source == "pat_kb":
        fpath = _PAT_KNOW / f"{name}.md"
    else:
        return {"ok": False, "error": f"未知知识来源: {source}"}
    if not fpath.exists():
        return {"ok": False, "error": f"知识文件不存在: {fpath.name}"}
    body = _read(fpath)
    out = _sanitize(body, source) if sanitize else body
    truncated = len(out) > max_chars
    return {"ok": True, "id": doc_id, "source": source, "name": name,
            "sanitized": bool(sanitize), "chars": len(out),
            "truncated": truncated, "content": out[:max_chars]}


def search(q, source=None, deep=False, limit=30):
    """检索知识库：先命中元数据（标题/关键词/描述），deep=True 时再扫正文片段。"""
    q = (q or "").strip()
    if not q:
        return {"ok": False, "error": "缺少检索关键字 q"}
    ql = q.lower()
    docs = _cr_docs() + _pat_docs()
    hits = []
    for d in docs:
        if source and d["source"] != source:
            continue
        meta = " ".join([d.get("name", ""), d.get("title", ""),
                         d.get("description", ""),
                         " ".join(d.get("keywords", []) or []),
                         " ".join(d.get("topics", []) or []),
                         d.get("category", "")]).lower()
        score = meta.count(ql)
        snippet = ""
        if score == 0 and deep:
            if d["source"] == "claude_red":
                body = _read(_CR_KNOW / f"{d['name']}.md")
            else:
                body = _read(_PAT_KNOW / f"{d['name']}.md")
            low = body.lower()
            idx = low.find(ql)
            if idx >= 0:
                score = 1
                start = max(0, idx - 60)
                snippet = body[start:idx + 120].replace("\n", " ")
        if score:
            hits.append({**d, "score": score, "snippet": snippet})
    hits.sort(key=lambda x: -x["score"])
    return {"ok": True, "q": q, "found": len(hits), "hits": hits[:limit]}
