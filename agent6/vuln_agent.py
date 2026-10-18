"""
VulnAgent —— 漏洞优化智能体（「发现」页的一键优化 / 复测 / AI 复测）。

三大能力：
1. **一键优化**：对选中漏洞
   a. 去重（同资产同漏洞只留一条，重复项打 audit_status=duplicate）
   b. 为缺 POC 的漏洞编写 POC（LLM 生成，LLM 不可用时规则降级）
   c. 执行 POC 验证并记录回显（请求/响应原文）
   d. 验证失败 → AI 分析判定是否误报（误报打 audit_status=fake）
   e. POC 与回显写回漏洞详情（nodes.data），全过程落 poc_records
2. **复测**：用已保存的 POC 重跑，回显与基线不同即判定「已修复」。
3. **AI 复测**：LLM 重新分析漏洞并生成/修正 POC，结合回显差异判定是否修复。

设计约定：
- 零新增第三方依赖：HTTP / 命令执行复用 ToolRegistry，LLM 复用 LLMClient。
- LLM 不可用（未配置 Key / 离线 / 调用失败）时全部降级为规则实现，流程不中断。
- 默认只自动执行 http 类 POC；Shell 类 POC 需显式开启 allow_command（默认关闭）。
- 全过程留痕：poc_records 表 + nodes.data 双写，详情弹窗可回放历史。
"""
import difflib
import json
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .store.db import get_db, jdump, jload, now

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_URL_RE = re.compile(r"https?://[^\s'\"<>)\]}]+", re.I)
_SEV_RANK = {"危急": 0, "高": 1, "中": 2, "低": 3, "信息": 4, "未评级": 9}
_SEV_ALL = ("危急", "高", "中", "低", "信息")
_ECHO_LIMIT = 8000

# 一段文本里的敏感"实锤"特征：出现即说明证据链扎实（可升级）
_STRONG_EVIDENCE = (
    "db_password", "auth_key", "secure_auth_key", "logged_in_key", "nonce_salt",
    "define(", "root:x:0:0", "uid=", "select ", "mysql_", "ora-", "sqlstate",
    "access_token", "secret_key", "private_key",
)

# 回显里与漏洞判定无关、且每次请求都会变化的噪声（时间 / Cookie / 会话串）
_VOLATILE = (
    re.compile(r"^(Date|Set-Cookie|Expires|Last-Modified|ETag|X-Runtime|"
               r"X-Request-Id|X-Trace-Id|X-Cache|X-Varnish|Age|Timing-Allow-Origin)"
               r"\s*:\s*.*$", re.I | re.M),
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?\w*\b"),
    re.compile(r"\b[0-9]{10,13}\b"),                       # 秒/毫秒级时间戳
)


def _norm_title(label: str) -> str:
    """归一化标题：去空白/标点/版本号差异，保留中英文主体（与 Auditor 保持一致）。"""
    s = (label or "").lower()
    s = re.sub(r"cve-\d{4}-\d{4,7}", "", s)
    s = re.sub(r"[\s\d.（）()\[\]【】：:，,。·\-_/\\|'\"`～~*#?！!]+", "", s)
    return s


def _host_of(ref: str) -> str:
    """把资产引用 / URL 归一化成「主机[:端口]」，作为审查分组的第一层键。"""
    s = str(ref or "").strip().lower()
    if not s:
        return ""
    m = _URL_RE.search(s)
    if m:
        s = m.group(0)
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("/")[0].split("?")[0].strip()
    if not s:
        return ""
    host, _, port = s.partition(":")
    host = re.sub(r"^(root_domain|subdomain|domain|dom|host|webapp|ip):", "", host)
    return host + (":" + port if port.isdigit() else "")


_SEV_ALIAS = {
    "critical": "危急", "crit": "危急", "severe": "危急", "严重": "危急",
    "紧急": "危急", "urgent": "危急",
    "high": "高", "major": "高", "重大": "高",
    "medium": "中", "moderate": "中", "普通": "中",
    "low": "低", "minor": "低",
    "info": "信息", "informational": "信息", "none": "信息", "提示": "信息",
}


def _norm_sev(sev: Any) -> str:
    """把各种写法归一化到 危急/高/中/低/信息/未评级。

    只接受精确写法与「高危 / 中级」这类带等级后缀的写法；
    「超级高」等含等级字的任意串一律视为非法（返回"未评级"），
    避免把非等级文本误判成等级。
    """
    s = str(sev or "").strip()
    if not s:
        return "未评级"
    if s in _SEV_ALL or s == "未评级":
        return s
    low = s.lower()
    if low in _SEV_ALIAS:
        return _SEV_ALIAS[low]
    core = s
    for suf in ("危", "级", "险"):
        if len(core) > 1 and core.endswith(suf):
            core = core[:-1]
            break
    if core in _SEV_ALL:
        return core
    for k, v in _SEV_ALIAS.items():
        if len(k) >= 4 and k in low:          # 仅较长的英文别名允许包含匹配
            return v
    return "未评级"


def _rule_severity(title: str, evidence: str, vtype: str = "") -> Tuple[str, str, bool]:
    """规则版严重性定级（LLM 不可用时的兜底）。

    返回 (等级, 理由, 是否可置信)。只有可置信的判定才允许覆盖原有等级，
    避免规则认不出类型时把高危误降级。

    升级：RCE / 命令执行 / 上传 / 拿到明文凭据或密钥；
    降级：仅泄露备份文件路径或版本、响应中无实际内容（典型如备份文件路径但拿不到文件）。
    """
    t = f"{title or ''} {vtype or ''}".lower()
    ev = str(evidence or "").lower()

    if any(k in t for k in ("命令执行", "代码执行", "rce", "反序列化",
                            "任意文件上传", "文件上传", "getshell", "远程执行")):
        return "危急", "规则：可直接代码执行 / 上传利用", True
    if any(k in ev for k in ("uid=", "root:x:0:0", "www-data")) and "命令" in t:
        return "危急", "规则：命令执行已回显", True

    strong = any(k in ev for k in _STRONG_EVIDENCE)
    backup_like = any(k in t for k in ("备份", "backup", "wp-config", "配置文件",
                                       "config", "源码", "svn", "git"))
    if strong:
        return "高", "规则：证据中出现明文凭据 / 密钥 / 数据库指纹", True
    # 是否真的拿到了文件内容（而非只探测到路径 / 状态码）
    content_like = ("<?php" in ev or "define(" in ev
                    or ("config" in ev and len(ev) > 120) or len(ev) > 400)
    if backup_like and content_like:
        return "高", "规则：备份 / 配置文件可访问且响应含实质内容", True
    if backup_like:
        return "低", "规则：仅命中备份文件路径 / 状态码，未取得实际文件内容，降级", True

    if any(k in t for k in ("sql", "注入", "sqli", "文件读取", "任意文件", "目录遍历",
                            "lfi", "path traversal", "xxe", "ssrf", "越权")):
        return "高", "规则：可读取数据 / 越过权限边界", True
    if any(k in t for k in ("xss", "跨站", "csrf", "重定向", "open redirect",
                            "弱口令", "未授权", "逻辑", "敏感信息")):
        return "中", "规则：中等风险，需交互或影响有限", True
    if any(k in t for k in ("版本", "banner", "指纹", "robots", "目录列表",
                            "目录浏览", "信息泄露", "路径")):
        return "低", "规则：信息类，风险有限", True
    if not ev:
        return "信息", "规则：缺少可验证证据，先记为信息级", True
    # 认不出类型：不可置信，调用方应保留原有等级
    return "中", "规则：按通用风险定级（类型未识别，不覆盖原等级）", False


def _title_similar(a: str, b: str) -> float:
    """两条标题的相似度（归一化后的字面相似度）。"""
    na, nb = _norm_title(a), _norm_title(b)
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    return difflib.SequenceMatcher(None, na, nb).ratio()


def _same_vuln_family(a: str, b: str) -> bool:
    """弱语义同族判定：共享足够多的关键片段即认为同族（规则兜底用）。"""
    ka, kb = _norm_title(a), _norm_title(b)
    if not ka or not kb:
        return False
    grams = {ka[i:i + 2] for i in range(len(ka) - 1)}
    gb = {kb[i:i + 2] for i in range(len(kb) - 1)}
    if not grams or not gb:
        return False
    inter = len(grams & gb)
    return inter / max(1, min(len(grams), len(gb))) >= 0.55


def _extract_json(text: str) -> Optional[Any]:
    """从 LLM 输出里稳健地取出 JSON（容忍 ```json 代码块与前后废话）。"""
    if not text:
        return None
    s = str(text).strip()
    m = re.search(r"```(?:json)?\s*(.+?)```", s, re.S)
    if m:
        s = m.group(1).strip()
    try:
        return json.loads(s)
    except Exception:
        pass
    i, j = s.find("{"), s.rfind("}")
    if i >= 0 and j > i:
        try:
            return json.loads(s[i:j + 1])
        except Exception:
            pass
    return None


def _echo_fingerprint(echo: str) -> str:
    """回显指纹：剥掉时间戳 / Cookie 等易变噪声，用于前后两次回显是否一致的比对。"""
    s = str(echo or "")
    # HTTP 响应只比 body（状态行与头部的 Date/Set-Cookie 每次都变）
    if "\n\n" in s and re.match(r"^\s*HTTP/", s):
        s = s.split("\n\n", 1)[1]
    for rgx in _VOLATILE:
        s = rgx.sub("", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s[:4000]


def _same_echo(a: str, b: str, threshold: float = 0.92) -> bool:
    """两次回显是否实质相同：指纹完全相等，或相似度高于阈值。"""
    fa, fb = _echo_fingerprint(a), _echo_fingerprint(b)
    if not fa and not fb:
        return True
    if not fa or not fb:
        return False
    if fa == fb:
        return True
    return difflib.SequenceMatcher(None, fa, fb).ratio() >= threshold


def _echo_diff(a: str, b: str) -> str:
    """给出两次回显的关键差异摘要（各取前若干行做 diff）。"""
    def lines(s):
        return [x.strip() for x in str(s or "").splitlines()][:60]
    la, lb = lines(a), lines(b)
    out = [x for x in difflib.unified_diff(la, lb, "上次", "本次", lineterm="", n=0)]
    return "\n".join(out[:40]) or "（无显著差异）"


class VulnAgent:
    """漏洞优化智能体。所有方法都不抛异常，失败以结构化结果返回。"""

    def __init__(self, db=None, llm=None, tools=None,
                 progress: Callable[[str, str], None] = None):
        self.db = db or get_db()
        self.llm = llm
        self.tools = tools
        self.progress = progress or (lambda stage, msg: None)

    # ------------------------------------------------------------------
    # 基础：进度 / 读写 / 留痕
    # ------------------------------------------------------------------
    def _log(self, stage: str, msg: str):
        try:
            self.progress(stage, msg)
        except Exception:
            pass

    def get_finding(self, node_id: str) -> Optional[dict]:
        row = self.db.query_one(
            "SELECT id, task_id, label, data, status, asset_ref, created_at, updated_at"
            " FROM nodes WHERE id=?", (node_id,))
        if not row:
            return None
        row["data"] = jload(row["data"], {}) or {}
        return row

    def _patch_data(self, node_id: str, patch: Dict) -> Dict:
        """把结论合并写回漏洞节点的 data，并返回合并后的 data。"""
        row = self.db.query_one("SELECT data FROM nodes WHERE id=?", (node_id,))
        if not row:
            return {}
        d = jload(row["data"], {}) or {}
        d.update(patch or {})
        self.db.execute("UPDATE nodes SET data=?, updated_at=? WHERE id=?",
                        (jdump(d), now(), node_id))
        return d

    def _record(self, finding_id: str, task_id: str, kind: str, poc=None,
                echo: str = "", ok: int = 0, verdict: str = "",
                analysis: Any = None) -> int:
        self.db.execute(
            "INSERT INTO poc_records(finding_id,task_id,kind,poc,echo,ok,verdict,"
            "analysis,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (finding_id, task_id, kind,
             jdump(poc) if poc is not None else "",
             (echo or "")[:_ECHO_LIMIT], int(bool(ok)), verdict or "",
             jdump(analysis) if analysis is not None else "", now()))
        cur = self.db.query_one("SELECT last_insert_rowid() AS id")
        return (cur or {}).get("id", 0)

    def records(self, finding_id: str, limit: int = 50) -> List[dict]:
        rows = self.db.query(
            "SELECT id, kind, poc, echo, ok, verdict, analysis, created_at"
            " FROM poc_records WHERE finding_id=? ORDER BY created_at DESC LIMIT ?",
            (finding_id, limit))
        for r in rows:
            r["poc"] = jload(r["poc"], None)
            r["analysis"] = jload(r["analysis"], None)
        return rows

    # ------------------------------------------------------------------
    # 人工备注（测试人员在详情页补充，AI 生成 POC / 判误报 / 复测时优先参考）
    # ------------------------------------------------------------------
    def set_note(self, node_id: str, note: str) -> Dict[str, Any]:
        """写入 / 清空人工备注（清空传空字符串）。"""
        f = self.get_finding(node_id)
        if not f:
            return {"ok": False, "error": f"漏洞不存在: {node_id}"}
        text = str(note or "")
        patch = {"human_note": text}
        if text.strip():
            patch["human_note_at"] = now()
        self._patch_data(node_id, patch)
        return {"ok": True, "id": node_id, "human_note": text,
                "human_note_at": patch.get("human_note_at")}

    # ------------------------------------------------------------------
    # 人工修改严重等级（人工结论优先，AI 重评估不得覆盖）
    # ------------------------------------------------------------------
    def set_severity(self, node_id: str, severity: str, reason: str = "",
                     lock: bool = True) -> Dict[str, Any]:
        """人工设定该漏洞的严重等级。

        写入 severity / severity_source='human' / severity_reason，并追加 severity_history；
        lock=True 时置 severity_locked，后续「一键优化」重评估会跳过该条（尊重人工结论）。
        """
        sev = _norm_sev(severity)
        if sev == "未评级":
            return {"ok": False, "error": f"非法等级: {severity}（可选 危急/高/中/低/信息）"}
        f = self.get_finding(node_id)
        if not f:
            return {"ok": False, "error": f"漏洞不存在: {node_id}"}
        d = f.get("data") or {}
        prev = _norm_sev(d.get("severity"))
        hist = list(d.get("severity_history") or [])
        hist.append({"at": now(), "from": prev, "to": sev,
                     "by": "human", "reason": str(reason or "")[:500]})
        patch = {
            "severity": sev,
            "severity_source": "human",
            "severity_reason": str(reason or "")[:500],
            "severity_prev": prev,
            "severity_at": now(),
            "severity_history": hist[-30:],
            "severity_locked": bool(lock),
        }
        self._patch_data(node_id, patch)
        try:
            from .store import SessionStore
            SessionStore(self.db).add_event(
                f.get("task_id") or "", "finding",
                f"人工调整漏洞等级：{f.get('label')} {prev} → {sev}"
                + (f"（{reason}）" if reason else ""),
                "human", {"id": node_id, "from": prev, "to": sev, "reason": reason})
        except Exception:
            pass
        return {"ok": True, "id": node_id, "severity": sev, "from": prev,
                "locked": bool(lock), "history": hist[-30:]}

    def set_severity_bulk(self, ids: List[str], severity: str,
                          reason: str = "") -> Dict[str, Any]:
        """批量人工设定等级。"""
        out = []
        for i in ids or []:
            r = self.set_severity(str(i), severity, reason=reason)
            out.append({"id": str(i), "ok": r.get("ok"), "error": r.get("error")})
        ok = len([x for x in out if x["ok"]])
        return {"ok": True, "updated": ok, "total": len(out), "items": out,
                "severity": _norm_sev(severity)}

    def delete_findings(self, ids: List[str], reason: str = "") -> Dict[str, Any]:
        """删除漏洞节点：连带清理血缘边、资产锚点、POC 留痕，并记一条人工事件。

        只删 kind='finding' 的节点（id 精确匹配），误传其它类型节点不会被删。
        """
        ids = [str(i).strip() for i in (ids or []) if str(i).strip()]
        if not ids:
            return {"ok": True, "deleted": 0, "items": [], "counts": {}}
        ph = ",".join("?" * len(ids))
        rows = self.db.query(
            f"SELECT id, task_id, label, data FROM nodes"
            f" WHERE id IN ({ph}) AND kind='finding'", ids)
        items = []
        for r in rows:
            d = jload(r["data"], {}) or {}
            items.append({"id": r["id"], "task_id": r["task_id"],
                          "title": r["label"],
                          "audit_status": d.get("audit_status") or "",
                          "severity": d.get("severity") or ""})
        if not items:
            return {"ok": True, "deleted": 0, "items": [], "counts": {},
                    "error": "没有匹配的漏洞（可能已被删除）"}

        hit = [i["id"] for i in items]
        ph2 = ",".join("?" * len(hit))
        c_nodes = self.db.execute(f"DELETE FROM nodes WHERE id IN ({ph2})", hit).rowcount
        c_edges = self.db.execute(
            f"DELETE FROM edges WHERE src_id IN ({ph2}) OR dst_id IN ({ph2})",
            hit * 2).rowcount
        c_anchors = self.db.execute(
            f"DELETE FROM exploration_anchors WHERE node_id IN ({ph2})", hit).rowcount
        c_records = self.db.execute(
            f"DELETE FROM poc_records WHERE finding_id IN ({ph2})", hit).rowcount
        # 父节点若把它当子节点引用，清掉悬空 parent_id
        self.db.execute(
            f"UPDATE nodes SET parent_id=NULL WHERE parent_id IN ({ph2})", hit)

        # 事件留痕：按任务分组记一条，方便在活动流里回溯
        try:
            from .store import SessionStore
            ss = SessionStore(self.db)
            by_task: Dict[str, list] = {}
            for i in items:
                by_task.setdefault(i["task_id"] or "", []).append(i)
            for tid, group in by_task.items():
                ss.add_event(
                    tid, "finding",
                    "人工删除漏洞：" + "、".join(f"{g['id']} {g['title']}" for g in group)[:400],
                    "human",
                    {"ids": [g["id"] for g in group],
                     "reason": reason or "人工删除",
                     "audit_status": [g["audit_status"] for g in group]})
        except Exception:
            pass

        counts = {"nodes": c_nodes, "edges": c_edges,
                  "anchors": c_anchors, "poc_records": c_records}
        self._log("delete", f"已删除 {len(items)} 个漏洞：{counts}")
        return {"ok": True, "deleted": len(items), "items": items, "counts": counts}

    def delete_by_audit(self, ids: List[str] = None,
                        statuses: Tuple[str, ...] = ("fake", "duplicate")) -> Dict[str, Any]:
        """一键清理：删除指定范围内 audit_status 命中（误报 / 重复）的漏洞。

        ids 为空表示全库扫描；否则只在选中范围内清理。
        """
        want = {str(s).strip().lower() for s in (statuses or ()) if str(s).strip()}
        if not want:
            return {"ok": False, "error": "缺少要清理的状态 statuses"}
        ph = ""
        params: List[str] = []
        if ids:
            clean = [str(i).strip() for i in ids if str(i).strip()]
            if clean:
                ph = " AND id IN (" + ",".join("?" * len(clean)) + ")"
                params = clean
        rows = self.db.query(
            "SELECT id, data FROM nodes WHERE kind='finding'" + ph, params)
        matched = []
        for r in rows:
            d = jload(r["data"], {}) or {}
            st = str(d.get("audit_status") or "").strip().lower()
            if st in want:
                matched.append(r["id"])
        if not matched:
            return {"ok": True, "deleted": 0, "items": [], "counts": {},
                    "scanned": len(rows),
                    "message": "没有可清理的误报 / 重复漏洞"}
        reason = "一键清理" + ("误报" if "fake" in want else "") + \
                 ("重复" if "duplicate" in want else "")
        out = self.delete_findings(matched, reason=reason)
        out["scanned"] = len(rows)
        out["statuses"] = sorted(want)
        return out

    # ------------------------------------------------------------------
    # LLM / 工具（惰性构造，失败降级）
    # ------------------------------------------------------------------
    def _get_llm(self):
        if self.llm is not None:
            return self.llm
        try:
            from .llm import LLMClient
            from .settings import llm_kwargs, load_settings
            st = load_settings()
            self.llm = LLMClient(cfg={"llm": llm_kwargs()},
                                 api_key=(st.get("llm") or {}).get("api_key") or None)
        except Exception as e:
            self.llm = None
            self._log("llm", f"LLM 不可用，降级为规则模式：{e}")
        return self.llm

    def _get_tools(self):
        if self.tools is not None:
            return self.tools
        try:
            from .tools import ToolRegistry
            self.tools = ToolRegistry("skills")
        except Exception as e:
            self.tools = None
            self._log("tool", f"工具层不可用：{e}")
        return self.tools

    def _chat(self, system: str, user: str, agent: str = "vuln_agent",
              max_tokens: int = 1500, temperature: float = 0.1) -> Optional[str]:
        # 「多智能体管理」可设置漏洞审查 Agent 的附加指令，前置到系统提示词
        try:
            from .agent_admin import prefix as _prefix
            system = _prefix("vuln", system)
        except Exception:
            pass
        llm = self._get_llm()
        if not llm:
            return None
        try:
            return llm.chat(
                [{"role": "system", "content": system},
                 {"role": "user", "content": user}],
                agent=agent, max_tokens=max_tokens, temperature=temperature)
        except Exception as e:
            self._log("llm", f"LLM 调用失败，降级为规则模式：{e}")
            return None

    # ------------------------------------------------------------------
    # POC 生成
    # ------------------------------------------------------------------
    def _poc_context(self, f: dict) -> Dict[str, str]:
        d = f.get("data") or {}
        evidence = str(d.get("evidence") or "")
        return {
            "title": f.get("label") or "",
            "vuln_type": d.get("type") or d.get("vuln_type") or "",
            "severity": d.get("severity") or "",
            "asset": f.get("asset_ref") or d.get("asset") or "",
            "url": (d.get("url") or d.get("target") or
                    (_URL_RE.search(evidence).group(0) if _URL_RE.search(evidence) else "")),
            "evidence": evidence[:1500],
            # 人工备注：测试人员在详情页补充的复现要点，AI 应优先遵循
            "human_note": str(d.get("human_note") or "")[:2000],
        }

    @staticmethod
    def _note_block(ctx: Dict[str, str]) -> str:
        """把人工备注拼成给 LLM 的高优先级提示段；无备注返回空串。"""
        note = str(ctx.get("human_note") or "").strip()
        if not note:
            return ""
        return ("\n\n【人工备注 · 测试人员补充，优先级高于上面所有自动推断】\n"
                + note
                + "\n（备注结束：若备注里给了完整 URL、参数、复现步骤或判定意见，"
                  "必须以此为准。）")

    def generate_poc(self, f: dict) -> Dict[str, Any]:
        """为漏洞编写 POC。优先 LLM，失败用规则兜底。"""
        ctx = self._poc_context(f)
        poc = self._llm_generate_poc(ctx)
        if poc and self._poc_valid(poc):
            poc["source"] = "llm"
            return poc
        poc = self._rule_generate_poc(ctx, f)
        poc["source"] = "rule"
        return poc

    def _poc_valid(self, poc: Any) -> bool:
        if not isinstance(poc, dict):
            return False
        t = (poc.get("type") or "").lower()
        if t == "http":
            return bool(poc.get("url"))
        if t == "command":
            return bool(poc.get("command"))
        if t == "manual":
            return bool(poc.get("desc"))
        return False

    def _llm_generate_poc(self, ctx: Dict[str, str]) -> Optional[Dict]:
        system = ("你是资深渗透测试工程师，负责把漏洞结论转成可机读的最小化验证 POC。\n"
                  "严格要求：\n"
                  "1. 只输出一个 JSON 对象，不要任何解释文字或代码块外的废话；\n"
                  "2. http 型：{\"type\":\"http\",\"method\":\"GET\",\"url\":\"完整URL\","
                  "\"headers\":{},\"data\":\"\",\"match\":\"命中特征\",\"desc\":\"一句话说明\"}；\n"
                  "3. command 型：{\"type\":\"command\",\"command\":\"curl -sk '...'\","
                  "\"match\":\"命中特征\",\"desc\":\"...\"}；\n"
                  "4. 无法自动化时：{\"type\":\"manual\",\"desc\":\"人工验证步骤\"}；\n"
                  "5. POC 必须只读、无害（不写入、不删除、不反弹 shell），url 必须是完整绝对地址；\n"
                  "6. match 是漏洞存在时响应中必然出现的特征片段；无法给出时留空字符串。"
                  + self._note_block(ctx))
        user = ("漏洞信息：\n" + json.dumps(ctx, ensure_ascii=False, indent=2)
                + "\n请输出 POC JSON。")
        raw = self._chat(system, user, agent="vuln_poc")
        poc = _extract_json(raw or "")
        return poc if isinstance(poc, dict) else None

    def _rule_generate_poc(self, ctx: Dict[str, str], f: dict) -> Dict[str, Any]:
        """规则兜底：优先用人工备注/证据里的 URL，按漏洞类型拼一个最小探测请求。"""
        url = ctx.get("url") or ""
        note = str(ctx.get("human_note") or "")
        # 人工备注里贴的完整 URL 优先级最高
        m = _URL_RE.search(note)
        if m:
            url = m.group(0)
        asset = ctx.get("asset") or ""
        if not url and asset:
            url = asset if asset.startswith("http") else "http://" + asset
        vtype = (ctx.get("vuln_type") or "") + (ctx.get("title") or "")
        method, data, headers = "GET", "", {}
        match = ""
        low = vtype.lower()
        from_note = bool(m)          # URL 来自人工备注时不再追加探测参数，避免破坏原样
        if not from_note:
            if any(k in low for k in ("sql", "注入", "sqli")):
                url = self._with_param(url, "id", "1'")
                match = "sql|syntax|mysql|ora-|you have an error"
            elif any(k in low for k in ("xss", "跨站")):
                url = self._with_param(url, "q", "<script>alert(1)</script>")
                match = "<script>alert(1)</script>"
            elif any(k in low for k in ("ssrf",)):
                url = self._with_param(url, "url", "http://127.0.0.1:80/")
            elif any(k in low for k in ("目录遍历", "文件读取", "lfi",
                                        "path traversal", "任意文件")):
                url = self._with_param(url, "file", "../../../../etc/passwd")
                match = "root:"
            elif any(k in low for k in ("redirect", "跳转")):
                url = self._with_param(url, "redirect", "http://example.com")
            elif any(k in low for k in ("命令执行", "rce", "command")):
                method, data = "POST", "cmd=id"
                match = "uid="
        if not url:
            return {"type": "manual", "desc": "缺少可访问 URL，需人工验证：" +
                    (ctx.get("title") or ""), "match": ""}
        return {"type": "http", "method": method, "url": url, "headers": headers,
                "data": data, "match": match,
                "desc": ("按人工备注中的 URL 生成的只读探测 POC" if from_note
                         else "规则生成的只读探测 POC")}

    @staticmethod
    def _with_param(url: str, key: str, value: str) -> str:
        if not url:
            return url
        sep = "&" if "?" in url else "?"
        from urllib.parse import quote
        return f"{url}{sep}{key}={quote(value, safe='')}"

    # ------------------------------------------------------------------
    # POC 执行
    # ------------------------------------------------------------------
    def run_poc(self, poc: Dict, allow_command: bool = False,
                timeout: int = 20) -> Dict[str, Any]:
        """执行 POC，返回 {exec_ok, matched, ok, echo, error}。"""
        poc = poc or {}
        ptype = (poc.get("type") or "").lower()
        if ptype == "manual":
            return {"exec_ok": False, "matched": False, "ok": False, "echo": "",
                    "error": "人工验证型 POC，未自动执行"}
        if ptype == "command" and not allow_command:
            return {"exec_ok": False, "matched": False, "ok": False, "echo": "",
                    "error": "Shell 类 POC 未开启执行（默认关闭，可在优化选项中开启）"}
        if ptype not in ("http", "command"):
            return {"exec_ok": False, "matched": False, "ok": False, "echo": "",
                    "error": f"不支持的 POC 类型: {ptype or '空'}"}

        tools = self._get_tools()
        if not tools:
            return {"exec_ok": False, "matched": False, "ok": False, "echo": "",
                    "error": "工具层不可用"}
        if ptype == "http":
            args = {"method": poc.get("method") or "GET", "url": poc.get("url"),
                    "headers": poc.get("headers") or {}, "data": poc.get("data") or "",
                    "timeout": timeout}
        else:
            args = {"command": poc.get("command"), "timeout": timeout}
        try:
            res = tools.run(ptype, args, {"source": "vuln_agent"})
        except Exception as e:
            return {"exec_ok": False, "matched": False, "ok": False, "echo": "",
                    "error": f"执行异常: {e}"}

        echo = (res.get("response") or res.get("output")
                or res.get("message") or jdump(res))[:_ECHO_LIMIT]
        exec_ok = str(res.get("status", "")) == "success"
        matched = self._match_echo(poc.get("match"), echo)
        return {"exec_ok": exec_ok, "matched": matched, "ok": bool(exec_ok and matched),
                "echo": echo, "error": "" if exec_ok else str(res.get("message") or "")}

    @staticmethod
    def _match_echo(match: Any, echo: str) -> bool:
        """命中判定：空=不校验；/regex/ 走正则；其余为大小写不敏感子串。"""
        m = str(match or "").strip()
        if not m:
            return True
        text = str(echo or "")
        if len(m) > 2 and m.startswith("/") and m.rstrip("i").endswith("/"):
            pat = m[1:-1] if not m.lower().endswith("/i") else m[1:-2]
            try:
                return re.search(pat, text, re.I) is not None
            except re.error:
                return pat.lower() in text.lower()
        return m.lower() in text.lower()

    # ------------------------------------------------------------------
    # AI 误报判定 / AI 复测判定
    # ------------------------------------------------------------------
    def ai_analyze_false_positive(self, f: dict, poc: Dict, result: Dict) -> Dict:
        """验证失败时，让 AI 判断是否误报；LLM 不可用时退回规则判定。"""
        ctx = self._poc_context(f)
        user = ("漏洞信息：\n" + json.dumps(ctx, ensure_ascii=False, indent=2)
                + "\n\n执行的 POC：\n" + json.dumps(poc or {}, ensure_ascii=False, indent=2)
                + "\n\n执行回显：\n" + str(result.get("echo") or "")[:3000]
                + ("\n\n执行错误：" + str(result.get("error") or "") if result.get("error") else "")
                + self._note_block(ctx)
                + "\n\n请判断该漏洞是否为误报，输出 JSON："
                  "{\"false_positive\":true/false,\"confidence\":0-1,"
                  "\"reason\":\"不超过120字的理由\",\"suggestion\":\"下一步建议\"}")
        raw = self._chat(
            "你是漏洞审核专家，只依据证据判断，宁可存疑也不臆断。"
            "只输出 JSON，不要其它文字。", user, agent="vuln_audit")
        obj = _extract_json(raw or "")
        if isinstance(obj, dict) and "false_positive" in obj:
            fp = bool(obj.get("false_positive"))
            return {"false_positive": fp,
                    "confidence": float(obj.get("confidence") or 0.5),
                    "reason": str(obj.get("reason") or "")[:600],
                    "suggestion": str(obj.get("suggestion") or "")[:600],
                    "source": "llm"}
        # 规则降级：无证据 / 证据与标题同文 / 根本没拿到回显 → 判误报
        ev = (ctx.get("evidence") or "").strip()
        title = (ctx.get("title") or "").strip()
        weak = (not ev) or (ev == title) or (not result.get("exec_ok"))
        return {"false_positive": bool(weak), "confidence": 0.4,
                "reason": "LLM 不可用，按规则判定：" +
                          ("无有效证据或请求未成功" if weak else "已有证据但 POC 未复现"),
                "suggestion": "建议人工复核原始请求与响应", "source": "rule"}

    def ai_plan_retest(self, f: dict, prev_poc: Dict, last_echo: str) -> Dict:
        """AI 复测第一步：让 LLM 生成/修正复测 POC。"""
        ctx = self._poc_context(f)
        user = ("漏洞信息：\n" + json.dumps(ctx, ensure_ascii=False, indent=2)
                + "\n\n上次 POC：\n" + json.dumps(prev_poc or {}, ensure_ascii=False, indent=2)
                + "\n\n上次回显：\n" + str(last_echo or "")[:2500]
                + self._note_block(ctx)
                + "\n\n请输出用于**复测**的 POC JSON（同 verify 格式），"
                  "要求与上次命中路径一致、便于对比回显差异。")
        raw = self._chat(
            "你是资深渗透测试工程师，负责生成用于漏洞复测（验证是否已修复）的只读 POC。"
            "只输出 JSON。", user, agent="vuln_retest")
        poc = _extract_json(raw or "")
        if isinstance(poc, dict) and self._poc_valid(poc):
            poc["source"] = "llm"
            return poc
        return prev_poc or self._rule_generate_poc(ctx, f)

    def ai_judge_fixed(self, f: dict, poc: Dict, last_echo: str,
                       new_echo: str, mechanical: str) -> Dict:
        """AI 复测第二步：结合回显差异判定是否已修复。"""
        ctx = self._poc_context(f)
        user = ("漏洞信息：\n" + json.dumps(ctx, ensure_ascii=False, indent=2)
                + "\n\n复测 POC：\n" + json.dumps(poc or {}, ensure_ascii=False, indent=2)
                + "\n\n上次回显：\n" + str(last_echo or "")[:2500]
                + "\n\n本次回显：\n" + str(new_echo or "")[:2500]
                + "\n\n机器比对结论：" + mechanical
                + self._note_block(ctx)
                + "\n\n请判定该漏洞是否已被修复，输出 JSON："
                  "{\"fixed\":true/false,\"confidence\":0-1,\"reason\":\"不超过150字\","
                  "\"evidence\":\"关键回显差异\"}")
        raw = self._chat(
            "你是漏洞修复验证专家：回显与漏洞特征消失/被拦截/返回 404 等通常意味着已修复；"
            "仅当漏洞特征依然出现才判未修复。只输出 JSON。", user, agent="vuln_retest")
        obj = _extract_json(raw or "")
        if isinstance(obj, dict) and "fixed" in obj:
            return {"fixed": bool(obj.get("fixed")),
                    "confidence": float(obj.get("confidence") or 0.5),
                    "reason": str(obj.get("reason") or "")[:800],
                    "evidence": str(obj.get("evidence") or "")[:800],
                    "source": "llm"}
        fixed = mechanical.startswith("fixed")
        return {"fixed": fixed, "confidence": 0.4,
                "reason": "LLM 不可用，按回显比对判定（" + mechanical + "）",
                "evidence": _echo_diff(last_echo, new_echo)[:800], "source": "rule"}

    # ------------------------------------------------------------------
    # 审查式去重 + 严重性重评估（一键优化的核心）
    # ------------------------------------------------------------------
    def _review_item(self, f: dict) -> Dict[str, Any]:
        """把一条漏洞压缩成审查输入项：来源接口 / 详情 / 证据摘要 / 现有等级。"""
        d = f.get("data") or {}
        ev = str(d.get("evidence") or "")
        url = (d.get("url") or d.get("target") or "")
        if not url:
            m = _URL_RE.search(ev)
            url = m.group(0) if m else ""
        host = _host_of(f.get("asset_ref") or d.get("asset") or url) or "(未知资产)"
        return {
            "id": f["id"], "task_id": f.get("task_id"),
            "title": f.get("label") or "",
            "type": d.get("type") or d.get("vuln_type") or "",
            "host": host, "url": url,
            "severity": _norm_sev(d.get("severity")),
            "evidence": ev[:600],
            "verify_status": d.get("verify_status") or "",
            "fixed": bool(d.get("fixed")),
            "has_poc": bool(isinstance(d.get("poc"), dict)),
            "locked": bool(d.get("severity_locked")) or d.get("severity_source") == "human",
            "data": d,
        }

    def _llm_review(self, host: str, grp: List[dict]) -> Optional[List[dict]]:
        """让 LLM 对「同一资产下的一批记录」做语义去重 + 重新定级。"""
        llm = self._get_llm()
        if not llm:
            return None
        brief = []
        for it in grp[:30]:
            brief.append({
                "id": it["id"], "标题": it["title"], "类型": it["type"],
                "接口": it["url"] or it["host"], "现有等级": it["severity"],
                "证据": it["evidence"][:300], "验证": it["verify_status"],
            })
        system = (
            "你是漏洞审核与定级专家。下面列出了**同一资产**下的若干条漏洞记录，"
            "它们可能来自自动化扫描的重复上报（同一漏洞被不同措辞重复记录）。\n"
            "请完成三件事：\n"
            "1. 按『同一资产 + 同一漏洞本质（同一接口 / 同一文件 / 同一成因）』聚类去重；\n"
            "2. 每个唯一漏洞指定保留项 keep 与被合并项 duplicates；\n"
            "3. **重新评估严重性**，只能取 危急 / 高 / 中 / 低 / 信息，并给出理由：\n"
            "   - 能直接利用（RCE / 拿到明文凭据或密钥 / 越权读数据）→ 升级；\n"
            "   - 仅发现备份文件路径、响应里没有实际文件内容 → 降级；\n"
            "   - 无可验证证据 → 信息；\n"
            "   - 依据不足时保守处理，不要为了好看而抬级。\n"
            "只输出一个 JSON 对象，不要任何解释或代码块：\n"
            "{\"unique\":[{\"keep\":\"记录id\",\"duplicates\":[\"id\"],"
            "\"title\":\"规范标题\",\"severity\":\"高\","
            "\"severity_reason\":\"不超过60字\",\"dedup_reason\":\"不超过60字\"}]}\n"
            "硬性要求：unique 必须覆盖输入里的**每一个** id（单条也要作为 unique 列出，"
            "其 duplicates 为空）；同一 id 不得出现在多处。")
        user = (f"资产：{host}\n记录（JSON）：\n"
                + json.dumps(brief, ensure_ascii=False, indent=1)
                + "\n请输出审查结果 JSON。")
        raw = self._chat(system, user, agent="vuln_review", max_tokens=2000)
        obj = _extract_json(raw or "")
        if not isinstance(obj, dict):
            return None
        uniq = obj.get("unique")
        if not isinstance(uniq, list) or not uniq:
            return None
        valid_ids = {it["id"] for it in grp}
        out, seen = [], set()
        for u in uniq:
            if not isinstance(u, dict):
                continue
            keep = str(u.get("keep") or "")
            if keep not in valid_ids or keep in seen:
                continue
            seen.add(keep)
            dups = [str(x) for x in (u.get("duplicates") or [])
                    if str(x) in valid_ids and str(x) != keep and str(x) not in seen]
            for x in dups:
                seen.add(x)
            out.append({"keep": keep, "duplicates": dups,
                        "title": str(u.get("title") or "")[:200],
                        "severity": _norm_sev(u.get("severity")),
                        "severity_reason": str(u.get("severity_reason") or "")[:300],
                        "dedup_reason": str(u.get("dedup_reason") or "")[:300]})
        # 未被 LLM 覆盖的记录：各自成为独立唯一项（保留原等级）
        for it in grp:
            if it["id"] not in seen:
                out.append({"keep": it["id"], "duplicates": [], "title": "",
                            "severity": "未评级", "severity_reason": "",
                            "dedup_reason": ""})
        return out or None

    def _rule_review(self, host: str, grp: List[dict]) -> List[dict]:
        """规则兜底：标题相似度 + 同族关键词聚类，规则定级。"""
        clusters: List[List[dict]] = []
        for it in grp:
            placed = False
            for c in clusters:
                rep = c[0]
                same_cve = _CVE_RE.findall(it["title"]) and \
                    set(x.upper() for x in _CVE_RE.findall(it["title"])) == \
                    set(x.upper() for x in _CVE_RE.findall(rep["title"]))
                if same_cve or _title_similar(it["title"], rep["title"]) >= 0.72 \
                        or _same_vuln_family(it["title"], rep["title"]):
                    c.append(it)
                    placed = True
                    break
            if not placed:
                clusters.append([it])
        out = []
        for c in clusters:
            def _rank(x):
                return (-len(x["evidence"]), -int(x["has_poc"]),
                        _SEV_RANK.get(x["severity"], 9))
            c_sorted = sorted(c, key=_rank)
            keep = c_sorted[0]
            sevs = [_norm_sev(x["severity"]) for x in c]
            best = min(sevs, key=lambda s: _SEV_RANK.get(s, 9)) if sevs else "未评级"
            # 用**全组最完整的证据**做重评估，避免把有实锤的那条漏掉
            best_ev = max((x["evidence"] or "" for x in c), key=len, default="")
            rsev, rreason, confident = _rule_severity(keep["title"], best_ev, keep["type"])
            # 规则能明确判定时以重评估为准（可升级 / 可降级）；否则保留更严重者
            final = rsev if confident else best
            out.append({
                "keep": keep["id"],
                "duplicates": [x["id"] for x in c_sorted[1:]],
                "title": keep["title"],
                "severity": final,
                "severity_reason": rreason,
                "dedup_reason": f"同资产同族漏洞（规则聚类，保留 {keep['id']}）"
                                if len(c) > 1 else "",
            })
        return out

    def _apply_unique(self, by_id: Dict[str, dict], u: dict, source: str,
                      retitle: bool, reeval: bool = True) -> Dict[str, Any]:
        """落地一个「唯一漏洞」：合并重复项信息、规范标题、写入/尊重严重性。"""
        keep_id = u.get("keep")
        keep = by_id.get(keep_id)
        if not keep:
            return {}
        out = {"merged": [], "severity": None}
        dup_ids = [d for d in (u.get("duplicates") or []) if d in by_id]
        reason = u.get("dedup_reason") or ""

        merged_ids, merged_titles, urls = [], [], []
        for did in dup_ids:
            d = by_id[did]
            merged_ids.append(did)
            merged_titles.append(d["title"])
            if d.get("url"):
                urls.append(d["url"])
            self._patch_data(did, {
                "audit_status": "duplicate",
                "merged_into": keep_id,
                "dedup_reason": reason or f"同资产同类漏洞（已并入 {keep_id}）",
            })
            self._record(did, d.get("task_id"), "dedup", verdict="duplicate",
                         analysis={"merged_into": keep_id, "reason": reason,
                                   "source": source})
            out["merged"].append({"drop_id": did, "keep_id": keep_id,
                                  "reason": reason or "同资产同类漏洞"})

        kd = keep["data"] or {}
        patch: Dict[str, Any] = {}
        if merged_ids:
            patch["merged_ids"] = sorted(set(list(kd.get("merged_ids") or []) + merged_ids))
            patch["merged_titles"] = (list(kd.get("merged_titles") or [])
                                      + merged_titles)[:20]
            if reason:
                patch["dedup_reason"] = reason
        if urls:
            patch["source_interfaces"] = sorted(set(
                list(kd.get("source_interfaces") or []) + urls))[:20]
        title = (u.get("title") or "").strip()
        if title and title != keep["title"]:
            patch["canonical_title"] = title
            if retitle:
                try:
                    self.db.execute("UPDATE nodes SET label=?, updated_at=? WHERE id=?",
                                    (title[:300], now(), keep_id))
                except Exception:
                    pass

        # ---- 严重性重评估（人工锁定 / 人工设定者不覆盖）----
        sev = _norm_sev(u.get("severity"))
        if reeval and not keep.get("locked") and sev not in ("未评级",):
            prev = keep["severity"]
            if sev != prev:
                hist = list(kd.get("severity_history") or [])
                hist.append({"at": now(), "from": prev, "to": sev, "by": source,
                             "reason": u.get("severity_reason") or ""})
                patch.update({
                    "severity": sev,
                    "severity_source": source,
                    "severity_reason": u.get("severity_reason") or "",
                    "severity_prev": prev,
                    "severity_at": now(),
                    "severity_history": hist[-30:],
                })
                out["severity"] = {"id": keep_id, "title": keep["title"],
                                   "from": prev, "to": sev,
                                   "reason": u.get("severity_reason") or "",
                                   "source": source}
        if patch:
            self._patch_data(keep_id, patch)
        return out

    def review(self, ids: List[str], opts: Dict = None) -> Dict[str, Any]:
        """审查选中漏洞：重新分析来源接口/详情 → 语义去重 → 重评估严重性。

        这是「一键优化」的第一步（取代旧的纯字符串去重）。LLM 可用时按资产分组做
        语义聚类；不可用时退回规则聚类。返回 {merged, severity_changes, groups, kept}。
        """
        opts = opts or {}
        use_llm = bool(opts.get("use_llm", True))
        max_llm_groups = int(opts.get("max_llm_groups") or 12)
        retitle = bool(opts.get("retitle", True))
        reeval = bool(opts.get("reeval_severity", True))

        by_id: Dict[str, dict] = {}
        for i in ids or []:
            f = self.get_finding(i)
            if not f:
                continue
            if (f.get("data") or {}).get("audit_status") == "duplicate":
                continue
            it = self._review_item(f)
            by_id[it["id"]] = it
        if not by_id:
            return {"merged": [], "severity_changes": [], "groups": 0,
                    "kept": 0, "skipped": True}

        groups: Dict[str, List[dict]] = {}
        for it in by_id.values():
            groups.setdefault(it["host"], []).append(it)

        merged: List[dict] = []
        sev_changes: List[dict] = []
        llm_used = 0
        for host, grp in groups.items():
            uniq = None
            if use_llm and llm_used < max_llm_groups and len(grp) >= 1:
                uniq = self._llm_review(host, grp)
                if uniq:
                    llm_used += 1
            source = "ai" if uniq else "rule"
            if not uniq:
                uniq = self._rule_review(host, grp)
            for u in uniq:
                res = self._apply_unique(by_id, u, source, retitle, reeval)
                merged.extend(res.get("merged") or [])
                if res.get("severity"):
                    sev_changes.append(res["severity"])
        self._log("review",
                  f"审查完成：{len(by_id)} 条 → 合并 {len(merged)}、"
                  f"调整等级 {len(sev_changes)}（{llm_used} 组由 AI 审查）")
        return {"merged": merged, "severity_changes": sev_changes,
                "groups": len(groups), "kept": len(by_id) - len(merged),
                "llm_groups": llm_used, "skipped": False,
                "map": {m["drop_id"]: m["keep_id"] for m in merged}}

    # ------------------------------------------------------------------
    # 去重（兼容入口，内部走审查逻辑）
    # ------------------------------------------------------------------
    def dedup(self, ids: List[str]) -> Dict[str, Any]:
        """对指定漏洞去重（保留旧接口，内部调用审查逻辑）。"""
        r = self.review(ids, {"use_llm": True, "retitle": False})
        return {"merged": r.get("merged") or [], "kept": r.get("kept", 0),
                "skipped": r.get("skipped", False), "map": r.get("map") or {},
                "severity_changes": r.get("severity_changes") or []}

    # ------------------------------------------------------------------
    # 一键优化（单条）
    # ------------------------------------------------------------------
    def optimize_one(self, node_id: str, opts: Dict = None) -> Dict[str, Any]:
        opts = opts or {}
        allow_command = bool(opts.get("allow_command"))
        timeout = int(opts.get("timeout") or 20)
        f = self.get_finding(node_id)
        if not f:
            return {"id": node_id, "ok": False, "error": "漏洞不存在"}
        d = f.get("data") or {}
        if d.get("audit_status") == "duplicate":
            return {"id": node_id, "ok": True, "skipped": True,
                    "reason": "已并入 " + str(d.get("merged_into") or "")}

        out: Dict[str, Any] = {"id": node_id, "title": f.get("label"),
                               "stage": "", "poc_generated": False,
                               "verified": False, "false_positive": False,
                               "error": ""}

        # 1) POC：没有就生成
        poc = d.get("poc") if isinstance(d.get("poc"), dict) else None
        if not poc and not opts.get("skip_poc"):
            self._log("poc", f"[{node_id}] 编写 POC：{f.get('label')}")
            poc = self.generate_poc(f)
            out["poc_generated"] = True
            self._record(node_id, f.get("task_id"), "gen", poc=poc,
                         verdict="", analysis={"source": poc.get("source")})
        if not poc:
            poc = {"type": "manual", "desc": "未能生成 POC"}
        out["poc"] = poc

        # 2) 执行验证（未开 allow_command 时 command 型只记录不执行）
        if opts.get("skip_verify"):
            self._patch_data(node_id, {"poc": poc})
            out["stage"] = "poc-only"
            return out

        self._log("verify", f"[{node_id}] 执行 POC 验证")
        res = self.run_poc(poc, allow_command=allow_command, timeout=timeout)
        echo = res.get("echo") or ""
        patch: Dict[str, Any] = {
            "poc": poc,
            "poc_echo": echo,
            "poc_verified_at": now(),
            "poc_exec_error": res.get("error") or "",
        }
        if res.get("ok"):
            patch.update({"verify_status": "verified",
                          "fixed": False, "fix_status": "unfixed",
                          "ai_analysis": ""})
            out.update({"stage": "verified", "verified": True})
            verdict = "verified"
        else:
            # 3) 验证失败 → AI 判定是否误报
            self._log("ai", f"[{node_id}] 验证失败，AI 分析是否误报")
            analysis = self.ai_analyze_false_positive(f, poc, res)
            fp = bool(analysis.get("false_positive"))
            patch.update({
                "verify_status": "false_positive" if fp else "failed",
                "audit_status": "fake" if fp else (d.get("audit_status") or ""),
                "ai_analysis": analysis.get("reason") or "",
                "ai_analysis_detail": analysis,
                "fix_status": "unknown",
            })
            out.update({"stage": "false_positive" if fp else "failed",
                        "false_positive": fp, "analysis": analysis,
                        "error": res.get("error") or ""})
            verdict = "false_positive" if fp else "failed"

        self._patch_data(node_id, patch)
        self._record(node_id, f.get("task_id"), "verify", poc=poc, echo=echo,
                     ok=1 if res.get("ok") else 0, verdict=verdict,
                     analysis=out.get("analysis") or {"error": res.get("error") or ""})
        out["echo"] = echo[:400]
        return out

    # ------------------------------------------------------------------
    # 复测（用已保存 POC，回显不同即视为已修复）
    # ------------------------------------------------------------------
    def retest_one(self, node_id: str, opts: Dict = None) -> Dict[str, Any]:
        opts = opts or {}
        allow_command = bool(opts.get("allow_command"))
        timeout = int(opts.get("timeout") or 20)
        f = self.get_finding(node_id)
        if not f:
            return {"id": node_id, "ok": False, "error": "漏洞不存在"}
        d = f.get("data") or {}
        poc = d.get("poc") if isinstance(d.get("poc"), dict) else None
        if not poc:
            self._log("poc", f"[{node_id}] 无 POC，先生成再复测")
            poc = self.generate_poc(f)
            self._record(node_id, f.get("task_id"), "gen", poc=poc,
                         analysis={"source": poc.get("source")})

        baseline = str(d.get("poc_echo") or "")
        self._log("retest", f"[{node_id}] 用 POC 复测")
        res = self.run_poc(poc, allow_command=allow_command, timeout=timeout)
        echo = res.get("echo") or ""

        if res.get("exec_ok") is False and not echo:
            status, fixed = "unknown", None
            reason = "复测请求未成功，无法判定（" + (res.get("error") or "执行失败") + "）"
        elif not baseline:
            status, fixed = "unknown", None
            reason = "无历史基线回显，本次结果已作为基线保存"
        else:
            same = _same_echo(baseline, echo)
            status = "unfixed" if same else "fixed"
            fixed = (not same)
            reason = ("回显与基线一致，漏洞仍存在" if same
                      else "回显与基线不同，判定已修复")

        patch: Dict[str, Any] = {
            "poc": poc,
            "poc_echo": echo if not baseline else baseline,   # 基线只在首次写入
            "last_echo": echo,
            "last_retest_at": now(),
            "retest_count": int(d.get("retest_count") or 0) + 1,
            "fix_status": status,
            "retest_reason": reason,
            "retest_diff": _echo_diff(baseline, echo)[:2000],
        }
        if fixed is True:
            patch["fixed"] = True
            patch["fixed_at"] = now()
            patch["verify_status"] = "verified"     # 曾验证存在，现已被修复
        elif fixed is False:
            patch["fixed"] = False
            patch["verify_status"] = d.get("verify_status") or "verified"
        self._patch_data(node_id, patch)
        self._record(node_id, f.get("task_id"), "retest", poc=poc, echo=echo,
                     ok=1 if res.get("ok") else 0, verdict=status,
                     analysis={"reason": reason, "diff": patch["retest_diff"]})
        return {"id": node_id, "ok": True, "fix_status": status, "fixed": fixed,
                "reason": reason, "echo": echo[:400], "poc_type": poc.get("type")}

    # ------------------------------------------------------------------
    # AI 复测（LLM 生成/修正 POC + LLM 判定是否修复）
    # ------------------------------------------------------------------
    def ai_retest_one(self, node_id: str, opts: Dict = None) -> Dict[str, Any]:
        opts = opts or {}
        allow_command = bool(opts.get("allow_command"))
        timeout = int(opts.get("timeout") or 20)
        f = self.get_finding(node_id)
        if not f:
            return {"id": node_id, "ok": False, "error": "漏洞不存在"}
        d = f.get("data") or {}
        prev_poc = d.get("poc") if isinstance(d.get("poc"), dict) else None
        last_echo = str(d.get("poc_echo") or d.get("last_echo") or "")

        self._log("ai", f"[{node_id}] AI 规划复测 POC")
        poc = self.ai_plan_retest(f, prev_poc or {}, last_echo)
        self._record(node_id, f.get("task_id"), "gen", poc=poc,
                     analysis={"source": poc.get("source"), "stage": "ai_retest"})

        self._log("ai", f"[{node_id}] 执行 AI 复测 POC")
        res = self.run_poc(poc, allow_command=allow_command, timeout=timeout)
        echo = res.get("echo") or ""

        if last_echo and echo:
            mechanical = "fixed（回显与上次不同）" if not _same_echo(last_echo, echo) \
                else "unfixed（回显与上次一致）"
        elif not echo:
            mechanical = "unknown（未拿到回显：" + (res.get("error") or "执行失败") + "）"
        else:
            mechanical = "unknown（无历史回显，本次作为基线）"

        self._log("ai", f"[{node_id}] AI 判定是否修复")
        judge = self.ai_judge_fixed(f, poc, last_echo, echo, mechanical)

        if mechanical.startswith("unknown"):
            status = "unknown"
        else:
            status = "fixed" if judge.get("fixed") else "unfixed"
        fixed = True if status == "fixed" else (False if status == "unfixed" else None)

        patch: Dict[str, Any] = {
            "poc": poc,
            "last_echo": echo,
            "ai_retest_at": now(),
            "ai_retest_count": int(d.get("ai_retest_count") or 0) + 1,
            "ai_retest_verdict": judge,
            "ai_analysis": judge.get("reason") or "",
            "fix_status": status,
            "retest_diff": _echo_diff(last_echo, echo)[:2000],
        }
        if not last_echo:
            patch["poc_echo"] = echo
        if fixed is True:
            patch["fixed"] = True
            patch["fixed_at"] = now()
        elif fixed is False:
            patch["fixed"] = False
        self._patch_data(node_id, patch)
        self._record(node_id, f.get("task_id"), "ai_retest", poc=poc, echo=echo,
                     ok=1 if res.get("ok") else 0, verdict=status, analysis=judge)
        return {"id": node_id, "ok": True, "fix_status": status, "fixed": fixed,
                "reason": judge.get("reason") or "", "confidence": judge.get("confidence"),
                "source": judge.get("source"), "echo": echo[:400],
                "poc_type": poc.get("type")}

    # ------------------------------------------------------------------
    # 批量入口
    # ------------------------------------------------------------------
    def optimize(self, ids: List[str], opts: Dict = None,
                 on_item: Callable[[int, int, dict], None] = None) -> Dict[str, Any]:
        opts = opts or {}
        ids = [i for i in (ids or [])]
        total = len(ids)
        summary = {"total": total, "dedup_merged": 0, "severity_changed": 0,
                   "review_groups": 0, "poc_generated": 0,
                   "verified": 0, "false_positive": 0, "failed": 0, "skipped": 0}
        results: List[dict] = []

        if opts.get("dedup", True) and total:
            self._log("review", f"开始审查：重新分析 {total} 条漏洞的来源接口与详情")
            dd = self.review(ids, opts)
            summary["dedup_merged"] = len(dd.get("merged") or [])
            summary["severity_changed"] = len(dd.get("severity_changes") or [])
            summary["review_groups"] = dd.get("groups", 0)
            results.append({"kind": "review",
                            "merged": dd.get("merged") or [],
                            "severity_changes": dd.get("severity_changes") or [],
                            "llm_groups": dd.get("llm_groups", 0)})
            ids = [i for i in ids if i not in (dd.get("map") or {})]

        for n, nid in enumerate(ids, 1):
            self._log("run", f"({n}/{len(ids)}) 优化 {nid}")
            try:
                r = self.optimize_one(nid, opts)
            except Exception as e:
                r = {"id": nid, "ok": False, "error": f"优化异常: {e}"}
            results.append(r)
            if r.get("skipped"):
                summary["skipped"] += 1
            if r.get("poc_generated"):
                summary["poc_generated"] += 1
            if r.get("verified"):
                summary["verified"] += 1
            elif r.get("false_positive"):
                summary["false_positive"] += 1
            elif r.get("stage") == "failed":
                summary["failed"] += 1
            if on_item:
                try:
                    on_item(n, len(ids), r)
                except Exception:
                    pass
        self._log("done", f"优化完成：{summary}")
        return {"ok": True, "summary": summary, "results": results}

    def retest(self, ids: List[str], opts: Dict = None,
               on_item: Callable[[int, int, dict], None] = None) -> Dict[str, Any]:
        ids = [i for i in (ids or [])]
        results = []
        fixed = unfixed = unknown = 0
        for n, nid in enumerate(ids, 1):
            self._log("run", f"({n}/{len(ids)}) 复测 {nid}")
            try:
                r = self.retest_one(nid, opts)
            except Exception as e:
                r = {"id": nid, "ok": False, "error": f"复测异常: {e}"}
            results.append(r)
            if r.get("fix_status") == "fixed":
                fixed += 1
            elif r.get("fix_status") == "unfixed":
                unfixed += 1
            else:
                unknown += 1
            if on_item:
                try:
                    on_item(n, len(ids), r)
                except Exception:
                    pass
        summary = {"total": len(ids), "fixed": fixed, "unfixed": unfixed,
                   "unknown": unknown}
        self._log("done", f"复测完成：{summary}")
        return {"ok": True, "summary": summary, "results": results}

    def ai_retest(self, ids: List[str], opts: Dict = None,
                  on_item: Callable[[int, int, dict], None] = None) -> Dict[str, Any]:
        ids = [i for i in (ids or [])]
        results = []
        fixed = unfixed = unknown = 0
        for n, nid in enumerate(ids, 1):
            self._log("run", f"({n}/{len(ids)}) AI 复测 {nid}")
            try:
                r = self.ai_retest_one(nid, opts)
            except Exception as e:
                r = {"id": nid, "ok": False, "error": f"AI 复测异常: {e}"}
            results.append(r)
            if r.get("fix_status") == "fixed":
                fixed += 1
            elif r.get("fix_status") == "unfixed":
                unfixed += 1
            else:
                unknown += 1
            if on_item:
                try:
                    on_item(n, len(ids), r)
                except Exception:
                    pass
        summary = {"total": len(ids), "fixed": fixed, "unfixed": unfixed,
                   "unknown": unknown}
        self._log("done", f"AI 复测完成：{summary}")
        return {"ok": True, "summary": summary, "results": results}
