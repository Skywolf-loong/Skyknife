# -*- coding: utf-8 -*-
"""攻击链管理 + 攻击链记忆（Attack Chain Memory）。

把一次任务的攻击链路（意图 → 事实 → 漏洞）沉淀为可复用的「攻击链记忆」：

  - 结构化记录：``agent6_data/attack_chains.json``（供界面浏览 / 编辑 / 删除）
  - 单链 Markdown：``agent6_data/chain_memory/<ACID>.md``
  - 汇总记忆文件：``agent6_data/chain_memory/attack_chain_memory.md``
    ——「分类索引 + 全量档案」，**不设条数上限**
  - 人类可读镜像：``.workbuddy/memory/attack_chain_memory.md``（存在该目录时）

三条硬约定：
1. **脱敏入库**：域名 / IP / URL 主机 / 邮箱 / 用户名 / 口令 / Token / Cookie 一律不落盘，
   统一替换为 ``<DOMAIN>`` ``<IP>`` ``<HOST>`` ``<EMAIL>`` ``<REDACTED>``；
   目标身份改用**不可逆指纹**（``target_fp`` / ``root_fp``）表示，既能匹配「同目标/同主域」
   又不会泄露业务资产。端口与路径保留（对打法的复用价值最高）。
2. **不设上限**：所有攻击链全量保留并进记忆文件；``inject_limit`` 只约束「单次注入 Planner 的条数」。
3. **按需调用**：``catalog()`` 给出分类目录（目标类型 / 技术栈 / 漏洞类型 / 阶段），
   ``query_memory()`` / ``reference_for()`` 只在命中时才取用，绝不把全部记忆塞进提示词。

设计原则：只读沉淀（不改任务数据、不重放请求）、可回溯（带 task_id 与指标）、失败不阻断。
"""
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Dict, List, Optional

_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = _ROOT / "agent6_data"
STORE = _DATA_DIR / "attack_chains.json"
MEM_DIR = _DATA_DIR / "chain_memory"
MEM_FILE = MEM_DIR / "attack_chain_memory.md"
# 项目记忆目录镜像（供人类/其它会话直接阅读，存在才写）
_MIRROR = _ROOT / ".workbuddy" / "memory" / "attack_chain_memory.md"

SCHEMA_VERSION = 2
_MIGRATING = False

DEFAULT_SETTINGS = {
    "auto_review": True,     # 任务结束后自动复盘并写记忆
    "inject_memory": True,   # 任务开始前按需注入历史链记忆
    "inject_limit": 3,       # 单次注入 Planner 的最大条数（不影响记忆存储）
}

# ---------------------------------------------------------------------------
# 脱敏
# ---------------------------------------------------------------------------
REDACTED = "<REDACTED>"
P_DOMAIN = "<DOMAIN>"
P_IP = "<IP>"
P_HOST = "<HOST>"
P_EMAIL = "<EMAIL>"

# 常见顶级域（白名单，避免把 index.php / wp-login.php 这类文件名误判成域名）
_TLD = {
    "com", "cn", "net", "org", "edu", "gov", "io", "me", "co", "info", "biz",
    "xyz", "top", "cc", "tv", "vip", "club", "site", "shop", "online", "tech",
    "dev", "app", "cloud", "link", "pro", "ltd", "group", "work", "art", "fun",
    "space", "website", "store", "asia", "mobi", "name", "wang", "ren", "xin",
    "hk", "tw", "mo", "jp", "kr", "sg", "us", "uk", "de", "fr", "ru", "au",
    "ca", "br", "in", "it", "nl", "es", "se", "no", "fi", "dk", "pl", "cz",
    "tr", "ch", "at", "be", "ie", "pt", "gr", "hu", "ro", "bg", "hr", "sk",
    "si", "ee", "lv", "lt", "ua", "by", "kz", "ir", "ae", "il", "sa", "eg",
    "za", "ma", "ke", "ng", "gh", "mx", "ar", "cl", "pe", "ve", "ec", "uy",
    "py", "bo", "nz", "ph", "th", "vn", "my", "id", "pk", "bd", "lk", "kh",
    "mm", "np", "la", "by", "am", "ge", "az", "uz", "mn",
}
_TLD_ALT = "|".join(sorted(_TLD, key=len, reverse=True))

_RE_URL = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.\-]*)://([^\s\"'<>`]+)")
_RE_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w-]+(?:\.[\w-]+)+")
_RE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?P<port>:\d{1,5})?(?![\d.])")
# IPv6：只认「完整 8 段」或「含 ::」的压缩形式，避免把 13:40:43 这类时间误脱敏；
# 端口由方括号/URL 分支处理，这里只替换地址本体
_RE_IPV6 = re.compile(
    r"(?<![\w:.\-])(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?"
    r"|::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6}"
    r")(?![\w:.])")
_RE_DOMAIN = re.compile(
    r"(?<![A-Za-z0-9_.\-])(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:" + _TLD_ALT + r")(?![A-Za-z0-9\-])(?P<port>:\d{1,5})?", re.I)
# 中文键：用户名：root / 密码 toor / 口令=xxx（必须有分隔符；值若像文件名/版本号则不动）
_RE_SECRET_CN = re.compile(
    r"(用户名|账号|账户|密码|口令|密钥|令牌|凭证|邮箱)(\s*[:：=]\s*|\s+)(?!<)"
    r"(?![\w.\-]+\.(?:php|phtml|jsp|aspx?|html?|js|json|xml|txt|zip|bak|log|ini|conf|ya?ml|md)\b)"
    r"(?![A-Za-z][\w.\-]*:\d)"
    r"([^\s，。；;、,<]{2,64})")

# 裸凭据对：仅在「含凭据关键词的行」里把 user:pass 这类成对值脱敏，
# 避免误伤 Date: Fri / Content-Type: text/html 这类 HTTP 头
_RE_CRED_CTX = re.compile(
    r"(弱口令|口令|密码|凭据|凭证|账号|用户名|credential|password|passwd|brute)",
    re.I)
_RE_BARE_PAIR = re.compile(r"\b([A-Za-z][A-Za-z0-9_.\-]{1,30}):([^\s，。；;,/<>\"'@]{2,32})")
_PROTO = {"http", "https", "ftp", "sftp", "ws", "wss", "mysql", "redis", "postgres",
          "postgresql", "mongodb", "mssql", "smb", "ldap", "smtp", "imap", "pop3",
          "ssh", "rdp", "jdbc", "telnet", "vnc", "rdp"}


def _pair_sub(m: "re.Match") -> str:
    left, right = m.group(1), m.group(2)
    if left.lower() in _PROTO or re.match(r"^\d", left):
        return m.group(0)
    if re.fullmatch(r"\d+(?:\.\d+)+", right):      # 版本号
        return m.group(0)
    if right.isdigit() and "." in left:            # IP:端口
        return m.group(0)
    return REDACTED


def _redact_cred_pairs(text: str) -> str:
    if not _RE_CRED_CTX.search(text):
        return text
    out = []
    for line in text.splitlines(True):
        if _RE_CRED_CTX.search(line):
            line = _RE_BARE_PAIR.sub(_pair_sub, line)
        out.append(line)
    return "".join(out)
# 口令 / 账号 / 令牌类键值：password=xx、user: xx、"token":"xx"
_RE_SECRET_KV = re.compile(
    r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|authorization|auth|bearer|cookie|session(?:id)?|jwt|"
    r"user(?:name)?|uname|login|account)\b(\s*[:=]\s*)([\"']?)([^\s\"',;&<>]{1,200})\3")
# 常见凭据形态：Basic/Bearer 头、JWT、36 位 UUID 之外的超长随机串
_RE_AUTH_HEAD = re.compile(r"(?i)\b(basic|bearer|digest)\s+[A-Za-z0-9._\-+/=]{8,}")
_RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")


def _red_url(m: "re.Match") -> str:
    scheme, rest = m.group(1), m.group(2)
    host, tail = rest, ""
    for sep in ("/", "?", "#"):
        i = rest.find(sep)
        if i >= 0:
            host, tail = rest[:i], rest[i:]
            break
    port = re.search(r":\d{1,5}$", host)
    keep = port.group(0) if port else ""
    if _RE_IPV4.search(host) or _RE_IPV6.search(host):
        host = _red_ip(host)
    else:
        host = P_HOST + keep
    return f"{scheme}://{host}{tail}"


def _red_ip(raw: str) -> str:
    """IP 脱敏并保留端口：1.2.3.4:8080 → <IP>:8080。"""
    m = re.search(r":\d{1,5}$", raw or "")
    return P_IP + (m.group(0) if m else "")


def _ip_sub(m: "re.Match") -> str:
    return P_IP + (m.groupdict().get("port") or "")


def _ip6_sub(m: "re.Match") -> str:
    return P_IP


def _domain_sub(m: "re.Match") -> str:
    return P_DOMAIN + (m.group("port") or "")


def redact_text(value) -> str:
    """把文本里的域名 / IP / URL 主机 / 邮箱 / 账号口令脱敏（保留端口与路径）。"""
    if value is None:
        return ""
    s = str(value)
    if not s:
        return ""
    # 先处理认证头（Basic/Bearer/JWT），再处理键值口令，避免 "Authorization: Bearer x" 只吃掉 Bearer
    s = _RE_AUTH_HEAD.sub(lambda m: f"{m.group(1)} {REDACTED}", s)
    s = _RE_JWT.sub(REDACTED, s)
    s = _RE_SECRET_KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", s)
    s = _RE_URL.sub(_red_url, s)
    s = _RE_EMAIL.sub(P_EMAIL, s)
    s = _RE_SECRET_CN.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", s)
    s = _RE_IPV4.sub(_ip_sub, s)
    s = _RE_IPV6.sub(_ip6_sub, s)
    s = _RE_DOMAIN.sub(_domain_sub, s)
    s = _redact_cred_pairs(s)
    return s


def redact_obj(obj, depth: int = 0):
    """递归脱敏 dict / list / str（深度上限防爆栈）。"""
    if depth > 6:
        return obj
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, depth + 1) for v in obj]
    return obj


def _host(raw: str) -> str:
    p = str(raw or "").strip().lower()
    p = re.sub(r"^[a-z]+://", "", p).split("/")[0].split(":")[0].rstrip(".")
    return p


_SLD = {"com.cn", "net.cn", "gov.cn", "edu.cn", "org.cn", "ac.cn",
        "co.uk", "com.hk", "com.tw", "com.au", "co.jp"}


def _registrable(host: str) -> str:
    parts = (host or "").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _SLD:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host or ""


def _fp(text: str) -> str:
    return hashlib.sha256(("ac1:" + (text or "").strip().lower()).encode("utf-8")
                          ).hexdigest()[:12]


def target_meta(raw) -> Dict:
    """目标 → 脱敏身份：类型 + 不可逆指纹 + 展示用短码（不含明文）。"""
    host = _host(raw)
    if not host:
        return {"target_fp": "", "root_fp": "", "target_kind": "other",
                "target_hint": ""}
    if _RE_IPV4.fullmatch(host) or _RE_IPV6.fullmatch(host):
        kind = "ip"
    elif "." in host and _RE_DOMAIN.fullmatch(host):
        kind = "domain"
    elif host in ("localhost", "127.0.0.1", "::1"):
        kind = "local"
    elif "." in host:
        kind = "domain"
    else:
        kind = "other"
    root = _registrable(host) if kind == "domain" else host
    fp = _fp(host)
    return {"target_fp": fp, "root_fp": _fp(root) if root else "",
            "target_kind": kind, "target_hint": fp[:8]}


# ---------------------------------------------------------------------------
# 分类（技术栈 / 漏洞类型）
# ---------------------------------------------------------------------------
_TECH_WORDS = {
    "laravel": ("laravel",), "wordpress": ("wordpress", "wp-", "wp_", "woocommerce",
                                           "xmlrpc", "wp-login"),
    "thinkphp": ("thinkphp",), "spring": ("spring", "actuator"),
    "shiro": ("shiro",), "fastjson": ("fastjson",), "struts2": ("struts",),
    "redis": ("redis",), "postgresql": ("postgres", "pgsql"),
    "mysql": ("mysql", "mariadb"), "mssql": ("mssql", "sqlserver"),
    "mongodb": ("mongo",), "elasticsearch": ("elasticsearch", "elastic"),
    "nginx": ("nginx",), "apache": ("apache", "httpd"), "tomcat": ("tomcat",),
    "iis": ("iis", "microsoft-httpapi"), "weblogic": ("weblogic",),
    "jenkins": ("jenkins",), "gitlab": ("gitlab",), "confluence": ("confluence",),
    "traefik": ("traefik",), "kubernetes": ("kubernetes", "k8s"),
    "docker": ("docker",), "php": ("php",), "java": ("java", "jsp", "jdk"),
    "nodejs": ("node.js", "express", "nodejs"), "python": ("python", "werkzeug",
                                                           "flask", "django", "gunicorn"),
    "jquery": ("jquery",), "vue": ("vue",), "react": ("react",),
    "cdn": ("cdn", "cloudflare", "akamai", "cloudfront"),
}
_VULN_WORDS = {
    "SQL 注入": ("sql injection", "sqli", "sql注入", "注入点"),
    "XSS": ("xss", "cross-site scripting", "跨站"),
    "SSRF": ("ssrf", "服务端请求伪造"),
    "命令执行": ("rce", "command injection", "命令执行", "远程代码"),
    "文件上传": ("file upload", "upload", "文件上传", "webshell"),
    "文件包含/遍历": ("lfi", "rfi", "path traversal", "目录遍历", "文件读取"),
    "反序列化": ("deserial", "反序列化", "unserialize"),
    "越权/IDOR": ("idor", "越权", "authorization bypass", "权限绕过"),
    "未授权访问": ("unauthorized", "未授权", "unauth"),
    "弱口令": ("weak password", "weak credential", "弱口令", "默认口令", "brute"),
    "信息泄露": ("info leak", "information disclosure", "信息泄露", "sensitive"),
    "CSRF": ("csrf",), "XXE": ("xxe",), "SSTI": ("ssti", "模板注入"),
    "逻辑漏洞": ("logic", "业务逻辑"),
}
_STAGE_ORDER = ["侦察", "漏洞验证", "利用与横向", "提权与持久化", "其它"]


def _hay(rec: Dict) -> str:
    parts = [rec.get("summary") or "", " ".join(rec.get("tags") or []),
             " ".join(c for c in (rec.get("tech") or [])),
             " ".join(c for c in (rec.get("vuln") or [])),
             " ".join(c for c in (rec.get("stage_set") or [])),
             " ".join(str(s.get("stage")) + " " + str(s.get("action"))
                      for s in rec.get("stages") or []),
             " ".join(str(x) for x in rec.get("lessons") or []),
             " ".join(str(f.get("title")) for f in rec.get("findings") or []),
             " ".join(str(s.get("tool")) + " " + str(s.get("summary"))
                      for s in rec.get("steps") or [])]
    return " ".join(parts).lower()


def classify(rec: Dict) -> Dict:
    """给一条链打上 技术栈 / 漏洞类型 / 阶段 分类标签。"""
    hay = _hay(rec)
    tech = [k for k, kws in _TECH_WORDS.items() if any(w in hay for w in kws)]
    vuln = [k for k, kws in _VULN_WORDS.items() if any(w in hay for w in kws)]
    stages = [str(s.get("stage")) for s in rec.get("stages") or []
              if s.get("stage") and s.get("stage") != "其它"]
    stages = [s for i, s in enumerate(stages) if s not in stages[:i]]
    return {"tech": tech[:8], "vuln": vuln[:8], "stage_set": stages[:6]}


# ---------------------------------------------------------------------------
# 存储
# ---------------------------------------------------------------------------
def _migrate_settings(raw: dict) -> dict:
    st = dict(DEFAULT_SETTINGS)
    for k in DEFAULT_SETTINGS:
        if k in raw and raw[k] is not None:
            st[k] = raw[k]
    # 旧版 memory_limit 是「保留条数」，现改为「单次注入条数」，仅作迁移参考
    if "inject_limit" not in raw and isinstance(raw.get("memory_limit"), int):
        st["inject_limit"] = max(1, min(10, raw["memory_limit"]))
    try:
        st["inject_limit"] = max(1, min(10, int(st.get("inject_limit") or 3)))
    except Exception:
        st["inject_limit"] = 3
    st["auto_review"] = bool(st.get("auto_review", True))
    st["inject_memory"] = bool(st.get("inject_memory", True))
    return st


_TEXT_FIELDS = ("summary", "note", "lessons", "next_steps", "tags")


def _migrate_record(rec: Dict) -> bool:
    """把 v1（含明文 target/scope）的旧记录就地脱敏成 v2。"""
    changed = False
    meta = None
    raw_target = rec.get("target") or rec.get("scope") or ""
    if "target_fp" not in rec:
        meta = target_meta(raw_target)
        rec.update(meta)
        changed = True
    for k in ("target", "scope", "target_label"):
        if k in rec:
            rec.pop(k, None)
            changed = True
    for k in _TEXT_FIELDS:
        if isinstance(rec.get(k), str):
            new = redact_text(rec[k])
            if new != rec[k]:
                rec[k] = new
                changed = True
        elif isinstance(rec.get(k), list):
            new = [redact_text(x) for x in rec[k]]
            if new != rec[k]:
                rec[k] = new
                changed = True
    for key in ("stages", "steps", "findings"):
        if isinstance(rec.get(key), list):
            new = redact_obj(rec[key])
            if new != rec[key]:
                rec[key] = new
                changed = True
    cls = classify(rec)
    if rec.get("tech") != cls["tech"] or rec.get("vuln") != cls["vuln"] \
            or rec.get("stage_set") != cls["stage_set"]:
        rec.update(cls)
        changed = True
    return changed


def _load() -> dict:
    global _MIGRATING
    try:
        d = json.loads(STORE.read_text(encoding="utf-8"))
    except Exception:
        d = {}
    if not isinstance(d, dict):
        d = {}
    d.setdefault("chains", [])
    d.setdefault("settings", {})
    if not isinstance(d["chains"], list):
        d["chains"] = []
    if not isinstance(d["settings"], dict):
        d["settings"] = {}
    d["settings"] = _migrate_settings(d["settings"])
    # 一次性迁移：旧数据脱敏 + 打分类标签（用重入锁避免 _load → rebuild_memory → _load 递归）
    if int(d.get("version") or 1) < SCHEMA_VERSION and not _MIGRATING:
        _MIGRATING = True
        try:
            touched = 0
            for c in d["chains"]:
                if isinstance(c, dict) and _migrate_record(c):
                    touched += 1
            d["version"] = SCHEMA_VERSION
            if touched:
                try:
                    _save(d)
                except Exception:
                    pass
                try:
                    for c in d["chains"]:
                        _write_chain_md(c)
                    rebuild_memory()
                except Exception:
                    pass
        finally:
            _MIGRATING = False
    return d


def _save(d: dict) -> dict:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    d["version"] = SCHEMA_VERSION
    STORE.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    return d


def settings() -> dict:
    return dict(_load()["settings"])


def set_settings(**kw) -> dict:
    d = _load()
    changed_limit = False
    limit_keys = ("inject_limit", "memory_limit")
    for k in DEFAULT_SETTINGS:
        if k in kw and kw[k] is not None:
            if k in limit_keys:
                try:
                    lim = max(1, min(10, int(kw[k])))
                    if lim != d["settings"].get("inject_limit"):
                        changed_limit = True
                    d["settings"]["inject_limit"] = lim
                except Exception:
                    pass
            else:
                d["settings"][k] = bool(kw[k])
    _save(d)
    if changed_limit:
        try:
            rebuild_memory()
        except Exception:
            pass
    return {"ok": True, "settings": d["settings"]}


def _next_id(chains: List[dict]) -> str:
    mx = 0
    for c in chains:
        m = re.match(r"^AC(\d+)$", str(c.get("id") or ""))
        if m:
            mx = max(mx, int(m.group(1)))
    return f"AC{mx + 1:04d}"


# ---------------------------------------------------------------------------
# 采集：把一个任务还原成「攻击链素材」（已脱敏）
# ---------------------------------------------------------------------------
def _brief_args(args) -> str:
    """工具参数只留最有信息量的部分（会被再次脱敏）。"""
    if not isinstance(args, dict):
        return redact_text(args)[:120]
    keep = ("url", "path", "host", "domain", "target", "query", "payload",
            "port", "cmd", "method", "data")
    parts = []
    for k in keep:
        v = args.get(k)
        if v in (None, ""):
            continue
        parts.append(f"{k}={str(v)[:90]}")
    if not parts:
        parts = [f"{k}={str(v)[:60]}" for k, v in list(args.items())[:4]]
    return redact_text(" ".join(parts))[:240]


def collect(task_id: str, db=None) -> Dict:
    """把一个任务的双图数据整理成攻击链素材（纯读取 + 脱敏，不改数据）。"""
    from .store import ExplorationGraph, SessionStore
    from .store.db import get_db, jload
    from .planning_todo import PlanningTodo

    db = db or get_db()
    ss = SessionStore(db)
    t = ss.get_task(task_id) or {}
    eg = ExplorationGraph(db, task_id)
    nodes = (eg.graph() or {}).get("nodes", [])

    def of(kind):
        return [n for n in nodes if n.get("kind") == kind]

    intents = of("intent")
    facts = of("fact")
    findings = of("finding")
    try:
        from .agents.auditor import Auditor
        findings = Auditor.visible(findings) or []
    except Exception:
        pass

    calls = []
    try:
        calls = db.query(
            "SELECT tool,args,status,result_summary,intent_id,started_at"
            " FROM tool_calls WHERE task_id=? ORDER BY started_at, id", (task_id,))
        for c in calls:
            c["args"] = jload(c.get("args"), {})
    except Exception:
        calls = []

    todos = []
    try:
        todos = PlanningTodo(db, task_id).steps()
    except Exception:
        todos = []

    tok = {"total": 0}
    try:
        tok = ss.task_token_total(task_id)
    except Exception:
        pass

    fact_labels = []
    for f in facts:
        d = f.get("data") or {}
        if d.get("compressed"):
            continue
        fact_labels.append(redact_text(f.get("label") or "")[:200])

    steps = []
    for i, c in enumerate(calls, 1):
        steps.append({
            "seq": i, "tool": c.get("tool") or "",
            "args": _brief_args(c.get("args")),
            "status": c.get("status") or "",
            "summary": redact_text(c.get("result_summary") or "")[:200],
        })

    raw_target = t.get("target") or ""
    meta = target_meta(raw_target)
    return {
        "task_id": task_id,
        # 明文目标只在内存里用于算指纹，绝不写入记录
        "_target_raw": raw_target,
        "target": P_DOMAIN if meta["target_kind"] == "domain" else (
            P_IP if meta["target_kind"] == "ip" else P_HOST),
        **meta,
        "mode": t.get("mode") or "SRC",
        "task_status": t.get("status") or "",
        "created_at": t.get("created_at") or time.time(),
        "config": t.get("config") or {},
        "intents": [{"label": redact_text(n.get("label")),
                     "status": n.get("status"),
                     "tool": (n.get("data") or {}).get("tool"),
                     "summary": redact_text((n.get("data") or {}).get("_summary", ""))}
                    for n in intents],
        "facts": fact_labels,
        "findings": [{"title": redact_text(n.get("label")),
                      "severity": (n.get("data") or {}).get("severity", ""),
                      "evidence": redact_text(
                          (n.get("data") or {}).get("evidence") or "")[:300],
                      "verify_status": (n.get("data") or {}).get("verify_status", ""),
                      "logic": bool((n.get("data") or {}).get("logic"))}
                     for n in findings],
        "steps": steps,
        "todos": [{"label": redact_text(s.get("label")), "status": s.get("status"),
                   "tool": s.get("tool")} for s in todos],
        "tokens": tok,
        "metrics": {"rounds": (t.get("config") or {}).get("max_rounds"),
                    "intents": len(intents), "facts": len(facts),
                    "findings": len(findings), "tool_calls": len(calls),
                    "tokens": (tok or {}).get("total", 0)},
    }


# ---------------------------------------------------------------------------
# 规则复盘（LLM 不可用/输出不可解析时的兜底）
# ---------------------------------------------------------------------------
_STAGE_RULES = [
    ("侦察", ("http", "dns", "whois", "subdomain", "dir", "fingerprint", "crawl",
              "port", "nmap", "tech", "waf")),
    ("漏洞验证", ("sql", "xss", "ssrf", "rce", "lfi", "upload", "xxe", "ssti",
                  "vuln", "logic", "idor", "csrf", "deser")),
    ("利用与横向", ("exploit", "shell", "exec", "command", "webshell", "privesc",
                    "lateral")),
]


def _stage_of(tool: str, label: str = "") -> str:
    hay = f"{tool} {label}".lower()
    for name, kws in _STAGE_RULES:
        if any(k in hay for k in kws):
            return name
    return "其它"


def rule_review(material: Dict) -> Dict:
    """不依赖 LLM 的复盘：从数据本身归纳阶段链与可用打法（输入已脱敏）。"""
    steps = material.get("steps") or []
    findings = material.get("findings") or []
    todos = material.get("todos") or []
    ok_tools = [s for s in steps if str(s.get("status")).lower() in
                ("success", "ok", "done", "200")]
    stage_map: Dict[str, List[str]] = {}
    for s in steps:
        st = _stage_of(s.get("tool") or "", s.get("summary") or "")
        stage_map.setdefault(st, [])
        if s.get("tool") and s.get("tool") not in stage_map[st]:
            stage_map[st].append(s.get("tool"))
    stages = [{"stage": k, "action": "、".join(v[:6])}
              for k, v in stage_map.items() if v]
    order = {"侦察": 0, "漏洞验证": 1, "利用与横向": 2, "其它": 3}
    stages.sort(key=lambda x: order.get(x["stage"], 9))

    lessons = []
    if ok_tools:
        tools = []
        for s in ok_tools:
            if s.get("tool") and s["tool"] not in tools:
                tools.append(s["tool"])
        lessons.append("本链有效的工具序列：" + " → ".join(tools[:8]))
    verified = [f for f in findings if f.get("verify_status") in ("verified", "已确认")]
    if verified:
        lessons.append("已实测确认的漏洞：" +
                       "；".join(f"{f.get('title')}({f.get('severity')})"
                                for f in verified[:6]))
    if findings and not verified:
        lessons.append("漏洞均为待验证结论，复用时必须先取证再上报")

    next_steps = []
    for td in todos:
        if td.get("status") in ("pending", "skipped"):
            next_steps.append(f"未完成链步骤：{td.get('label')}")
    if not findings:
        next_steps.append("本次未取得漏洞，若同源目标可优先换攻击面（接口/后台/弱口令）")
    for f in findings[:3]:
        if f.get("verify_status") not in ("verified", "已确认"):
            next_steps.append(f"补验证：{f.get('title')}")

    summary = (f"对 {material.get('target')}（{material.get('target_kind')}"
               f" #{material.get('target_hint')}）的 {material.get('mode')} 任务，"
               f"共 {len(steps)} 次工具调用、{len(material.get('intents') or [])} 个意图、"
               f"{len(findings)} 条漏洞结论；"
               + ("阶段：" + " → ".join(s["stage"] for s in stages) if stages else "阶段：信息不足"))

    tags = []
    for s in steps:
        t = s.get("tool") or ""
        if t and t not in tags:
            tags.append(t)
    return {"summary": redact_text(summary)[:800], "stages": stages[:8],
            "lessons": [redact_text(x) for x in lessons[:8]],
            "next_steps": [redact_text(x) for x in next_steps[:8]],
            "tags": [redact_text(x) for x in tags[:12]], "model": "rule"}


# ---------------------------------------------------------------------------
# 复盘落库
# ---------------------------------------------------------------------------
def _merge_stages(stages) -> List[Dict]:
    """合并同名阶段（LLM 常把同一阶段拆成多条），保持首次出现顺序。"""
    order, buckets = [], {}
    for s in stages or []:
        if not isinstance(s, dict):
            continue
        name = redact_text(s.get("stage") or "其它").strip() or "其它"
        act = redact_text(s.get("action") or "").strip()
        if name not in buckets:
            buckets[name] = []
            order.append(name)
        if act and act not in buckets[name]:
            buckets[name].append(act)
    return [{"stage": n, "action": "；".join(buckets[n])[:800]} for n in order]


def save_chain(material: Dict, review: Dict, source: str = "auto") -> Dict:
    """把复盘结果写入 attack_chains.json + 记忆文件（同任务覆盖旧链）。

    落盘前统一脱敏：域名/IP/URL 主机/账号口令 → 占位符，目标改用指纹表示。
    """
    d = _load()
    chains = d["chains"]
    tid = material.get("task_id") or ""
    cur = next((c for c in chains if c.get("task_id") == tid), None)
    ts = time.time()
    cid = cur["id"] if cur else _next_id(chains)
    meta = target_meta(material.get("_target_raw") or "")
    if not meta.get("target_fp"):
        meta = {"target_fp": material.get("target_fp") or "",
                "root_fp": material.get("root_fp") or "",
                "target_kind": material.get("target_kind") or "other",
                "target_hint": material.get("target_hint") or ""}

    rec = {
        "id": cid,
        "task_id": tid,
        **meta,
        "mode": material.get("mode") or "SRC",
        "source": source,
        "status": "reviewed",
        "created_at": (cur or {}).get("created_at") or material.get("created_at") or ts,
        "updated_at": ts,
        "summary": redact_text(review.get("summary") or "")[:2000],
        "stages": _merge_stages(review.get("stages")),
        "steps": redact_obj((material.get("steps") or [])[:120]),
        "findings": redact_obj(material.get("findings") or []),
        "lessons": redact_obj([redact_text(x) for x in (review.get("lessons") or [])]),
        "next_steps": redact_obj([redact_text(x) for x in
                                  (review.get("next_steps") or [])]),
        "tags": redact_obj([redact_text(x) for x in (review.get("tags") or [])])[:12],
        "metrics": material.get("metrics") or {},
        "model": review.get("model") or "rule",
        "note": redact_text((cur or {}).get("note") or ""),
        "memory_file": str(MEM_DIR / f"{cid}.md"),
    }
    rec.update(classify(rec))
    if cur:
        cur.clear()
        cur.update(rec)
    else:
        chains.append(rec)
    d["chains"] = chains
    _save(d)
    try:
        _write_chain_md(rec)
    except Exception:
        pass
    try:
        rebuild_memory()
    except Exception:
        pass
    return {"ok": True, "chain": _pub(rec, with_steps=True)}


# ---------------------------------------------------------------------------
# 记忆文件
# ---------------------------------------------------------------------------
def _fmt_ts(ts) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts)))
    except Exception:
        return ""


_KIND_TXT = {"domain": "域名", "ip": "IP", "local": "本机", "other": "其它"}


def _chain_md(rec: Dict) -> str:
    m = rec.get("metrics") or {}
    hint = rec.get("target_hint") or ""
    kind = _KIND_TXT.get(rec.get("target_kind") or "other", "其它")
    lines = [f"# 攻击链 {rec.get('id')} · {kind} #{hint}",
             "",
             f"- 来源任务：{rec.get('task_id')}（{rec.get('mode')} 模式）",
             f"- 生成时间：{_fmt_ts(rec.get('updated_at'))}"
             f"　来源：{'自动复盘' if rec.get('source') == 'auto' else '人工复盘'}"
             f"　推理：{'LLM' if rec.get('model') == 'llm' else '规则'}",
             f"- 目标指纹：target={rec.get('target_fp') or '-'} / root={rec.get('root_fp') or '-'}"
             f"（已脱敏，不可反推域名/IP）",
             f"- 规模：工具调用 {m.get('tool_calls', 0)}・意图 {m.get('intents', 0)}"
             f"・事实 {m.get('facts', 0)}・漏洞 {m.get('findings', 0)}"
             f"・Token {m.get('tokens', 0)}",
             f"- 分类：技术栈 {'、'.join(rec.get('tech') or []) or '—'}"
             f"｜漏洞类型 {'、'.join(rec.get('vuln') or []) or '—'}",
             "",
             "## 概述",
             rec.get("summary") or "（无）",
             ""]
    if rec.get("stages"):
        lines.append("## 攻击阶段链")
        for i, s in enumerate(rec["stages"], 1):
            lines.append(f"{i}. **{s.get('stage')}** — {s.get('action') or ''}")
        lines.append("")
    if rec.get("findings"):
        lines.append("## 漏洞结论")
        for f in rec["findings"][:20]:
            vs = f.get("verify_status") or ""
            tag = "（已实测）" if vs in ("verified", "已确认") else ""
            lines.append(f"- [{f.get('severity') or '?'}] {f.get('title')}{tag}")
        lines.append("")
    if rec.get("lessons"):
        lines.append("## 有效打法（下次可直接复用）")
        lines += [f"- {x}" for x in rec["lessons"]]
        lines.append("")
    if rec.get("next_steps"):
        lines.append("## 下一步建议 / 待补验证")
        lines += [f"- {x}" for x in rec["next_steps"]]
        lines.append("")
    if rec.get("steps"):
        lines.append("## 执行序列（节选，已脱敏）")
        for s in rec["steps"][:30]:
            lines.append(f"{s.get('seq')}. `{s.get('tool')}` {s.get('args') or ''}"
                         f" → {s.get('summary') or s.get('status') or ''}")
        lines.append("")
    if rec.get("note"):
        lines.append("## 人工备注")
        lines.append(rec["note"])
    return "\n".join(lines).strip() + "\n"


def _write_chain_md(rec: Dict):
    MEM_DIR.mkdir(parents=True, exist_ok=True)
    (MEM_DIR / f"{rec['id']}.md").write_text(_chain_md(rec), encoding="utf-8")


def _catalog_lines(chains: List[Dict]) -> List[str]:
    """分类索引（目标类型 / 技术栈 / 漏洞类型 / 阶段）。"""
    kinds: Dict[str, List[str]] = {}
    techs: Dict[str, List[str]] = {}
    vulns: Dict[str, List[str]] = {}
    stages: Dict[str, List[str]] = {}
    for c in chains:
        cid = c.get("id")
        kinds.setdefault(_KIND_TXT.get(c.get("target_kind") or "other", "其它"),
                         []).append(cid)
        for t in c.get("tech") or []:
            techs.setdefault(t, []).append(cid)
        for v in c.get("vuln") or []:
            vulns.setdefault(v, []).append(cid)
        key = " → ".join(c.get("stage_set") or []) or "—"
        stages.setdefault(key, []).append(cid)

    def block(title, mapping):
        if not mapping:
            return []
        out = [f"### {title}"]
        for k in sorted(mapping, key=lambda x: -len(mapping[x])):
            ids = mapping[k]
            out.append(f"- {k}（{len(ids)}）：{'、'.join(ids[:40])}"
                       + ("…" if len(ids) > 40 else ""))
        out.append("")
        return out

    lines = ["## 分类索引（全量，不设上限；按需检索/注入）"]
    lines += block("按目标类型", kinds)
    lines += block("按技术栈", techs)
    lines += block("按漏洞类型", vulns)
    lines += block("按攻击阶段", stages)
    return lines


def rebuild_memory(limit: int = None) -> Dict:
    """重建汇总记忆文件：分类索引 + 全量档案（不按条数截断）。"""
    d = _load()
    chains = sorted(d["chains"], key=lambda c: c.get("updated_at") or 0, reverse=True)
    lines = ["# 攻击链记忆（分类索引 + 全量档案）",
             "",
             f"> 由「攻击链复盘员」自动维护，最近更新 {_fmt_ts(time.time())}。",
             f"> 共 {len(chains)} 条链，**全量保留、不设条数上限**。",
             "> 已脱敏：不含域名 / IP / 用户名 / 口令等业务敏感数据，目标以不可逆指纹标识。",
             "> 使用方式：`GET /api/chains/catalog` 看分类目录，"
             "`POST /api/chain/memory/query` 按技术栈/漏洞类型/关键词按需检索；"
             f"任务启动时最多注入 {d['settings'].get('inject_limit', 3)} 条命中项（非全量导入）。",
             ""]
    lines += _catalog_lines(chains)
    lines += ["---", "", "## 全量档案", ""]
    for rec in chains:
        lines += [f"<!-- {rec.get('id')} -->", _chain_md(rec), ""]
    text = "\n".join(lines).strip() + "\n"
    MEM_DIR.mkdir(parents=True, exist_ok=True)
    MEM_FILE.write_text(text, encoding="utf-8")
    try:
        _MIRROR.parent.mkdir(parents=True, exist_ok=True)
        _MIRROR.write_text(text, encoding="utf-8")
    except Exception:
        pass
    return {"ok": True, "file": str(MEM_FILE), "chains": len(chains),
            "size": len(text)}


def memory_text() -> Dict:
    try:
        txt = MEM_FILE.read_text(encoding="utf-8")
    except Exception:
        txt = ""
    try:
        mtime = MEM_FILE.stat().st_mtime
    except Exception:
        mtime = 0
    return {"ok": True, "file": str(MEM_FILE), "content": txt,
            "updated_at": mtime, "mirror": str(_MIRROR)}


# ---------------------------------------------------------------------------
# 分类目录 / 按需检索
# ---------------------------------------------------------------------------
def catalog() -> Dict:
    """分类目录：目标类型 / 技术栈 / 漏洞类型 / 阶段 → 链 id 列表。"""
    d = _load()
    chains = sorted(d["chains"], key=lambda c: c.get("updated_at") or 0, reverse=True)

    def collect_map(getter):
        out: Dict[str, List[str]] = {}
        for c in chains:
            for k in getter(c):
                out.setdefault(k, []).append(c["id"])
        return [{"name": k, "count": len(v), "ids": v[:100]}
                for k, v in sorted(out.items(), key=lambda kv: -len(kv[1]))]

    return {"ok": True, "total": len(chains),
            "kind": collect_map(lambda c: [_KIND_TXT.get(c.get("target_kind") or
                                                         "other", "其它")]),
            "tech": collect_map(lambda c: c.get("tech") or []),
            "vuln": collect_map(lambda c: c.get("vuln") or []),
            "stage": collect_map(lambda c: c.get("stage_set") or []),
            "settings": d["settings"]}


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()] or ([v] if v.strip() else [])
    if isinstance(v, (list, tuple, set)):
        return [str(x) for x in v if str(x).strip()]
    return [str(v)]


def _match(rec: Dict, q: str, tech, vuln, stage, kind) -> bool:
    tech, vuln, stage = _as_list(tech), _as_list(vuln), _as_list(stage)
    if tech and not (set(tech) & set(rec.get("tech") or [])):
        return False
    if vuln and not (set(vuln) & set(rec.get("vuln") or [])):
        return False
    if stage and not (set(stage) & set(rec.get("stage_set") or [])):
        return False
    if kind and _KIND_TXT.get(rec.get("target_kind") or "other", "其它") != kind:
        return False
    if q:
        hay = _hay(rec) + " " + str(rec.get("task_id") or "").lower() \
            + " " + str(rec.get("id") or "").lower()
        for term in q.lower().split():
            if term and term not in hay:
                return False
    return True


def query_memory(q: str = "", tech=None, vuln=None, stage=None, kind=None,
                 limit: int = 10) -> Dict:
    """按需检索记忆（分类 + 关键词），返回命中的链摘要（不含敏感明文）。"""
    d = _load()
    tech = [tech] if isinstance(tech, str) and tech else (tech or [])
    vuln = [vuln] if isinstance(vuln, str) and vuln else (vuln or [])
    stage = [stage] if isinstance(stage, str) and stage else (stage or [])
    items = [c for c in d["chains"] if _match(c, q or "", tech, vuln, stage, kind)]
    items.sort(key=lambda c: c.get("updated_at") or 0, reverse=True)
    total = len(items)
    items = items[:max(1, int(limit or 10))]
    return {"ok": True, "total": total, "chains": [_pub(c) for c in items],
            "query": {"q": q, "tech": tech, "vuln": vuln, "stage": stage,
                      "kind": kind}}


# ---------------------------------------------------------------------------
# 供下一次任务参考（按需，不全量导入）
# ---------------------------------------------------------------------------
def reference_for(target: str = "", scope: str = "", query: str = "",
                  limit: int = None) -> str:
    """按需生成注入 Planner 的历史记忆文本。

    - 只挑**命中**的链：同目标指纹（+100）> 同主域指纹（+60）> 技术栈/漏洞类型交集 >
      关键词命中；无命中返回空串（不把无关记忆塞进上下文）。
    - 条数受 ``inject_limit`` 约束（默认 3），记忆本身不设上限。
    - 全部内容已脱敏，正文只出现 ``<DOMAIN>`` / ``<IP>`` / 指纹短码。
    """
    d = _load()
    if not d["settings"].get("inject_memory", True):
        return ""
    chains = d["chains"]
    if not chains:
        return ""
    limit = limit or d["settings"].get("inject_limit") or 3
    meta = target_meta(target or scope)
    terms = set()
    for w in re.split(r"[\s,;/|]+", str(query or "")):
        w = w.strip().lower()
        if len(w) >= 2:
            terms.add(w)

    def score(c):
        s = 0.0
        if meta.get("target_fp") and c.get("target_fp") == meta["target_fp"]:
            s += 100
        elif meta.get("root_fp") and c.get("root_fp") == meta["root_fp"]:
            s += 60
        hay = _hay(c)
        if terms:
            s += 8 * len(terms & set(c.get("tech") or []))
            s += 6 * len(terms & set(c.get("vuln") or []))
            s += 4 * sum(1 for t in terms if t in hay)
        return s

    ranked = [(score(c), c) for c in chains]
    picked = [(s, c) for s, c in sorted(ranked, key=lambda x: (
        x[0], x[1].get("updated_at") or 0), reverse=True) if s > 0]
    if not picked:
        return ""
    picked = picked[:max(1, int(limit))]

    lines = ["## 历史攻击链记忆（已脱敏，按匹配度取用，非全量）",
             "以下打法来自本工作台既往任务：域名/IP/账号口令已脱敏为占位符，"
             "目标以指纹标识。可复用其思路与工具序列，但**不得**直接假定结论仍成立，"
             "必须重新取证。"]
    for s, c in picked:
        kind = _KIND_TXT.get(c.get("target_kind") or "other", "其它")
        rel = ("同目标" if s >= 100 else "同主域" if s >= 60 else "相似打法")
        lines.append(f"\n### {c.get('id')}｜{kind} #{c.get('target_hint') or '-'}"
                     f"｜{rel}｜{_fmt_ts(c.get('updated_at'))}")
        if c.get("summary"):
            lines.append(f"- 概述：{str(c['summary'])[:400]}")
        if c.get("tech"):
            lines.append("- 技术栈：" + "、".join(c["tech"][:6]))
        if c.get("stages"):
            lines.append("- 阶段链：" + " → ".join(
                str(x.get("stage")) for x in c["stages"][:6]))
        for x in (c.get("lessons") or [])[:4]:
            lines.append(f"- 有效打法：{str(x)[:220]}")
        if c.get("next_steps"):
            lines.append("- 待补：" + "；".join(str(x)[:120]
                                              for x in c["next_steps"][:3]))
        fs = c.get("findings") or []
        if fs:
            lines.append("- 曾发现：" + "；".join(
                f"{f.get('title')}({f.get('severity') or '?'})" for f in fs[:4]))
    out = "\n".join(lines)
    return out[:4000]


# ---------------------------------------------------------------------------
# 列表 / 详情 / 编辑 / 删除
# ---------------------------------------------------------------------------
def _pub(rec: Dict, with_steps: bool = False) -> Dict:
    out = {k: rec.get(k) for k in
           ("id", "task_id", "target_fp", "root_fp", "target_kind", "target_hint",
            "mode", "source", "status", "created_at", "updated_at", "summary",
            "stages", "lessons", "next_steps", "tags", "tech", "vuln",
            "stage_set", "metrics", "model", "note", "memory_file")}
    out["findings"] = (rec.get("findings") or [])[:50]
    out["steps_count"] = len(rec.get("steps") or [])
    if with_steps:
        out["steps"] = rec.get("steps") or []
    return out


def list_chains(q: str = "", target: str = "", limit: int = 0,
                tech=None, vuln=None, stage=None, kind=None, fp: str = "") -> Dict:
    """清单（支持分类过滤与关键词）；``fp`` 用于按目标指纹精确筛选。"""
    d = _load()
    items = sorted(d["chains"], key=lambda c: c.get("updated_at") or 0, reverse=True)
    if fp:
        items = [c for c in items if c.get("target_fp") == fp]
    items = [c for c in items if _match(c, (q or "").strip().lower(),
                                        tech, vuln, stage, kind)]
    target = (target or "").strip().lower()
    if target:   # 兼容旧调用：按脱敏短码 / task_id 过滤（不再按明文域名）
        items = [c for c in items
                 if target in str(c.get("target_hint") or "").lower()
                 or target in str(c.get("task_id") or "").lower()]
    total = len(items)
    if limit:
        items = items[:int(limit)]
    return {"ok": True, "chains": [_pub(c) for c in items], "total": total,
            "settings": d["settings"], "memory_file": str(MEM_FILE)}


def get_chain(cid: str, with_steps: bool = True) -> Dict:
    d = _load()
    rec = next((c for c in d["chains"] if c.get("id") == cid), None)
    if not rec:
        return {"ok": False, "error": f"攻击链不存在: {cid}"}
    out = {"ok": True, "chain": _pub(rec, with_steps=with_steps)}
    try:
        out["markdown"] = (MEM_DIR / f"{cid}.md").read_text(encoding="utf-8")
    except Exception:
        out["markdown"] = _chain_md(rec)
    return out


_EDITABLE = ("summary", "lessons", "next_steps", "tags", "note")


def update_chain(cid: str, **fields) -> Dict:
    d = _load()
    rec = next((c for c in d["chains"] if c.get("id") == cid), None)
    if not rec:
        return {"ok": False, "error": f"攻击链不存在: {cid}"}
    for k in _EDITABLE:
        if k in fields and fields[k] is not None:
            v = fields[k]
            if k in ("lessons", "next_steps", "tags"):
                if isinstance(v, str):
                    v = [x.strip() for x in re.split(r"[\n;；]+", v) if x.strip()]
                rec[k] = [redact_text(str(x)) for x in v][:30]
            else:
                rec[k] = redact_text(str(v))[:4000]
    rec["updated_at"] = time.time()
    rec.update(classify(rec))
    _save(d)
    try:
        _write_chain_md(rec)
    except Exception:
        pass
    try:
        rebuild_memory()
    except Exception:
        pass
    return {"ok": True, "chain": _pub(rec)}


def delete_chains(ids: List[str]) -> Dict:
    ids = [str(i).strip() for i in (ids or []) if str(i).strip()]
    if not ids:
        return {"ok": False, "error": "缺少攻击链 id"}
    d = _load()
    before = len(d["chains"])
    keep, drop = [], []
    for c in d["chains"]:
        (drop if c.get("id") in ids else keep).append(c)
    d["chains"] = keep
    _save(d)
    for c in drop:
        try:
            p = MEM_DIR / f"{c['id']}.md"
            if p.exists():
                p.unlink()
        except Exception:
            pass
    try:
        rebuild_memory()
    except Exception:
        pass
    return {"ok": True, "deleted": before - len(keep), "remaining": len(keep)}


def stats() -> Dict:
    d = _load()
    chains = d["chains"]
    findings = sum(len(c.get("findings") or []) for c in chains)
    return {"chains": len(chains), "findings": findings,
            "settings": d["settings"], "memory_file": str(MEM_FILE),
            "last_review": max([c.get("updated_at") or 0 for c in chains] or [0]),
            "tech": len({t for c in chains for t in (c.get("tech") or [])}),
            "vuln": len({v for c in chains for v in (c.get("vuln") or [])})}
