"""
业务逻辑漏洞专项智能体（LogicAgent）。

在主 Agent 完成**信息搜集**（资产测绘 / 指纹识别 / 接口发现）之后介入，与主 Agent
协同：主 Agent 负责「技术栈漏洞」，本 Agent 负责「业务逻辑漏洞」。

工作流（五步）：
1. **攻击面收集**：从资产图取本任务的 webapp / endpoint，作为逻辑测试入口。
2. **动态分析**：抓取页面（复用 ToolRegistry 的 http 工具），解析链接 / 表单 /
   参数 / JS，抽取可能的 API 接口并写回资产图（endpoint）。
3. **逻辑推理**：LLM 依据页面服务内容（标题 / 表单字段 / 参数 / 接口命名）推理
   可能的逻辑漏洞——零元购 / 价格篡改、垂直与水平越权、IDOR、竞态、批量赋值、
   支付与优惠券绕过、验证码绕过、订单遍历等；LLM 不可用时按关键词规则降级。
4. **测试验证**：逐条假设调用 logic_vuln skill 做基线对比式实测
   （垂直越权 / IDOR / 价格篡改 / 批量赋值 / 验证码复用），默认只读探测，
   `allow_write=True` 才执行状态变更类验证；**只有实测确认的假设才写入 findings**，
   未验证的仅留痕在事件与 summary（dropped_unverified），不再「猜测即上报」。
5. **写回**：已验证的以 finding 写回探索图（data.logic=True、verify_status=
   "verified"、附 POC 与基线对比证据），供「发现」页与漏洞优化智能体复用。

设计约定：零新增第三方依赖；只读、无害；找不到可测页面时明确返回空结果而非臆造。
"""
import json
import re
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from .store import AssetGraph, ExplorationGraph
from .store.db import get_db, jdump

_URL_RE = re.compile(r"https?://[^\s'\"<>)\]}]+", re.I)
_HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#][^"']*)["']""", re.I)
_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
_ACTION_RE = re.compile(r"""<form[^>]*?(?:action\s*=\s*["']([^"']*)["'][^>]*?)?>""", re.I)
_FORM_RE = re.compile(r"<form\b.*?</form>", re.I | re.S)
_INPUT_RE = re.compile(r"""<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*>""", re.I)
_NAME_RE = re.compile(r"""name\s*=\s*["']([^"']+)["']""", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_JSAPI_RE = re.compile(r"""["'`]((?:https?://[^"'`\s]+)?/[A-Za-z0-9_\-./]*(?:api|ajax|json|action|do|service|rest|graphql|pay|order|user|login|upload)[A-Za-z0-9_\-./]*(?:\?[^"'`\s]*)?)["'`]""", re.I)
_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")

# ---- 逻辑漏洞线索关键词（规则兜底 + 提示 LLM 关注点）----
_LOGIC_HINTS = [
    ("价格篡改 / 零元购", ("price", "amount", "total", "money", "价格", "金额", "总额",
                          "支付", "pay", "order", "订单", "cart", "购物车", "结算",
                          "discount", "折扣", "优惠", "coupon", "券", "积分", "point"),
     "高", "修改提交的价格 / 数量 / 优惠参数，观察实付金额是否随客户端可改而变。"),
    ("越权（水平 / IDOR）", ("user_id", "uid", "account", "member", "订单号", "order_id",
                            "orderid", "id=", "编号", "owner", "customer"),
     "高", "遍历 id 类参数，用 A 账号令牌访问 B 账号资源，观察是否返回他人数据。"),
    ("越权（垂直）", ("admin", "manage", "后台", "管理", "role", "permission", "is_admin",
                     "superuser", "grant", "设置"),
     "危急", "以低权限账号直接请求管理接口 / 页，观察是否放行。"),
    ("条件竞争（竞态）", ("submit", "redeem", "领取", "抽奖", "秒杀", "flash", "seckill",
                        "withdraw", "提现", "transfer", "转账"),
     "高", "并发重复提交同一业务请求，观察是否多次成功（超发 / 重复领取）。"),
    ("批量赋值 / 参数注入", ("register", "注册", "profile", "资料", "update", "编辑",
                            "role", "level", "vip", "balance", "余额"),
     "中", "在提交体里追加 role/vip/balance 等隐藏字段，观察是否被服务端接收生效。"),
    ("验证码 / 短信接口滥用", ("captcha", "verify", "验证码", "sms", "短信", "code",
                              "otp", "token"),
     "中", "观察验证码是否可复用 / 可爆破，短信接口是否限频。"),
]
_DEFAULT_TEST = ("按只读方式构造请求：先以正常流程取基线，再最小化篡改关键业务参数，"
                 "对比响应差异并记录请求 / 响应原文。")

# 规则假设 → 接口选择的类别相关关键词（挑最贴切的验证目标）
_HINT_URL_KWS = {
    "价格篡改 / 零元购": ("order", "pay", "price", "buy", "cart", "settle", "trade", "cashier"),
    "越权（水平 / IDOR）": ("user", "member", "order", "info", "detail", "account", "customer"),
    "越权（垂直）": ("admin", "manage", "console", "backend", "system", "boss"),
    "条件竞争（竞态）": ("redeem", "draw", "seckill", "withdraw", "sign", "lottery", "prize"),
    "批量赋值 / 参数注入": ("register", "profile", "update", "user", "save", "edit"),
    "验证码 / 短信接口滥用": ("sms", "captcha", "verify", "code", "send", "otp"),
}


class LogicAgent:
    """业务逻辑漏洞专项智能体。所有方法失败均返回结构化结果，不抛异常。"""

    def __init__(self, db=None, llm=None, tools=None,
                 progress: Callable[[str, str], None] = None, mode: str = "SRC"):
        self.db = db or get_db()
        self.llm = llm
        self.tools = tools
        self.progress = progress or (lambda stage, msg: None)
        self.mode = mode
        self.ag = AssetGraph(self.db)

    # ------------------------------------------------------------------
    # 基础
    # ------------------------------------------------------------------
    def _log(self, stage: str, msg: str):
        try:
            self.progress(stage, msg)
        except Exception:
            pass

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
            self._log("llm", f"LLM 不可用，逻辑推理降级为规则模式：{e}")
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

    def _chat(self, system: str, user: str, agent: str = "logic_agent",
              max_tokens: int = 2000) -> Optional[str]:
        # 「多智能体管理」可设置逻辑漏洞 Agent 的附加指令，前置到系统提示词
        try:
            from .agent_admin import prefix as _prefix
            system = _prefix("logic", system)
        except Exception:
            pass
        llm = self._get_llm()
        if not llm:
            return None
        try:
            return llm.chat([{"role": "system", "content": system},
                             {"role": "user", "content": user}],
                            agent=agent, max_tokens=max_tokens, temperature=0.2)
        except Exception as e:
            self._log("llm", f"LLM 调用失败，降级规则模式：{e}")
            return None

    # ------------------------------------------------------------------
    # 越界放行名单（与主流程口径一致：只打自己的目标）
    # ------------------------------------------------------------------
    _DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
    _IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

    @classmethod
    def _allowed_hosts(cls, target: str, scope: str = "") -> List[str]:
        hosts = set()
        for raw in (target, scope):
            for part in re.split(r"[,;\s]+", str(raw or "")):
                k = re.sub(r"^[a-z]+://", "", part.strip().lower())
                k = k.split("/")[0].split(":")[0].rstrip(".")
                if k and (cls._DOMAIN_RE.match(k) or cls._IPV4_RE.match(k)):
                    hosts.add(k)
        if not hosts:
            return []
        t = re.sub(r"^[a-z]+://", "", str(target or "").lower()).split("/")[0].split(":")[0]
        if "." in t and cls._DOMAIN_RE.match(t):
            parts = t.split(".")
            if len(parts) >= 2:
                hosts.add(".".join(parts[-2:]))
        return sorted(hosts)

    # ------------------------------------------------------------------
    # 攻击面收集
    # ------------------------------------------------------------------
    def attack_surface(self, task_id: str) -> Dict[str, Any]:
        """从资产图取本任务的 webapp / endpoint 作为逻辑测试入口。"""
        webapps, endpoints = [], []
        try:
            for a in self.ag.list_assets(kind="webapp", limit=300, task_id=task_id):
                webapps.append({"key": a["key"], "label": a["label"],
                                "props": a.get("props") or {}})
            for a in self.ag.list_assets(kind="endpoint", limit=500, task_id=task_id):
                endpoints.append({"key": a["key"], "label": a["label"],
                                  "props": a.get("props") or {}})
        except Exception as e:
            self._log("surface", f"资产读取失败：{e}")
        return {"webapps": webapps, "endpoints": endpoints}

    # ------------------------------------------------------------------
    # 动态分析：抓取 + 接口抽取
    # ------------------------------------------------------------------
    def _http(self, url: str, method: str = "GET", data: str = None,
              allowed: List[str] = None, timeout: int = 15) -> Dict[str, Any]:
        tools = self._get_tools()
        if not tools:
            return {"ok": False, "error": "工具层不可用"}
        ctx = {"source": "logic_agent"}
        if allowed:
            ctx["allowed_hosts"] = allowed
        try:
            res = tools.run("http", {"method": method, "url": url,
                                     "data": data or "", "timeout": timeout}, ctx)
        except Exception as e:
            return {"ok": False, "error": f"请求异常: {e}"}
        ok = str(res.get("status", "")) == "success"
        status_code = None
        body = ""
        headers = {}
        d = res.get("data")
        if isinstance(d, dict):
            status_code = d.get("status_code")
            body = d.get("body") or ""
            headers = d.get("headers") or {}
        if not body:
            body = res.get("response") or ""
        return {"ok": ok, "status_code": status_code, "body": body,
                "headers": headers, "error": "" if ok else str(res.get("message") or "")}

    @staticmethod
    def _text_of(html: str) -> str:
        return re.sub(r"\s+", " ", _TAG_RE.sub(" ", html or ""))[:800]

    def _page_info(self, url: str, html: str) -> Dict[str, Any]:
        title = ""
        m = _TITLE_RE.search(html or "")
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
        forms = []
        for fm in _FORM_RE.findall(html or "")[:20]:
            am = _ACTION_RE.search(fm)
            action = (am.group(1) if am and am.group(1) else "")
            method = "POST" if re.search(r'method\s*=\s*["\']?post', fm, re.I) else "GET"
            inputs = _INPUT_RE.findall(fm) + _NAME_RE.findall(fm)
            forms.append({"action": action, "method": method,
                          "fields": sorted(set(inputs))[:20]})
        links = [l for l in _HREF_RE.findall(html or "") if not l.lower().startswith(
            ("javascript:", "mailto:", "tel:"))][:40]
        return {"url": url, "title": title, "forms": forms, "links": links,
                "text": self._text_of(html)}

    def extract_endpoints(self, base: str, text: str, js: bool = False) -> List[str]:
        """从 HTML / JS 文本里抽取可能的 API 接口候选（去重、绝对化、限内域）。"""
        out: List[str] = []
        seen = set()
        base_host = urlparse(base).netloc
        for m in _JSAPI_RE.finditer(text or ""):
            raw = m.group(1).strip()
            if not raw or raw.startswith("//"):
                continue
            full = raw if raw.startswith("http") else urljoin(base, raw)
            h = urlparse(full).netloc
            if base_host and h and h != base_host:
                continue
            if full not in seen:
                seen.add(full)
                out.append(full)
            if len(out) >= 60:
                break
        return out

    def crawl(self, seed_url: str, allowed: List[str] = None,
              max_pages: int = 15, max_js: int = 6) -> Dict[str, Any]:
        """轻量动态抓取：种子页 → 内链页面 → JS，产出页面摘要与接口候选。"""
        out = {"pages": [], "endpoints": [], "errors": []}
        seed_url = (seed_url or "").strip()
        if not seed_url:
            return out
        if not seed_url.startswith("http"):
            seed_url = "http://" + seed_url
        base_host = urlparse(seed_url).netloc
        seen_urls, js_urls = set(), []

        def _internal(u: str) -> bool:
            f = urljoin(seed_url, u)
            return urlparse(f).netloc == base_host

        todo = [seed_url]
        while todo and len(out["pages"]) < max_pages:
            url = todo.pop(0)
            if url in seen_urls:
                continue
            seen_urls.add(url)
            r = self._http(url, allowed=allowed)
            if not r.get("ok"):
                out["errors"].append(f"{url}: {r.get('error')}")
                continue
            html = r.get("body") or ""
            info = self._page_info(url, html)
            info["status_code"] = r.get("status_code")
            out["pages"].append(info)
            out["endpoints"].extend(self.extract_endpoints(url, html))
            # JS 内联 + 外链
            for mm in _SCRIPT_RE.findall(html)[:20]:
                out["endpoints"].extend(self.extract_endpoints(url, mm, js=True))
            for src in _SRC_RE.findall(html)[:10]:
                full = urljoin(url, src)
                if urlparse(full).netloc == base_host and full not in js_urls:
                    js_urls.append(full)
            for l in info["links"]:
                f = urljoin(url, l)
                if _internal(f) and f not in seen_urls and len(todo) < max_pages * 3:
                    todo.append(f.split("#")[0])

        for js in js_urls[:max_js]:
            r = self._http(js, allowed=allowed)
            if r.get("ok"):
                out["endpoints"].extend(self.extract_endpoints(js, r.get("body") or "",
                                                               js=True))
        # 去重
        out["endpoints"] = sorted(set(out["endpoints"]))[:120]
        out["pages"] = [p for p in out["pages"] if p.get("status_code") not in (None,)]
        return out

    # ------------------------------------------------------------------
    # 逻辑推理
    # ------------------------------------------------------------------
    def _llm_hypotheses(self, target: str, pages: List[dict],
                        endpoints: List[str], max_n: int) -> Optional[List[dict]]:
        llm = self._get_llm()
        if not llm:
            return None
        brief_pages = []
        for p in pages[:12]:
            brief_pages.append({
                "url": p.get("url"), "title": p.get("title"),
                "forms": p.get("forms")[:6], "text": (p.get("text") or "")[:500],
            })
        system = (
            "你是**业务逻辑漏洞**渗透专家。依据下面这份「网站页面与服务内容」的抓取结果，"
            "推理该站点可能存在的**业务逻辑漏洞**（区别于 SQLi/XSS 等技术漏洞）。\n"
            "重点方向：零元购 / 价格与数量篡改、垂直越权（低权限访问管理功能）、"
            "水平越权 / IDOR（遍历他人订单或资料）、条件竞争（重复领取 / 超发）、"
            "批量赋值（隐藏字段提升 vip/role/balance）、支付与优惠券绕过、验证码 / 短信接口滥用。\n"
            "要求：\n"
            "1. 只依据给定信息推断，不要臆造不存在的页面或接口；信息不足时降低 confidence；\n"
            "2. 每个假设给出：业务场景、可验证的具体接口与参数、只读验证步骤、"
            "以及预期若成立会观察到的现象；\n"
            "3. severity 只能取 危急/高/中/低；\n"
            "4. 最多输出 " + str(max_n) + " 条，按可验证性从高到低排序。\n"
            "只输出一个 JSON 对象，不要解释文字：\n"
            "{\"hypotheses\":[{\"title\":\"零元购：结算接口可篡改单价\","
            "\"category\":\"价格篡改\",\"severity\":\"高\",\"confidence\":0.6,"
            "\"url\":\"https://x/api/order/create\",\"params\":\"price,quantity\","
            "\"evidence\":\"结算页表单存在 price 字段且提交到 /api/order/create\","
            "\"test_plan\":\"带低权限令牌把 price 改为 0.01 提交，观察订单实付金额\","
            "\"expect\":\"若成立：服务端接受客户端价格，订单金额异常\"}]}")
        user = (f"目标：{target}\n\n【抓取到的页面】\n"
                + json.dumps(brief_pages, ensure_ascii=False, indent=1)
                + "\n\n【发现的接口候选】\n" + "\n".join(endpoints[:80])
                + "\n\n请输出逻辑漏洞假设 JSON。")
        raw = self._chat(system, user, agent="logic_agent", max_tokens=2500)
        from .vuln_agent import _extract_json
        obj = _extract_json(raw or "")
        if not isinstance(obj, dict):
            return None
        hyp = obj.get("hypotheses")
        if not isinstance(hyp, list) or not hyp:
            return None
        out = []
        for h in hyp[:max_n]:
            if not isinstance(h, dict) or not h.get("title"):
                continue
            out.append({
                "title": str(h.get("title"))[:200],
                "category": str(h.get("category") or "业务逻辑")[:60],
                "severity": str(h.get("severity") or "中")[:4],
                "confidence": float(h.get("confidence") or 0.5),
                "url": str(h.get("url") or "")[:500],
                "params": str(h.get("params") or "")[:200],
                "evidence": str(h.get("evidence") or "")[:600],
                "test_plan": str(h.get("test_plan") or "")[:800],
                "expect": str(h.get("expect") or "")[:400],
                "source": "llm",
            })
        return out or None

    def _rule_hypotheses(self, pages: List[dict], endpoints: List[str],
                         max_n: int) -> List[dict]:
        """规则兜底：按页面文本 / 表单字段 / 接口名里的业务关键词生成假设。"""
        hay_parts = []
        for p in pages:
            hay_parts.append(f"{p.get('url')} {p.get('title')} {p.get('text')}")
            for fm in p.get("forms") or []:
                hay_parts.append(f"{fm.get('action')} " + " ".join(fm.get("fields") or []))
        hay = (" ".join(hay_parts) + " " + " ".join(endpoints)).lower()
        out = []
        for name, kws, sev, plan in _LOGIC_HINTS:
            hit = [k for k in kws if k in hay]
            if not hit:
                continue
            # 按类别相关关键词挑最贴切的接口，其次退回通用业务接口
            rel = _HINT_URL_KWS.get(name) or ()
            url = ""
            for e in endpoints:
                el = e.lower()
                if rel and any(k in el for k in rel):
                    url = e
                    break
            if not url:
                for e in endpoints:
                    el = e.lower()
                    if any(k in el for k in ("api", "order", "pay", "user", "login",
                                             "admin", "action", "do", "service")):
                        url = e
                        break
            out.append({
                "title": f"疑似{name}（规则识别）",
                "category": name,
                "severity": sev, "confidence": 0.4,
                "url": url, "params": ", ".join(hit[:6]),
                "evidence": f"抓取内容命中业务关键词：{', '.join(hit[:8])}",
                "test_plan": plan, "expect": _DEFAULT_TEST, "source": "rule",
            })
            if len(out) >= max_n:
                break
        return out

    # ------------------------------------------------------------------
    # 测试验证：调 logic_vuln skill 做基线对比实测
    # ------------------------------------------------------------------
    _CAT_CHECKS = (
        (("价格", "零元购", "支付", "优惠", "金额"), ("price_tamper",)),
        (("水平", "idor", "遍历", "订单"), ("idor",)),
        (("垂直", "后台", "管理", "未授权"), ("vertical_authz",)),
        (("批量赋值", "参数注入"), ("mass_assignment",)),
        (("验证码", "短信"), ("captcha_reuse",)),
    )

    @classmethod
    def _checks_for(cls, h: dict) -> List[str]:
        """按假设的类别 / 标题 / URL 选择验证检查项。"""
        hay = f"{h.get('category') or ''} {h.get('title') or ''}".lower()
        url = (h.get("url") or "").lower()
        checks: List[str] = []
        for kws, cs in cls._CAT_CHECKS:
            if any(k.lower() in hay for k in kws):
                checks.extend(cs)
        if not checks:
            if any(k in url for k in ("admin", "manage", "backend")):
                checks.append("vertical_authz")
            if re.search(r"[?&](id|uid|user_id|order_id)=\d?", url):
                checks.append("idor")
            checks.extend(("vertical_authz", "idor"))
        seen, out = set(), []
        for c in checks:
            if c not in seen:
                seen.add(c)
                out.append(c)
        return out

    @staticmethod
    def _params_obj(params_str: str, url: str) -> Dict[str, str]:
        """把假设里的 params（逗号分隔参数名 / query 串）整理为参数对象。"""
        out: Dict[str, str] = {}
        s = str(params_str or "").strip()
        if s:
            for part in re.split(r"[,;，；\s]+", s):
                if not part:
                    continue
                k, _, v = part.partition("=")
                if k:
                    out[k] = v or "1"
        q = urlparse(url or "").query
        if q:
            from urllib.parse import parse_qs
            for k, v in parse_qs(q).items():
                out.setdefault(k, v[0] if v else "1")
        return out

    def _verify(self, h: dict, allowed: List[str], cookies: str = "",
                allow_write: bool = False) -> Dict[str, Any]:
        """对一条假设执行实测。返回 {status: verified|negative|skipped, vuln, tested}。"""
        tools = self._get_tools()
        url = h.get("url") or ""
        if not tools or not url:
            return {"status": "skipped", "reason": "无可用工具或无 URL",
                    "checks": [], "tested": []}
        args = {"url": url, "method": "GET",
                "params": self._params_obj(h.get("params"), url),
                "write": bool(allow_write), "timeout": 12}
        if cookies:
            args["cookies"] = cookies
        ctx = {"source": "logic_agent"}
        if allowed:
            ctx["allowed_hosts"] = allowed
        try:
            res = tools.run("logic_vuln", args, ctx)
        except Exception as e:
            return {"status": "skipped", "reason": f"验证执行异常: {e}",
                    "checks": [], "tested": []}
        if str(res.get("status")) != "success":
            return {"status": "skipped", "reason": str(res.get("message") or "验证失败")[:200],
                    "checks": [], "tested": []}
        d = res.get("data") if isinstance(res.get("data"), dict) else {}
        vulns = d.get("vulnerabilities") or []
        tested = d.get("tested") or []
        if vulns:
            best = max(vulns, key=lambda v: float(v.get("confidence") or 0))
            return {"status": "verified", "vuln": best, "vulns": vulns,
                    "tested": tested, "checks": self._checks_for(h)}
        return {"status": "negative", "tested": tested,
                "reason": "；".join(str(t.get("detail") or "")[:120]
                                    for t in tested if t.get("detail")) or "实测未见异常",
                "checks": self._checks_for(h)}

    # ------------------------------------------------------------------
    # 写回
    # ------------------------------------------------------------------
    def _persist_endpoints(self, task_id: str, endpoints: List[str],
                           webapp_key: str = None) -> int:
        n = 0
        for e in endpoints:
            try:
                self.ag.add_endpoint(e, webapp_url=None, method="GET", task_id=task_id,
                                     props={"source": "logic_agent"})
                n += 1
            except Exception:
                continue
        return n

    def _persist_finding(self, task_id: str, h: dict, parent_id: str = None,
                         verify: Dict[str, Any] = None) -> str:
        eg = ExplorationGraph(self.db, task_id)
        from .vuln_agent import _norm_sev
        sev = _norm_sev(h.get("severity"))
        if sev == "未评级":
            sev = "中"
        data = {
            "severity": sev,
            "type": "业务逻辑 / " + (h.get("category") or "逻辑"),
            "evidence": h.get("evidence") or "",
            "logic": True,
            "hypothesis": h.get("title") or "",
            "category": h.get("category") or "",
            "confidence": h.get("confidence"),
            "url": h.get("url") or "",
            "params": h.get("params") or "",
            "test_plan": h.get("test_plan") or "",
            "expect": h.get("expect") or "",
            "verify_status": "hypothesis",       # 待验证假设
            "source": "logic_agent",
            "logic_source": h.get("source") or "llm",
        }
        poc = None
        if verify and verify.get("status") == "verified":
            v = verify.get("vuln") or {}
            data["verify_status"] = "verified"   # 实测确认后才上报
            data["verify_evidence"] = str(v.get("evidence") or "")[:600]
            data["verify_check"] = v.get("check") or ""
            data["verify_at"] = time.time()
            if v.get("confidence"):
                try:
                    data["confidence"] = max(float(data.get("confidence") or 0),
                                             float(v["confidence"]))
                except (TypeError, ValueError):
                    pass
            if v.get("severity") and _norm_sev(v.get("severity")) != "未评级":
                data["severity"] = _norm_sev(v.get("severity"))
            if data.get("url"):
                poc = {"type": "http", "method": str(v.get("method") or "GET"),
                       "url": data["url"],
                       "params": v.get("params") or {},
                       "match": "", "desc": f"业务逻辑验证（{v.get('check')}）："
                       + str(v.get("evidence") or "")[:200],
                       "source": "logic_vuln"}
        if poc:
            data["poc"] = poc
            data["poc_type"] = "http"
        nid = eg.add_finding(h.get("title") or "业务逻辑漏洞假设", data,
                             parent_id=parent_id,
                             asset_ref=(h.get("url") or None))
        return nid

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------
    def run(self, task_id: str, target: str, scope: str = "",
            allowed: List[str] = None, max_pages: int = 15,
            max_hypotheses: int = 8, allow_write: bool = False,
            cookies: str = "") -> Dict[str, Any]:
        """完整流程：攻击面 → 动态抓取 → 接口抽取 → 逻辑推理 → 实测验证 → 写回。

        只有实测确认（verified）的假设才写入 findings；
        未验证的仅留痕在事件与 summary，不作为漏洞上报。
        """
        allowed = allowed if allowed is not None else self._allowed_hosts(target, scope)
        self._log("logic", f"业务逻辑专项分析启动：target={target}")
        surface = self.attack_surface(task_id)
        webapps = surface.get("webapps") or []
        known_eps = [e["label"] for e in surface.get("endpoints") or []]

        seeds = []
        for w in webapps:
            u = w.get("label") or ""
            if u and _URL_RE.match(u):
                seeds.append(u)
        if not seeds:
            seeds = [target if str(target).startswith("http") else "http://" + str(target)]

        crawl = {"pages": [], "endpoints": [], "errors": []}
        for s in seeds[:3]:
            c = self.crawl(s, allowed=allowed, max_pages=max_pages)
            crawl["pages"].extend(c.get("pages") or [])
            crawl["endpoints"].extend(c.get("endpoints") or [])
            crawl["errors"].extend(c.get("errors") or [])
        crawl["endpoints"] = sorted(set(crawl["endpoints"]))[:120]
        self._log("logic",
                  f"动态分析完成：页面 {len(crawl['pages'])}，接口候选 "
                  f"{len(crawl['endpoints'])}，错误 {len(crawl['errors'])}")

        # 接口写回资产图（含已知接口，便于后续复用）
        new_eps = [e for e in crawl["endpoints"] if e not in known_eps]
        added = self._persist_endpoints(task_id, new_eps)

        # 逻辑推理
        self._log("logic", "推理可能的业务逻辑漏洞…")
        hyps = self._llm_hypotheses(target, crawl["pages"], crawl["endpoints"],
                                   max_hypotheses)
        source = "ai"
        if not hyps:
            hyps = self._rule_hypotheses(crawl["pages"], crawl["endpoints"],
                                         max_hypotheses)
            source = "rule"

        goal = None
        eg = ExplorationGraph(self.db, task_id)
        for n in eg.graph()["nodes"]:
            if n["kind"] == "goal":
                goal = n["id"]
                break

        # 逐条实测验证：只有 verified 才写 findings，未验证仅留痕
        self._log("logic", f"开始实测验证 {len(hyps)} 条假设（logic_vuln，"
                           f"{'含写操作' if allow_write else '只读探测'}）…")
        created, dropped = [], []
        for h in hyps:
            try:
                v = self._verify(h, allowed, cookies=cookies, allow_write=allow_write)
            except Exception as e:
                v = {"status": "skipped", "reason": f"验证异常: {e}"}
            if v.get("status") == "verified":
                try:
                    nid = self._persist_finding(task_id, h, parent_id=goal, verify=v)
                    vv = v.get("vuln") or {}
                    created.append({"id": nid, "title": h.get("title"),
                                    "severity": vv.get("severity") or h.get("severity"),
                                    "category": h.get("category"),
                                    "confidence": h.get("confidence"),
                                    "url": h.get("url"),
                                    "verify_check": vv.get("check"),
                                    "verify_evidence": (vv.get("evidence") or "")[:200]})
                    self._log("logic", f"已验证并上报：{h.get('title')}"
                                       f"（{vv.get('check')}）")
                except Exception as e:
                    self._log("logic", f"写入验证结果失败：{e}")
            else:
                dropped.append({"title": h.get("title"), "category": h.get("category"),
                                "url": h.get("url"),
                                "status": v.get("status"),
                                "reason": str(v.get("reason") or "")[:200]})
                self._log("logic", f"未通过实测验证，不上报：{h.get('title')}"
                                   f"（{str(v.get('reason') or '')[:80]}）")

        summary = {
            "ok": True, "task_id": task_id, "target": target,
            "seed": seeds[0] if seeds else "",
            "pages_crawled": len(crawl["pages"]),
            "endpoints_found": len(crawl["endpoints"]),
            "endpoints_added": added,
            "hypotheses_total": len(hyps),
            "hypotheses": created,
            "hypotheses_count": len(created),
            "verified_count": len(created),
            "dropped_unverified": dropped,
            "dropped_count": len(dropped),
            "allow_write": bool(allow_write),
            "source": source,
            "crawl_errors": crawl["errors"][:10],
        }
        self._log("logic", f"完成：假设 {len(hyps)} 条，实测确认并上报 {len(created)} 条，"
                           f"未验证不上报 {len(dropped)} 条（{source}）")

        # 事件留痕（含未验证假设的去向，避免信息丢失）
        try:
            from .store import SessionStore
            SessionStore(self.db).add_event(
                task_id, "logic",
                f"业务逻辑专项：抓取页面 {len(crawl['pages'])}，发现接口 "
                f"{len(crawl['endpoints'])}，提出假设 {len(hyps)} 条，"
                f"实测确认上报 {len(created)} 条，未验证不上报 {len(dropped)} 条（{source}）",
                "logic_agent",
                {"verified": created, "dropped_unverified": dropped,
                 "summary": summary})
        except Exception:
            pass
        return summary

    # ------------------------------------------------------------------
    # 生成验证 POC（供漏洞优化智能体复用）
    # ------------------------------------------------------------------
    def hypothesis_poc(self, node_id: str) -> Optional[Dict[str, Any]]:
        """把一条逻辑漏洞假设转成可执行的只读验证 POC（http 型）。"""
        row = self.db.query_one("SELECT id, task_id, label, data, asset_ref"
                                " FROM nodes WHERE id=?", (node_id,))
        if not row:
            return None
        from .store.db import jload
        d = jload(row["data"], {}) or {}
        url = d.get("url") or ""
        if not url:
            return {"type": "manual", "desc": "该逻辑漏洞假设缺少可访问 URL，需人工验证："
                    + (d.get("test_plan") or "")[:400], "source": "logic_agent"}
        return {"type": "http", "method": "GET", "url": url, "headers": {}, "data": "",
                "match": "",
                "desc": (d.get("test_plan") or "按业务逻辑假设进行只读验证")[:300],
                "source": "logic_agent"}
