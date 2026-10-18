"""
渗透测试报告生成（零第三方依赖）。

从双图（资产图 + 探索图）与会话存储中汇总一次任务的全部产出，
生成可直接交付的 Markdown 与可打印 HTML 报告。

用法：
    from agent6.report import build_report, render_markdown, render_html
    data = build_report(db, "T4")
    md   = render_markdown(data)
    html = render_html(data)

报告结构：
    1. 任务概览      目标/模式/范围/时间/耗时/状态
    2. 执行摘要      风险面统计 + 结论一句话
    3. 漏洞清单      按 危急>高>中>低 排序的汇总表（含修复建议）
    4. 漏洞详情      逐条展开：资产 / 证据 / 来源意图 / 相关工具调用
    5. 资产清单      按类型分组（域名/IP/端口/服务/站点/端点）
    6. 攻击链路      goal → intent → fact/finding 血缘树
    7. 执行统计      工具调用次数、成功率、Token 消耗
    8. 附录          活动时间线
"""
import time
from typing import Dict, List, Optional

from .store import AssetGraph, ExplorationGraph, SessionStore
from .store.db import jload

# ---------------------------------------------------------------- 常量
SEV_ORDER = ["危急", "高", "中", "低", "信息"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}

SEV_ALIAS = {
    "critical": "危急", "severe": "危急", "严重": "危急", "危急": "危急",
    "high": "高", "高": "高", "高危": "高",
    "medium": "中", "mid": "中", "中": "中", "中危": "中",
    "low": "低", "低": "低", "低危": "低",
    "info": "信息", "informational": "信息", "信息": "信息", "提示": "信息",
}

KIND_TXT = {
    "root_domain": "根域名", "subdomain": "子域名", "ip": "IP 地址",
    "port": "开放端口", "service": "服务", "webapp": "Web 站点", "endpoint": "接口端点",
}
ASSET_KIND_SEQ = ["root_domain", "subdomain", "ip", "port", "service", "webapp", "endpoint"]

STATUS_TXT = {
    "pending": "排队中", "running": "运行中", "done": "已完成",
    "stopped": "已停止", "failed": "失败", "blocked": "受阻",
}

# 阴性结论：Agent 试过但确认不存在问题的记录，不应计为漏洞
NEGATIVE_KEYS = ("未发现", "未检出", "不存在", "无漏洞", "无 xss", "无sqli", "无 sql",
                 "未复现", "已修复", "已过滤", "已做输出编码", "已做转义", "no vuln",
                 "not vulnerable", "not found", "false positive", "无异常")

# 关键词 -> 修复建议（按出现顺序匹配，**越具体越靠前**，先命中先返回）
REMEDIATION = [
    (("证书过期", "证书已过期", "cert_expired", "expired cert", "sec_e_cert"),
     "更换/续期有效 TLS 证书，开启自动续期（如 Let's Encrypt + certbot），并禁用过时协议（SSLv2/3、TLS 1.0/1.1）与弱套件。"),
    (("wp-json", "wp/v2/users", "用户枚举", "用户名枚举", "enumeration", "枚举"),
     "限制或关闭 REST API 用户端点（如 /wp-json/wp/v2/users），对未登录访问返回 401；"
     "前台展示改用昵称而非登录名，避免用户名成为爆破入口。"),
    (("sql", "注入", "injection", "sqli"),
     "使用参数化查询/预编译语句或 ORM，禁止拼接 SQL；对输入做严格类型与白名单校验；数据库账号遵循最小权限。"),
    (("xss", "跨站", "反射", "dom"),
     "对所有输出到页面的用户输入做上下文相关编码（HTML/JS/URL），启用 CSP，设置 HttpOnly Cookie。"),
    (("lfi", "包含", "traversal", "目录遍历", "路径穿越", "文件读取"),
     "禁止将用户输入直接拼入文件路径；使用白名单映射或 basename + 根目录拼接后校验 realpath 前缀。"),
    (("命令", "cmd", "rce", "exec", "注入"),
     "移除所有将用户输入传入 shell 的调用；改用参数数组形式的 API（subprocess 无 shell），必要时做白名单指令映射。"),
    (("上传", "upload", "文件"),
     "校验文件类型（MIME + 魔数而非扩展名）、限制大小、重命名存储；上传目录禁止脚本执行权限，存储在 Web 根目录之外。"),
    (("csrf", "跨站请求"),
     "为所有状态变更请求加入不可预测的 CSRF Token 并校验 Referer/Origin，关键操作二次确认。"),
    (("弱口令", "weak password", "默认口令", "爆破", "brute"),
     "强制复杂度与定期更换策略，接入多因素认证，对登录失败做限速与锁定告警。"),
    (("jquery", "前端库", "js 库", "javascript 库"),
     "升级前端库到官方受支持版本，通过 SRI + CSP 降低被投毒风险，并移除页面中的版本号注释。"),
    (("版本泄露", "版本信息", "版本暴露", "指纹识别", "指纹", "wordpress", "cms", "中间件",
      "server:", "x-powered-by", "过旧", "outdated", "version", "ver=", "ver:"),
     "升级组件/中间件到官方受支持版本并订阅安全公告；移除无用插件与模块，"
     "隐藏版本号与指纹特征（删除 generator 标签、隐藏 Server/X-Powered-By 响应头）。"),
    ((".env", ".git", "备份文件", "backup", "数据库泄露", "密钥泄露", "口令泄露",
      "凭据泄露", "敏感信息泄露", "信息泄露", "leak"),
     "立即轮换已泄露的密钥/口令；从 Web 可访问目录移除 .env、.git、备份与调试文件；服务端屏蔽敏感路径访问。"),
    (("目录", "dir", "列目录", "directory listing", "index of"),
     "关闭 Web 服务器的目录列表功能，并为敏感目录配置访问控制。"),
    (("端口", "port", "开放", "服务", "service"),
     "按最小暴露面原则关闭非必要端口，仅对可信来源放通管理端口（如通过 VPN/堡垒机/安全组限制来源 IP）。"),
    (("错误", "error", "异常", "stack", "栈", "debug", "调试"),
     "生产环境关闭调试模式与详细错误回显，统一错误页面，日志仅落服务端。"),
    (("权限", "越权", "idor", "privesc", "提权", "sudo", "suid"),
     "按最小权限原则收紧账号与文件权限，服务端对每个资源做归属校验（防越权），清理不必要的 SUID 与 sudo 免密规则。"),
]


def is_negative(title: str, evidence: str = "") -> bool:
    """判断该发现是否为「试过但确认没问题」的阴性结论。"""
    text = f"{title} {evidence}".lower()
    return any(k in text for k in NEGATIVE_KEYS)


def norm_sev(s) -> str:
    """把各种写法的危害级别归一到 危急/高/中/低/信息。"""
    raw = ("" if s is None else str(s)).strip().lower()
    if raw in SEV_ALIAS:
        return SEV_ALIAS[raw]
    for k, v in SEV_ALIAS.items():
        if k in raw:
            return v
    return "中" if raw == "" else ("中" if raw not in SEV_ALIAS else raw)


def advice_for(label: str, evidence: str = "") -> str:
    """
    两阶段匹配：先只用标题匹配（标题最能说明问题类型），
    未命中再带上证据匹配（证据里可能混有与结论无关的字符串，如指纹证据里的 wp-json）。
    """
    title = (label or "").lower()
    for keys, tip in REMEDIATION:
        if any(k in title for k in keys):
            return tip
    text = f"{label} {evidence}".lower()
    for keys, tip in REMEDIATION:
        if any(k in text for k in keys):
            return tip
    return "结合业务影响评估修复优先级：在测试环境复现后修复，并在上线前做回归验证与安全评审。"


def _fmt_ts(ts) -> str:
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return ""
    if ts <= 0:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _fmt_dur(a, b) -> str:
    try:
        d = float(b) - float(a)
    except (TypeError, ValueError):
        return ""
    if d <= 0:
        return ""
    m, s = divmod(int(d), 60)
    h, m = divmod(m, 60)
    return f"{h} 小时 {m} 分 {s} 秒" if h else (f"{m} 分 {s} 秒" if m else f"{s} 秒")


def esc(s) -> str:
    return ("" if s is None else str(s)).replace("&", "&amp;").replace(
        "<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ---------------------------------------------------------------- 汇总
def build_report(db, task_id: str, asset_limit_per_kind: int = 60,
                 timeline_limit: int = 60) -> Dict:
    """汇总一次任务的全部产出为结构化数据（不含渲染）。"""
    ss = SessionStore(db)
    eg = ExplorationGraph(db, task_id)
    ag = AssetGraph(db)

    task = ss.get_task(task_id) or {}
    if not task:
        return {"ok": False, "error": f"任务不存在: {task_id}"}

    graph = eg.graph()
    nodes = {n["id"]: n for n in graph["nodes"]}

    # ---- 漏洞（去重：同资产同标题只保留一条，记录重复次数） ----
    raw_findings = eg.findings()
    audited_out = 0          # Auditor 剔除（重复/无证据），不计入漏洞数
    merged: Dict[str, dict] = {}
    for f in raw_findings:
        d = f.get("data") or {}
        if d.get("audit_status") in ("duplicate", "fake"):
            audited_out += 1
            continue
        sev = norm_sev(d.get("severity"))
        key = f"{sev}|{f.get('label','')}|{f.get('asset_ref') or ''}"
        if key in merged:
            merged[key]["dup"] += 1
            continue
        neg = is_negative(f.get("label") or "", d.get("evidence") or "")
        merged[key] = {
            "id": f["id"],
            "severity": "信息" if neg else sev,
            "negative": neg,
            "title": f.get("label") or "",
            "asset": f.get("asset_ref") or "",
            "evidence": (d.get("evidence") or "").strip(),
            "detail": {k: v for k, v in d.items() if k not in ("severity", "evidence")},
            # 阴性结论不需要修复建议，避免建议与结论自相矛盾
            "advice": "" if neg else advice_for(f.get("label") or "",
                                                d.get("evidence") or ""),
            "intent": _parent_intent(nodes, f),
            "tools": _related_tools(db, task_id, f["id"]),
            "dup": 1,
        }
    all_items = sorted(merged.values(),
                       key=lambda x: (x["negative"],
                                      SEV_RANK.get(x["severity"], 9), x["title"]))
    findings = [x for x in all_items if not x["negative"]]
    excluded = [x for x in all_items if x["negative"]]

    sev_count = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

    # ---- 资产（仅本任务涉及，杜绝其它任务目标串入报告） ----
    # 解析本任务探索图节点引用的资产；解析范围【限定为本任务归属的资产】
    # （first_task=本任务 或 被本任务节点锚定），避免 ref 误命中其它任务的同名资产。
    # 回退时也只取本任务资产全集，绝不取全库。
    refs = {n.get("asset_ref") for n in graph["nodes"] if n.get("asset_ref")}
    assets: List[dict] = []
    if refs:
        seen = set()
        for r in refs:
            if not r:
                continue
            row = db.query_one(
                "SELECT a.* FROM assets a WHERE (a.key=? OR a.label=?)"
                " AND (a.first_task=? OR a.id IN ("
                "SELECT asset_id FROM exploration_anchors WHERE task_id=?)) LIMIT 1",
                (r, r, task_id, task_id))
            if row and row["id"] not in seen:
                seen.add(row["id"])
                row["props"] = jload(row["props"], {})
                assets.append(row)
    if not assets:
        # 回退：本任务归属的全部资产（按归属过滤，绝不取全库）
        assets = ag.list_assets(
            limit=asset_limit_per_kind * len(ASSET_KIND_SEQ), task_id=task_id)
    by_kind: Dict[str, list] = {}
    for a in assets:
        by_kind.setdefault(a["kind"], []).append(a)

    # ---- 攻击链路：goal → intent → fact/finding ----
    chain = _build_chain(graph)

    # ---- 工具调用 / Token ----
    calls = ss.tool_calls(task_id, limit=1000)
    ok_n = len([c for c in calls if c.get("status") == "success"])
    tool_stats: Dict[str, dict] = {}
    for c in calls:
        t = tool_stats.setdefault(c.get("tool") or "unknown", {"total": 0, "ok": 0})
        t["total"] += 1
        if c.get("status") == "success":
            t["ok"] += 1
    tool_stats = dict(sorted(tool_stats.items(), key=lambda kv: -kv[1]["total"]))

    tokens = ss.task_token_total(task_id)
    events = ss.events(task_id, limit=timeline_limit)

    intents = [n for n in graph["nodes"] if n["kind"] == "intent"]
    facts = [n for n in graph["nodes"] if n["kind"] == "fact"]

    started, finished = task.get("started_at"), task.get("finished_at")
    return {
        "ok": True,
        "task": task,
        "generated_at": time.time(),
        "duration": _fmt_dur(started, finished) if finished else "",
        "started_at": _fmt_ts(started),
        "finished_at": _fmt_ts(finished),
        "status": STATUS_TXT.get(task.get("status"), task.get("status") or ""),
        "summary": {
            "findings": len(findings),
            "excluded": len(excluded),
            "audited_out": audited_out,
            "sev_count": sev_count,
            "assets": len(assets),
            "intents_done": len([i for i in intents if i.get("status") == "done"]),
            "intents_total": len(intents),
            "facts": len(facts),
            "tool_calls": len(calls),
            "tool_ok": ok_n,
            "tokens": tokens.get("total", 0),
        },
        "findings": findings,
        "excluded": excluded,
        "assets_by_kind": by_kind,
        "chain": chain,
        "tool_stats": tool_stats,
        "tokens": tokens,
        "events": events,
    }


def _parent_intent(nodes: Dict[str, dict], node: dict) -> str:
    """沿 parent_id 向上找到最近的 intent 标签。"""
    cur, seen = node, set()
    while cur and cur.get("id") not in seen:
        seen.add(cur.get("id"))
        if cur.get("kind") == "intent":
            return cur.get("label") or ""
        pid = cur.get("parent_id") or (cur.get("data") or {}).get("parent_id")
        cur = nodes.get(pid) if pid else None
    return ""


def _related_tools(db, task_id: str, node_id: str, limit: int = 5) -> List[dict]:
    rows = db.query(
        "SELECT tool, status, result_summary FROM tool_calls"
        " WHERE task_id=? AND intent_id=? ORDER BY started_at LIMIT ?",
        (task_id, node_id, limit))
    return [{"tool": r["tool"], "status": r["status"],
             "summary": (r.get("result_summary") or "")[:200]} for r in rows]


def _build_chain(graph: Dict[str, list]) -> List[dict]:
    """goal → intent →(fact|finding) 的三级血缘树。"""
    nodes = {n["id"]: n for n in graph["nodes"]}
    goals = [n for n in graph["nodes"] if n["kind"] == "goal"]
    intents = [n for n in graph["nodes"] if n["kind"] == "intent"]
    out = []
    for g in goals or [{"id": None, "label": "任务目标"}]:
        item = {"goal": g.get("label") or "", "intents": []}
        for i in intents:
            children = [n for n in graph["nodes"]
                        if n.get("parent_id") == i["id"]
                        and n["kind"] in ("fact", "finding")]
            if not children:
                continue
            item["intents"].append({
                "label": i.get("label") or "",
                "status": i.get("status") or "",
                "children": [{"kind": c["kind"], "label": c.get("label") or "",
                              "severity": norm_sev((c.get("data") or {}).get("severity"))
                              if c["kind"] == "finding" else ""}
                             for c in children],
            })
        out.append(item)
    return out


# ---------------------------------------------------------------- Markdown
def render_markdown(d: Dict) -> str:
    if not d.get("ok"):
        return f"# 报告生成失败\n\n{d.get('error')}\n"
    t, s = d["task"], d["summary"]
    L = []
    L.append(f"# 渗透测试报告 · {t.get('target','')}")
    L.append("")
    L.append(f"> 任务 `{t.get('id')}`　|　生成时间：{_fmt_ts(d['generated_at'])}")
    L.append("")
    L.append("## 一、任务概览")
    L.append("")
    L.append("| 项目 | 内容 |")
    L.append("|---|---|")
    L.append(f"| 任务 ID | `{t.get('id')}` |")
    L.append(f"| 目标 | {t.get('target','')} |")
    L.append(f"| 模式 | {t.get('mode','')} |")
    L.append(f"| 范围 | {t.get('scope') or '（未限定）'} |")
    L.append(f"| 状态 | {d['status']} |")
    L.append(f"| 开始时间 | {d['started_at'] or '-'} |")
    L.append(f"| 结束时间 | {d['finished_at'] or '-'} |")
    if d["duration"]:
        L.append(f"| 耗时 | {d['duration']} |")
    L.append(f"| Token 消耗 | {s['tokens']} |")
    L.append("")

    L.append("## 二、执行摘要")
    L.append("")
    top = [f"{k}危 {v} 个" for k, v in s["sev_count"].items() if v and k != "信息"]
    L.append(f"本次任务共发现 **{s['findings']}** 个问题"
             + (f"（{'、'.join(top)}）" if top else "")
             + f"，覆盖资产 **{s['assets']}** 个，"
             + f"执行攻击意图 {s['intents_done']}/{s['intents_total']} 个，"
             + f"沉淀事实 {s['facts']} 条，工具调用 {s['tool_calls']} 次"
             + (f"（成功 {s['tool_ok']} 次）。" if s["tool_calls"] else "。"))
    if s.get("excluded"):
        L.append("")
        L.append(f"另有 **{s['excluded']}** 项攻击面经测试确认**不存在**问题（阴性结论），"
                 "已单列在第六节，不计入漏洞数。")
    if s.get("audited_out"):
        L.append(f"Auditor 审核剔除 **{s['audited_out']}** 条重复/无证据记录，"
                 "不计入漏洞数（原始记录保留在探索图中可追溯）。")
    L.append("")
    if not s["findings"]:
        L.append("未发现可利用的高危问题，建议结合人工复核与业务场景做进一步验证。")
        L.append("")

    L.append("## 三、漏洞清单")
    L.append("")
    if not d["findings"]:
        L.append("本次任务未发现漏洞。")
        L.append("")
    else:
        L.append("| # | 危害级别 | 问题 | 受影响资产 | 修复建议 |")
        L.append("|---|---|---|---|---|")
        for i, f in enumerate(d["findings"], 1):
            L.append(f"| {i} | {f['severity']} | {f['title']} | "
                     f"`{f['asset'] or '-'}` | {f['advice']} |")
        L.append("")

        L.append("## 四、漏洞详情")
        L.append("")
        for i, f in enumerate(d["findings"], 1):
            L.append(f"### {i}. [{f['severity']}] {f['title']}")
            L.append("")
            L.append(f"- **受影响资产**：`{f['asset'] or '-'}`")
            if f["dup"] > 1:
                L.append(f"- **重复命中**：{f['dup']} 次（已合并）")
            if f["intent"]:
                L.append(f"- **来源意图**：{f['intent']}")
            L.append(f"- **证据**：{f['evidence'] or '（无）'}")
            for k, v in (f["detail"] or {}).items():
                L.append(f"- **{k}**：{v}")
            if f["tools"]:
                L.append("- **相关工具调用**："
                         + "；".join(f"{x['tool']}({x['status']})" for x in f["tools"]))
            L.append(f"- **修复建议**：{f['advice']}")
            L.append("")

    if d.get("excluded"):
        L.append("## 五、已排除的攻击面（阴性结论）")
        L.append("")
        L.append("以下项目已实际测试，结论为「未发现可利用问题」，列出以证明覆盖面。")
        L.append("")
        L.append("| # | 测试项 | 资产 | 结论依据 |")
        L.append("|---|---|---|---|")
        for i, f in enumerate(d["excluded"], 1):
            L.append(f"| {i} | {f['title']} | `{f['asset'] or '-'}` | {f['evidence'] or '（无）'} |")
        L.append("")

    L.append("## 六、资产清单")
    L.append("")
    for kind in ASSET_KIND_SEQ:
        items = d["assets_by_kind"].get(kind) or []
        if not items:
            continue
        L.append(f"### {KIND_TXT.get(kind, kind)}（{len(items)}）")
        L.append("")
        for a in items[:60]:
            extra = ""
            p = a.get("props") or {}
            if p.get("service"):
                extra = f"（{p['service']}{('/' + p['version']) if p.get('version') else ''}）"
            L.append(f"- `{a['label']}`{extra}")
        L.append("")

    L.append("## 七、攻击链路")
    L.append("")
    if not d["chain"] or not any(c["intents"] for c in d["chain"]):
        L.append("（无血缘记录）")
        L.append("")
    else:
        for c in d["chain"]:
            L.append(f"- **目标**：{c['goal']}")
            for i in c["intents"]:
                mark = "✓" if i["status"] == "done" else "○"
                L.append(f"  - {mark} {i['label']}")
                for ch in i["children"]:
                    tag = f"[{ch['severity']}] " if ch["severity"] else ""
                    ktxt = "漏洞" if ch["kind"] == "finding" else "事实"
                    L.append(f"    - （{ktxt}）{tag}{ch['label']}")
            L.append("")

    L.append("## 八、执行统计")
    L.append("")
    if d["tool_stats"]:
        L.append("| 工具 | 调用次数 | 成功 |")
        L.append("|---|---|---|")
        for k, v in d["tool_stats"].items():
            L.append(f"| {k} | {v['total']} | {v['ok']} |")
        L.append("")
    tok = d["tokens"]
    L.append(f"Token 消耗：提示 {tok.get('prompt',0)} / 补全 {tok.get('completion',0)} "
             f"/ 合计 **{tok.get('total',0)}**")
    L.append("")

    L.append("## 九、附录 · 活动时间线")
    L.append("")
    if not d["events"]:
        L.append("（无活动记录）")
    else:
        for e in d["events"][:60]:
            L.append(f"- `{_fmt_ts(e.get('ts'))}` **{e.get('actor','system')}** "
                     f"[{e.get('type','')}] {e.get('message','')}")
    L.append("")
    L.append("---")
    L.append("")
    L.append("_本报告由自主渗透测试工作台自动生成，所有结论均来自已记录的证据；"
             "请在授权范围内使用，并人工复核后修复。_")
    return "\n".join(L)


# ---------------------------------------------------------------- HTML
def render_html(d: Dict) -> str:
    if not d.get("ok"):
        return (f"<!doctype html><meta charset='utf-8'><title>报告生成失败</title>"
                f"<body style='font-family:sans-serif;padding:40px'>"
                f"<h1>报告生成失败</h1><p>{esc(d.get('error'))}</p></body>")
    t, s = d["task"], d["summary"]

    sev_badges = "".join(
        f"<span class='badge s-{esc(k)}'>{esc(k)} {v}</span>"
        for k, v in s["sev_count"].items() if v)

    rows = "".join(
        f"<tr><td>{i}</td><td><span class='sev {esc(f['severity'])}'>{esc(f['severity'])}</span></td>"
        f"<td><b>{esc(f['title'])}</b></td><td><code>{esc(f['asset'] or '-')}</code></td>"
        f"<td class='evi'>{esc(f['evidence'] or '（无）')}</td>"
        f"<td class='adv'>{esc(f['advice'])}</td></tr>"
        for i, f in enumerate(d["findings"], 1)) or \
        "<tr><td colspan='6' class='empty'>本次任务未发现漏洞</td></tr>"

    det = "".join(f"""
    <div class="finding">
      <h3><span class="sev {esc(f['severity'])}">{esc(f['severity'])}</span> {esc(f['title'])}
          <span class="dup">{('重复 ' + str(f['dup']) + ' 次') if f['dup'] > 1 else ''}</span></h3>
      <div class="meta">
        <div><span>受影响资产</span><code>{esc(f['asset'] or '-')}</code></div>
        {('<div><span>来源意图</span>' + esc(f['intent']) + '</div>') if f['intent'] else ''}
        {('<div><span>相关工具</span>' + esc('；'.join(x['tool'] + '(' + x['status'] + ')' for x in f['tools'])) + '</div>') if f['tools'] else ''}
      </div>
      <div class="block"><div class="lb">证据</div><pre>{esc(f['evidence'] or '（无）')}</pre></div>
      <div class="block"><div class="lb">修复建议</div><p>{esc(f['advice'])}</p></div>
    </div>""" for f in d["findings"]) or "<p class='empty'>本次任务未发现漏洞。</p>"

    assets_html = ""
    for kind in ASSET_KIND_SEQ:
        items = d["assets_by_kind"].get(kind) or []
        if not items:
            continue
        lis = "".join(f"<li><code>{esc(a['label'])}</code>{esc(extra(a))}</li>"
                      for a in items[:60])
        assets_html += (f"<div class='grp'><h4>{esc(KIND_TXT.get(kind, kind))}"
                        f"<span class='n'>{len(items)}</span></h4><ul>{lis}</ul></div>")

    chain_html = ""
    for c in d["chain"]:
        if not c["intents"]:
            continue
        inner = ""
        for i in c["intents"]:
            mark = "✓" if i["status"] == "done" else "○"
            kids = "".join(
                f"<li class='{ch['kind']}'>"
                f"{('<span class=\"sev ' + esc(ch['severity']) + '\">' + esc(ch['severity']) + '</span>') if ch['severity'] else ''}"
                f"{esc(ch['label'])}</li>" for ch in i["children"])
            inner += (f"<li><span class='mk'>{mark}</span>{esc(i['label'])}"
                      f"<ul class='kids'>{kids}</ul></li>")
        chain_html += f"<div class='goal'><b>{esc(c['goal'])}</b><ul>{inner}</ul></div>"
    if not chain_html:
        chain_html = "<p class='empty'>（无血缘记录）</p>"

    tool_rows = "".join(f"<tr><td><code>{esc(k)}</code></td><td>{v['total']}</td><td>{v['ok']}</td></tr>"
                        for k, v in d["tool_stats"].items()) or \
                "<tr><td colspan='3' class='empty'>无工具调用记录</td></tr>"

    tok = d["tokens"]
    timeline = "".join(
        f"<li><span class='t'>{esc(_fmt_ts(e.get('ts')))}</span>"
        f"<span class='a'>{esc(e.get('actor','system'))}</span>"
        f"<span class='p'>{esc(e.get('type',''))}</span>{esc(e.get('message',''))}</li>"
        for e in d["events"][:60]) or "<li class='empty'>（无活动记录）</li>"

    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>渗透测试报告 · {esc(t.get('target',''))}</title>
<style>
:root{{--bd:#e5e7eb;--mut:#6b7280;--bg:#f8fafc}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:#111827;
  font:14px/1.7 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}}
.wrap{{max-width:1080px;margin:0 auto;padding:32px 24px 64px}}
header.rp{{background:#fff;border:1px solid var(--bd);border-radius:12px;padding:24px 26px}}
header.rp h1{{margin:0 0 6px;font-size:24px}}
header.rp .sub{{color:var(--mut);font-size:13px}}
.kv{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px 22px;margin-top:18px}}
.kv div{{display:flex;gap:8px;font-size:13px}}
.kv span{{color:var(--mut);min-width:72px}}
section{{background:#fff;border:1px solid var(--bd);border-radius:12px;
  padding:20px 26px;margin-top:18px}}
h2{{font-size:17px;margin:0 0 14px;padding-bottom:10px;border-bottom:1px solid var(--bd)}}
h3{{font-size:15px;margin:0 0 10px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{border:1px solid var(--bd);padding:8px 10px;text-align:left;vertical-align:top}}
th{{background:#f1f5f9;font-weight:600}}
td.evi,td.adv{{color:#374151;font-size:12.5px}}
.empty{{color:var(--mut);text-align:center;padding:14px}}
code{{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:12.5px;word-break:break-all}}
.badge{{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;
  margin-right:6px;border:1px solid var(--bd);background:#f1f5f9}}
.sev{{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;
  color:#fff;background:#6b7280}}
.sev.危急{{background:#b91c1c}} .sev.高{{background:#dc2626}}
.sev.中{{background:#d97706}} .sev.低{{background:#2563eb}} .sev.信息{{background:#64748b}}
.finding{{border:1px solid var(--bd);border-radius:10px;padding:16px 18px;margin-bottom:14px}}
.finding h3{{display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.dup{{color:var(--mut);font-size:12px;font-weight:400}}
.meta{{color:var(--mut);font-size:12.5px;margin:6px 0 10px}}
.meta div{{margin:2px 0}}
.block{{margin-top:8px}}
.lb{{font-size:12px;color:var(--mut);margin-bottom:4px}}
pre{{background:#0f172a;color:#e2e8f0;padding:12px 14px;border-radius:8px;
  overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:12.5px;margin:0}}
.block p{{margin:0}}
.grp{{margin-bottom:14px}} .grp h4{{margin:0 0 6px;font-size:14px}}
.grp .n{{color:var(--mut);font-weight:400;font-size:12px;margin-left:6px}}
.grp ul{{margin:0;padding-left:20px}} .grp li{{font-size:13px}}
.goal{{margin-bottom:12px}} .goal ul{{margin:6px 0;padding-left:20px}}
.kids{{padding-left:18px;color:#374151}}
.mk{{color:#16a34a;margin-right:6px}}
li.finding{{color:#b91c1c}}
.timeline{{list-style:none;margin:0;padding:0;font-size:13px}}
.timeline li{{padding:5px 0;border-bottom:1px dashed var(--bd);display:flex;gap:10px}}
.timeline .t{{color:var(--mut);font-size:12px;min-width:140px}}
.timeline .a{{color:#2563eb;min-width:70px;font-size:12px}}
.timeline .p{{background:#f1f5f9;border-radius:4px;padding:0 6px;font-size:11.5px;color:#475569;height:19px}}
footer{{color:var(--mut);font-size:12px;text-align:center;margin-top:22px}}
@media print{{body{{background:#fff}} section,header.rp{{border:none;box-shadow:none}}
  .wrap{{max-width:none;padding:0}}}}
</style></head>
<body><div class="wrap">
<header class="rp">
  <h1>渗透测试报告 · {esc(t.get('target',''))}</h1>
  <div class="sub">任务 <code>{esc(t.get('id'))}</code> · 生成于 {esc(_fmt_ts(d['generated_at']))} · 自主渗透测试工作台</div>
  <div class="kv">
    <div><span>目标</span>{esc(t.get('target',''))}</div>
    <div><span>模式</span>{esc(t.get('mode',''))}</div>
    <div><span>范围</span>{esc(t.get('scope') or '（未限定）')}</div>
    <div><span>状态</span>{esc(d['status'])}</div>
    <div><span>开始</span>{esc(d['started_at'] or '-')}</div>
    <div><span>结束</span>{esc(d['finished_at'] or '-')}</div>
    {(('<div><span>耗时</span>' + esc(d['duration']) + '</div>') if d['duration'] else '')}
    <div><span>Token</span>{esc(s['tokens'])}</div>
  </div>
</header>

<section><h2>执行摘要</h2>
  <div style="margin-bottom:10px">{sev_badges or '<span class="badge">无漏洞发现</span>'}</div>
  <p style="margin:0">本次任务共发现 <b>{esc(s['findings'])}</b> 个问题，覆盖资产
    <b>{esc(s['assets'])}</b> 个，执行攻击意图
    <b>{esc(s['intents_done'])}/{esc(s['intents_total'])}</b> 个，沉淀事实
    <b>{esc(s['facts'])}</b> 条，工具调用 <b>{esc(s['tool_calls'])}</b> 次。</p>
  {(('<p style="margin:8px 0 0;color:#6b7280;font-size:13px">另有 <b>' + esc(s['excluded'])
     + '</b> 项攻击面经测试确认不存在问题（阴性结论），已单列于后，不计入漏洞数。</p>')
    if s.get('excluded') else '')}
</section>

<section><h2>漏洞清单</h2>
  <table><thead><tr><th style="width:38px">#</th><th style="width:74px">级别</th>
    <th style="width:24%">问题</th><th style="width:20%">资产</th>
    <th style="width:24%">证据</th><th>修复建议</th></tr></thead>
  <tbody>{rows}</tbody></table>
</section>

<section><h2>漏洞详情</h2>{det}</section>

{('<section><h2>已排除的攻击面（阴性结论）</h2>'
  '<p style="margin:0 0 10px;color:#6b7280;font-size:13px">'
  '以下项目已实际测试，结论为「未发现可利用问题」，列出以证明覆盖面，不计入漏洞数。</p>'
  '<table><thead><tr><th style="width:38px">#</th><th style="width:28%">测试项</th>'
  '<th style="width:22%">资产</th><th>结论依据</th></tr></thead><tbody>'
  + "".join(f"<tr><td>{i}</td><td>{esc(f['title'])}</td>"
            f"<td><code>{esc(f['asset'] or '-')}</code></td>"
            f"<td class='evi'>{esc(f['evidence'] or '（无）')}</td></tr>"
            for i, f in enumerate(d.get('excluded') or [], 1))
  + '</tbody></table></section>') if d.get('excluded') else ''}

<section><h2>资产清单</h2>{assets_html or '<p class="empty">（无资产记录）</p>'}</section>

<section><h2>攻击链路</h2>{chain_html}</section>

<section><h2>执行统计</h2>
  <table style="max-width:420px"><thead><tr><th>工具</th><th>调用</th><th>成功</th></tr></thead>
  <tbody>{tool_rows}</tbody></table>
  <p style="margin:12px 0 0;color:#374151">Token 消耗：提示 {esc(tok.get('prompt',0))} /
    补全 {esc(tok.get('completion',0))} / 合计 <b>{esc(tok.get('total',0))}</b></p>
</section>

<section><h2>活动时间线</h2><ul class="timeline">{timeline}</ul></section>

<footer>本报告由自主渗透测试工作台自动生成，结论均来自已记录证据；请在授权范围内使用并人工复核后修复。</footer>
</div></body></html>"""


def extra(a: dict) -> str:
    p = a.get("props") or {}
    if p.get("service"):
        v = p.get("version")
        return f"（{p['service']}{('/' + v) if v else ''}）"
    return ""


# ---------------------------------------------------------------- 便捷入口
def task_report(task_id: str, fmt: str = "md") -> Dict:
    """按任务 ID 直接取报告（内部自行取库连接）。"""
    from .store.db import get_db
    d = build_report(get_db(), task_id)
    if not d.get("ok"):
        return {"ok": False, "error": d.get("error"), "content": ""}
    if fmt == "html":
        content = render_html(d)
    elif fmt == "json":
        content = d
    else:
        content = render_markdown(d)
    return {"ok": True, "format": fmt, "content": content, "data": d}
