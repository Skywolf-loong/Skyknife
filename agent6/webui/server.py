"""
WebUI 服务端：标准库 http.server，提供 JSON API + 静态仪表盘。

端点：
  GET /                          -> 仪表盘页面
  GET /api/tasks                 -> 任务列表
  GET /api/stats                 -> 全局统计
  GET /api/asset_graph           -> 全局资产图 {nodes,links}
  GET /api/task/<id>/overview    -> 任务总览(资产/漏洞/Token/事件数)
  GET /api/task/<id>/assets      -> 任务相关资产(按 kind 过滤可选 ?kind=)
  GET /api/task/<id>/findings    -> 漏洞列表
  GET /api/task/<id>/events      -> 活动流
  GET /api/task/<id>/toolcalls   -> 工具调用记录
  GET /api/task/<id>/exploration -> 探索图 {nodes,links}
  GET /api/health                -> 健康检查
  GET /api/running               -> 运行中任务 + 已装载工具数
  GET /api/asset/<id>            -> 单个资产详情（属性/双向邻居/关联漏洞）
  GET /api/task/<id>/node/<nid>  -> 探索图节点详情（父子/关系/关联资产/工具调用）
  GET /api/task/<id>/report      -> 渗透测试报告（?format=md|html|json，默认 html）

  GET /api/settings              -> 运行期配置（llm / agent），api_key 脱敏回显
  GET /api/findings              -> 跨任务漏洞发现（?task_id= / ?severity= / ?fix=）
  GET /api/finding/<node_id>     -> 单个漏洞详情（含 POC / 回显 / 人工备注 / 验证与复测历史）
  GET /api/vulns/jobs            -> 最近漏洞优化作业列表
  GET /api/vulns/job/<job_id>    -> 漏洞作业进度（一键优化 / 复测 / AI 复测）
  GET /api/traffic               -> 带流量录制的工具调用（?task_id= / ?q= 全文检索）
  GET /api/logs                  -> 系统/任务日志 events（?task_id= / ?type= / ?limit=）
  GET /api/approvals/records     -> 审批历史记录（?task_id=），源自 HumanGate 落库的 approvals 表

  POST /api/scan                 -> 从界面发起自主渗透任务（后台线程）
  POST /api/demo                 -> 灌入离线演示数据（无需 API Key）
  POST /api/task/<id>/stop       -> 停止运行中的任务
  POST /api/reload               -> 重新装载 skills
  POST /api/settings/llm         -> 保存 LLM 配置（base_url/api_key/model/temperature...）
  POST /api/settings/agent       -> 保存 Agent 配置（max_rounds/max_workers/.../require_approval）
  POST /api/chat                 -> 与 LLM 对话（不启动渗透任务），返回 {reply}
  POST /api/vulns/optimize       -> 一键优化选中漏洞（去重 + 写 POC + 验证 + AI 误报判定）
  POST /api/vulns/retest         -> 用已保存 POC 复测，回显不同即判定已修复
  POST /api/vulns/ai-retest      -> AI 复测（LLM 生成/修正 POC 并判定是否修复）
  POST /api/vulns/delete         -> 删除选中漏洞（连带清理边/锚点/POC 留痕）
  POST /api/vulns/purge          -> 一键清理误报与重复漏洞（?statuses=fake,duplicate）
  POST /api/finding/<id>/note    -> 保存人工备注（AI 生成 POC / 判误报 / 复测时参考）
  POST   /api/finding/<id>/delete-> 删除单个漏洞（兼容不支持 DELETE 的客户端）

  DELETE /api/task/<id>          -> 删除任务及其事件/工具调用/Token/探索图，并清理本任务独有资产（保留被其它任务引用的共享资产）
  DELETE /api/finding/<id>       -> 删除单个漏洞及其血缘边 / 资产锚点 / POC 留痕
  POST   /api/task/<id>/delete   -> 同上（兼容不支持 DELETE 的客户端）

  ---- 代理池 ----
  GET    /api/proxies            -> 代理池列表（含轮切配置 / 活动代理 / 检测状态，密码脱敏）
  POST   /api/proxies            -> 新增代理 {type,host,port,username,password,tags,note}
  DELETE /api/proxy/<id>         -> 删除单个代理
  POST   /api/proxy/test         -> 测试单个代理连通性 {id,check_url?}
  POST   /api/proxy/activate     -> 设为活动代理 {id}
  POST   /api/proxy/toggle       -> 启用/停用代理 {id,enabled}
  POST   /api/proxy/settings     -> 总开关 {use_proxy}
  POST   /api/proxy/import-url   -> 从 URL 批量导入 {urls:[...],default_type,tags,timeout}
  POST   /api/proxy/import-text  -> 粘贴文本批量导入 {text,default_type,tags}
  POST   /api/proxy/verify-all   -> 并发自动验证 {check_url?,timeout,max_workers}
  POST   /api/proxy/rotation     -> 自动轮切设置 {enabled,seconds}
  POST   /api/proxy/batch-delete -> 批量删除 {ids:[...]}
  POST   /api/proxy/delete-failed-> 一键删除验证失败的代理

  ---- Tor 链路出口代理 ----
  GET    /api/tor                -> Tor 配置（enabled/egress_host/egress_port/compliance_ack/compliance_text）
  POST   /api/tor                -> 保存 Tor 配置 {enabled,egress_host,egress_port,compliance_ack}（未确认合规则拒绝开启）

  ---- 统一出网模式 ----
  GET    /api/egress             -> 当前出网模式 {mode: none|pool|tor}
  POST   /api/egress             -> 设置出网模式 {mode}（tor 模式需先确认合规并启用 Tor）
  GET    /api/egress/ip          -> 当前出口 IP（https://api.ip.sb/ip，?force=1 跳过缓存）

  ---- 攻击链管理 / 攻击链记忆（数据已脱敏，记忆全量保留、按需调用） ----
  GET    /api/chains             -> 清单（?q= / ?tech= / ?vuln= / ?stage= / ?kind= / ?fp=）
  GET    /api/chains/catalog     -> 分类目录（目标类型 / 技术栈 / 漏洞类型 / 阶段）
  GET    /api/chain/<id>         -> 单条攻击链详情（含 Markdown）
  GET    /api/chain/memory       -> 汇总记忆文件内容 + 路径 + 统计
  POST   /api/chain/review       -> 复盘某任务（后台作业）{task_id, use_llm}
  POST   /api/chain/<id>/update  -> 编辑概述/打法/下一步/标签/备注（落盘前脱敏）
  POST   /api/chain/settings     -> {auto_review, inject_memory, inject_limit}
  POST   /api/chain/memory/query -> 按需检索记忆 {q, tech, vuln, stage, kind, limit}
  POST   /api/chain/memory/rebuild -> 重建汇总记忆文件（全量，无条数上限）
  POST   /api/chains/delete      -> 批量删除 {ids, confirm:true}
  DELETE /api/chain/<id>         -> 删除单条攻击链

  ---- 批量管理 ----
  POST   /api/tasks/batch-delete -> 批量删除任务 {ids:[...]}
"""
import json
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

from ..paths import WEBUI_STATIC_DIR
from ..store import AssetGraph, ExplorationGraph, SessionStore
from ..store.db import get_db, jload


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "agent6-webui/1.0"

    # ---------- 基础 ----------
    def log_message(self, fmt, *args):  # 静音
        pass

    def _send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, ctype: str, filename: str = ""):
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition",
                             f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path):
        if not path.exists():
            self.send_error(404, "Not Found")
            return
        ctype = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        if path.suffix == ".html":
            ctype = "text/html; charset=utf-8"
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # ---------- 路由 ----------
    def do_GET(self):
        try:
            self._route()
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def do_POST(self):
        try:
            self._route_post()
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def do_DELETE(self):
        try:
            self._route_delete()
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _route_delete(self):
        from . import runner
        path = urlparse(self.path).path
        # 多智能体：DELETE /api/agent/<id>
        if path.startswith("/api/agent/"):
            aid = path[len("/api/agent/"):].strip("/")
            return self._send_json(self._agent_delete(aid))
        # WebShell：DELETE /api/webshell/<id>
        if path.startswith("/api/webshell/"):
            sid = path[len("/api/webshell/"):].strip("/")
            return self._send_json(self._webshell_delete(sid))
        # 攻击链：DELETE /api/chain/<id>（只删记忆记录，不动原任务数据）
        if path.startswith("/api/chain/"):
            cid = path[len("/api/chain/"):].strip("/")
            return self._send_json(self._chain_delete(cid))
        # 代理池：DELETE /api/proxy/<id>
        if path.startswith("/api/proxy/"):
            pid = path[len("/api/proxy/"):].strip("/")
            return self._send_json(self._proxy_remove(pid))
        # DELETE /api/finding/<node_id> -> 删除单个漏洞
        if path.startswith("/api/finding/"):
            nid = path[len("/api/finding/"):].strip("/")
            if not nid:
                return self._send_json({"error": "缺少漏洞 ID"}, 400)
            return self._send_json(self._delete_findings({"ids": [nid],
                                                          "reason": "人工删除"}))
        # DELETE /api/task/<id>
        parts = path[len("/api/task/"):].split("/") if path.startswith("/api/task/") else []
        if not parts or not parts[0]:
            return self._send_json({"error": "缺少任务 ID"}, 400)
        task_id = parts[0]
        if runner.is_running(task_id):
            return self._send_json(
                {"ok": False, "error": "任务正在运行，请先停止后再删除"}, 409)
        db = get_db()
        # 取消该任务所有待审批项，避免删除后审批卡仍残留弹出
        try:
            from ..human_gate import get_gate
            get_gate().clear_task(task_id)
        except Exception:
            pass
        # 兜底：DB 仍是 running 但已无存活线程的孤儿任务，先复位再删
        t = SessionStore(db).get_task(task_id)
        if t and t.get("status") == "running":
            SessionStore(db).finish_task(task_id, "stopped")
        res = SessionStore(db).delete_task(task_id)
        code = 200 if res.get("ok") else (404 if "不存在" in str(res.get("error")) else 409)
        return self._send_json(res, code)

    # ---------- 人在环路：干预指令下发 ----------
    def _intervene(self, task_id: str, body: dict) -> dict:
        msg = (body.get("message") or "").strip()
        if not msg:
            return {"ok": False, "error": "缺少指令内容 message"}
        db = get_db()
        ss = SessionStore(db)
        if not ss.get_task(task_id):
            return {"ok": False, "error": f"任务不存在: {task_id}"}
        as_intent = bool(body.get("as_intent"))
        ss.add_event(task_id, "intervention", msg, "human",
                     {"as_intent": as_intent})
        node_id = None
        if as_intent:
            eg = ExplorationGraph(db, task_id)
            goal = None
            for n in eg.graph()["nodes"]:
                if n["kind"] == "goal":
                    goal = n["id"]
                    break
            node_id = eg.add_intent(
                msg, {"tool": None, "args": {}, "priority": "high",
                      "intervention": True}, parent_id=goal)
        return {"ok": True, "as_intent": as_intent, "node_id": node_id,
                "message": msg}

    # ---------- 流量重放 ----------
    def _replay(self, task_id: str, body: dict) -> dict:
        tool = (body.get("tool") or "").strip()
        if not tool:
            return {"ok": False, "error": "缺少 tool"}
        args = body.get("args") if isinstance(body.get("args"), dict) else {}
        try:
            from . import runner
            reg = runner.get_tools()
            res = reg.run(tool, args, {"task_id": task_id, "replay": True})
            return {"ok": True, "tool": tool, "result": res}
        except Exception as e:
            return {"ok": False, "error": f"重放失败: {e}"}

    # ---------- 配置持久化 ----------
    @staticmethod
    def _save_settings(section: str, body: dict) -> dict:
        try:
            from ..settings import public_settings, save_section
            save_section(section, body or {})
            return {"ok": True, "section": section, "settings": public_settings()}
        except Exception as e:
            return {"ok": False, "error": f"保存失败: {e}"}

    # ---------- 对话 ----------
    @staticmethod
    def _chat(body: dict) -> dict:
        """一次普通 LLM 对话；未配置 / 调用失败都返回结构化错误，不抛异常。"""
        msg = (body.get("message") or "").strip()
        if not msg:
            return {"ok": False, "error": "缺少消息内容 message"}
        task_id = (body.get("task_id") or "").strip()
        try:
            from ..llm import LLMClient
            from ..settings import llm_kwargs, load_settings
            st = load_settings()
            client = LLMClient(cfg={"llm": llm_kwargs()},
                               api_key=(st.get("llm") or {}).get("api_key") or None)
        except Exception as e:
            return {"ok": False, "error": f"LLM 配置加载失败: {e}"}

        try:
            reply = client.chat(
                [{"role": "system",
                  "content": "你是自主渗透测试平台的助手，用中文简明回答；"
                             "涉及攻击手法时仅给出授权范围内的安全测试建议。"},
                 {"role": "user", "content": msg}],
                agent="chat")
        except Exception as e:
            return {"ok": False, "error": f"LLM 调用失败: {e}"}

        # 落库，刷新后仍可在「对话」视图看到
        try:
            ss = SessionStore(get_db())
            ss.add_event(task_id, "chat", msg, "human")
            ss.add_event(task_id, "chat", reply, "assistant")
        except Exception:
            pass
        return {"ok": True, "reply": reply, "task_id": task_id}

    # ---------- 列表查询辅助（跨任务聚合） ----------
    @staticmethod
    def _task_filter(qs: dict):
        """?task_id= 出现即过滤（空串匹配「无任务」记录）；未出现则不过滤。"""
        if "task_id" not in qs:
            return "", []
        tid = (qs.get("task_id") or [""])[0]
        return " AND IFNULL(task_id,'')=?", [tid]

    @staticmethod
    def _pager(qs, default_size=20, max_size=500):
        """解析分页参数 ?page= &page_size=，返回 (page, size, offset)。"""
        try:
            page = max(1, int((qs.get("page") or ["1"])[0] or 1))
        except Exception:
            page = 1
        try:
            size = min(max_size, max(1, int((qs.get("page_size") or [str(default_size)])[0]
                                            or default_size)))
        except Exception:
            size = default_size
        return page, size, (page - 1) * size

    def _findings_all(self, db, qs) -> dict:
        sev = ((qs.get("severity") or [""])[0] or "").strip()
        where, params = self._task_filter(qs)
        rows = db.query(
            "SELECT id, task_id, label, data, status, asset_ref, created_at, updated_at"
            " FROM nodes WHERE kind='finding'" + where +
            " ORDER BY created_at DESC LIMIT 1000", params)
        out = []
        for r in rows:
            d = jload(r["data"], {}) or {}
            poc = d.get("poc") if isinstance(d.get("poc"), dict) else None
            echo = str(d.get("poc_echo") or d.get("last_echo") or "")
            out.append({
                "id": r["id"], "node_id": r["id"], "task_id": r["task_id"],
                "source_task": r["task_id"],
                "title": r["label"],
                "severity": d.get("severity") or d.get("level") or "",
                "severity_source": d.get("severity_source") or "",
                "severity_reason": str(d.get("severity_reason") or "")[:300],
                "severity_prev": d.get("severity_prev") or "",
                "severity_locked": bool(d.get("severity_locked")),
                "type": d.get("type") or d.get("vuln_type") or "",
                "evidence": d.get("evidence") or "",
                # 业务逻辑专项标记
                "logic": bool(d.get("logic")),
                "logic_category": d.get("category") or "",
                "test_plan": str(d.get("test_plan") or "")[:400],
                "confidence": d.get("confidence"),
                "source": d.get("source") or "",
                "asset_ref": r["asset_ref"], "status": r["status"],
                "created_at": r["created_at"], "updated_at": r["updated_at"],
                "human_note": str(d.get("human_note") or "")[:200],
                # ---- 漏洞优化智能体（VulnAgent）相关 ----
                "has_poc": bool(poc),
                "poc_type": (poc or {}).get("type") or "",
                "poc_source": (poc or {}).get("source") or "",
                "verify_status": d.get("verify_status") or "unverified",
                "fix_status": d.get("fix_status") or "unknown",
                "fixed": bool(d.get("fixed")),
                "echo": echo[:400],
                "ai_analysis": d.get("ai_analysis") or "",
                "audit_status": d.get("audit_status") or "",
                "merged_into": d.get("merged_into") or "",
                "retest_count": int(d.get("retest_count") or 0),
                "ai_retest_count": int(d.get("ai_retest_count") or 0),
                "last_retest_at": d.get("last_retest_at") or d.get("ai_retest_at"),
            })
        total = len(out)
        filtered = False
        if sev:
            want = sev.lower()
            out = [x for x in out if (x["severity"] or "").lower() == want]
            filtered = True
        # 修复状态筛选（?fix=fixed|unfixed|unknown）
        fix = ((qs.get("fix") or [""])[0] or "").strip().lower()
        if fix:
            out = [x for x in out if (x["fix_status"] or "unknown") == fix]
            filtered = True
        if filtered:
            total = len(out)          # 带筛选时 total 表示筛选后命中数
        else:
            try:
                row = db.query_one(
                    "SELECT COUNT(*) c FROM nodes WHERE kind='finding'" + where, params)
                total = row["c"] if row else total
            except Exception:
                pass
        # 服务端排序：sort=severity|time|task，order=asc|desc
        sort = ((qs.get("sort") or ["severity"])[0] or "severity").strip()
        order = ((qs.get("order") or [""])[0] or "").strip().lower()
        if order not in ("asc", "desc"):
            order = "desc" if sort == "time" else "asc"
        rev = (order == "desc")
        _rank = {"危急": 0, "高": 1, "中": 2, "低": 3, "信息": 4, "未评级": 9}
        if sort == "time":
            out.sort(key=lambda x: (x.get("created_at") or 0), reverse=rev)
        elif sort == "task":
            out.sort(key=lambda x: str(x.get("source_task") or x.get("task_id") or ""),
                     reverse=rev)
        else:
            out.sort(key=lambda x: _rank.get((x.get("severity") or "未评级"), 9),
                     reverse=rev)
        page, size, offset = self._pager(qs)
        pages = (total + size - 1) // size if total else 0
        return {"findings": out[offset:offset + size], "total": total,
                "page": page, "page_size": size, "pages": pages,
                "sort": sort, "order": order}

    # ---------- 漏洞详情（含 POC / 回显 / 历史留痕） ----------
    def _finding_detail(self, db, node_id: str) -> dict:
        from ..vuln_agent import VulnAgent
        agent = VulnAgent(db=db)
        f = agent.get_finding(node_id)
        if not f:
            return {"ok": False, "error": f"漏洞不存在: {node_id}"}
        return {"ok": True, "node": f, "records": agent.records(node_id)}

    # ---------- 人工备注（AI 验证时参考） ----------
    @staticmethod
    def _save_note(node_id: str, body: dict) -> dict:
        from ..vuln_agent import VulnAgent
        if "note" not in body:
            return {"ok": False, "error": "缺少备注内容 note"}
        return VulnAgent().set_note(node_id, body.get("note") or "")

    # ---------- 删除漏洞 / 一键清理误报与重复 ----------
    @staticmethod
    def _delete_findings(body: dict) -> dict:
        from ..vuln_agent import VulnAgent
        ids = body.get("ids")
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        if not isinstance(ids, list) or not ids:
            return {"ok": False, "error": "缺少漏洞 id 列表 ids"}
        return VulnAgent().delete_findings(ids, reason=body.get("reason") or "人工删除")

    @staticmethod
    def _purge_findings(body: dict) -> dict:
        """一键清理：删除 audit_status 命中（误报 fake / 重复 duplicate）的漏洞。"""
        from ..vuln_agent import VulnAgent
        st = body.get("statuses")
        if isinstance(st, str):
            st = [x.strip() for x in st.split(",") if x.strip()]
        if not isinstance(st, list) or not st:
            st = ["fake", "duplicate"]
        ids = body.get("ids")
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        if not isinstance(ids, list):
            ids = None
        # 全库清理是破坏性操作：未限定 ids 时必须显式确认，避免误删真实数据
        if ids is None and not body.get("confirm") and not body.get("global"):
            return {"ok": False,
                    "error": "全库清理会扫描并删除所有任务的误报/重复漏洞，"
                             "请显式传 confirm=true，或限定 ids 只在勾选范围内清理"}
        return VulnAgent().delete_by_audit(ids, tuple(st))

    # ---------- 漏洞优化作业（一键优化 / 复测 / AI 复测） ----------
    @staticmethod
    def _start_vuln_job(action: str, body: dict) -> dict:
        ids = body.get("ids")
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        if not isinstance(ids, list) or not ids:
            return {"ok": False, "error": "缺少漏洞 id 列表 ids"}
        ids = [str(i).strip() for i in ids if str(i).strip()][:500]
        opts = body.get("opts") if isinstance(body.get("opts"), dict) else {}
        opt = {
            "dedup": bool(opts.get("dedup", True)),
            "skip_poc": bool(opts.get("skip_poc", False)),
            "skip_verify": bool(opts.get("skip_verify", False)),
            "allow_command": bool(opts.get("allow_command", False)),
            "timeout": int(opts.get("timeout") or 20),
            # 审查式去重 / 严重性重评估
            "use_llm": bool(opts.get("use_llm", True)),
            "retitle": bool(opts.get("retitle", True)),
            "reeval_severity": bool(opts.get("reeval_severity", True)),
            "max_llm_groups": int(opts.get("max_llm_groups") or 12),
        }
        try:
            from . import runner
            tools = runner.get_tools()
        except Exception:
            tools = None
        from . import jobs
        jid = jobs.start_job(action, ids, opt, tools=tools)
        return {"ok": True, "job_id": jid, "count": len(ids), "action": action}

    # ---------- 人工修改漏洞等级 ----------
    @staticmethod
    def _set_severity(node_id: str, body: dict) -> dict:
        from ..vuln_agent import VulnAgent
        sev = body.get("severity") or body.get("level")
        if not sev:
            return {"ok": False, "error": "缺少等级 severity（危急/高/中/低/信息）"}
        return VulnAgent().set_severity(
            node_id, sev, reason=body.get("reason") or "",
            lock=bool(body.get("lock", True)))

    @staticmethod
    def _set_severity_bulk(body: dict) -> dict:
        from ..vuln_agent import VulnAgent
        ids = body.get("ids")
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        if not isinstance(ids, list) or not ids:
            return {"ok": False, "error": "缺少漏洞 id 列表 ids"}
        sev = body.get("severity") or body.get("level")
        if not sev:
            return {"ok": False, "error": "缺少等级 severity"}
        return VulnAgent().set_severity_bulk(ids, sev, reason=body.get("reason") or "")

    # ---------- 业务逻辑漏洞专项 agent ----------
    @staticmethod
    def _start_logic_job(task_id: str, body: dict) -> dict:
        from ..store import SessionStore
        from ..store.db import get_db
        db = get_db()
        t = SessionStore(db).get_task(task_id)
        if not t:
            return {"ok": False, "error": f"任务不存在: {task_id}"}
        opts = {"task_id": task_id, "target": t.get("target") or "",
                "scope": t.get("scope") or "", "mode": t.get("mode") or "SRC"}
        try:
            from . import runner
            tools = runner.get_tools()
        except Exception:
            tools = None
        from . import jobs
        jid = jobs.start_job("logic", [], opts, tools=tools)
        return {"ok": True, "job_id": jid, "task_id": task_id,
                "target": opts["target"]}

    @staticmethod
    def _traffic_row(r):
        tr = jload(r["traffic"], None) or {}
        return {
            "id": r["id"], "task_id": r["task_id"], "intent_id": r["intent_id"],
            "tool": r["tool"], "args": jload(r["args"], {}), "status": r["status"],
            "result_summary": r["result_summary"], "started_at": r["started_at"],
            "finished_at": r["finished_at"], "duration_ms": r["duration_ms"],
            "traffic": {"request": tr.get("request") or "",
                        "response": tr.get("response") or ""},
        }

    def _traffic_all(self, db, qs) -> dict:
        q = ((qs.get("q") or [""])[0] or "").strip()
        page, size, offset = self._pager(qs, default_size=20)
        where, params = self._task_filter(qs)
        base = ("SELECT id, task_id, intent_id, tool, args, status, result_summary,"
                " started_at, finished_at, duration_ms, traffic FROM tool_calls"
                " WHERE traffic IS NOT NULL AND traffic<>''" + where)
        if q:
            # 带关键字：先放宽扫描范围再过滤（避免先截断后检索漏结果），再按页切片
            rows = db.query(base + " ORDER BY started_at DESC LIMIT ?", params + [5000])
            matched = []
            for r in rows:
                tr = jload(r["traffic"], None) or {}
                hay = (f"{r['tool'] or ''}\n{tr.get('request') or ''}\n"
                       f"{tr.get('response') or ''}\n{r['result_summary'] or ''}").lower()
                if q.lower() in hay:
                    matched.append(self._traffic_row(r))
            total = len(matched)          # 带关键字时 total 表示命中数
            items = matched[offset:offset + size]
        else:
            total = 0
            try:
                row = db.query_one(
                    "SELECT COUNT(*) c FROM tool_calls"
                    " WHERE traffic IS NOT NULL AND traffic<>''" + where, params)
                total = row["c"] if row else 0
            except Exception:
                total = 0
            rows = db.query(base + " ORDER BY started_at DESC LIMIT ? OFFSET ?",
                            params + [size, offset])
            items = [self._traffic_row(r) for r in rows]
        pages = (total + size - 1) // size if total else 0
        return {"traffic": items, "total": total, "q": q,
                "page": page, "page_size": size, "pages": pages}

    @staticmethod
    def _paged_qs(qs, default_size=200, max_size=2000):
        """兼容旧的 limit 参数：未显式给 page_size 时以其作为每页大小。"""
        tqs = dict(qs)
        if "page_size" not in tqs and (qs.get("limit") or [None])[0]:
            tqs["page_size"] = qs.get("limit")
        return tqs, default_size, max_size

    def _logs_all(self, db, qs) -> dict:
        etype = ((qs.get("type") or [""])[0] or "").strip()
        tqs, ds, ms = self._paged_qs(qs)
        page, size, offset = self._pager(tqs, default_size=ds, max_size=ms)
        where, params = self._task_filter(qs)
        if etype:
            where += " AND type=?"
            params.append(etype)
        rows = db.query(
            "SELECT id, task_id, ts, type, actor, message, data FROM events WHERE 1=1"
            + where + " ORDER BY ts DESC LIMIT ? OFFSET ?", params + [size, offset])
        for r in rows:
            r["data"] = jload(r["data"], {})
        total = len(rows)
        try:
            row = db.query_one(
                "SELECT COUNT(*) c FROM events WHERE 1=1" + where, params)
            total = row["c"] if row else len(rows)
        except Exception:
            pass
        pages = (total + size - 1) // size if total else 0
        return {"logs": rows, "total": total, "page": page,
                "page_size": size, "pages": pages}

    def _approval_records(self, db, qs) -> dict:
        tqs, ds, ms = self._paged_qs(qs)
        page, size, offset = self._pager(tqs, default_size=ds, max_size=ms)
        where, params = self._task_filter(qs)
        rows = db.query(
            "SELECT id, approval_id, task_id, tool, args, risk, reason, action,"
            " decision_reason, auto, created_at, decided_at FROM approvals WHERE 1=1"
            + where + " ORDER BY decided_at DESC, id DESC LIMIT ? OFFSET ?",
            params + [size, offset])
        for r in rows:
            r["args"] = jload(r["args"], {})
        total = len(rows)
        try:
            row = db.query_one(
                "SELECT COUNT(*) c FROM approvals WHERE 1=1" + where, params)
            total = row["c"] if row else len(rows)
        except Exception:
            pass
        pages = (total + size - 1) // size if total else 0
        return {"records": rows, "total": total, "page": page,
                "page_size": size, "pages": pages}

    def _assets_all(self, db, qs) -> dict:
        """资产清单分页：?page= &page_size= &kind= &task_id= &q="""
        try:
            page = max(1, int((qs.get("page") or ["1"])[0] or 1))
        except Exception:
            page = 1
        try:
            size = min(500, max(1, int((qs.get("page_size") or ["50"])[0] or 50)))
        except Exception:
            size = 50
        kind = (qs.get("kind") or [None])[0] or None
        tid = (qs.get("task_id") or [None])[0] or None
        q = (qs.get("q") or [""])[0] or ""
        ag = AssetGraph(db)
        items = ag.list_paged(page=page, page_size=size,
                              kind=kind, task_id=tid, q=q)
        total = ag.count_assets(kind=kind, task_id=tid, q=q)
        pages = (total + size - 1) // size if total else 0
        return {"items": items, "total": total, "page": page,
                "page_size": size, "pages": pages}

    # ------------------------------------------------------------------
    # 设置 → Agent 配置的默认值回落
    # ------------------------------------------------------------------
    @staticmethod
    def _agent_defaults() -> dict:
        """「设置 → Agent 配置」里保存的运行参数，作为发起任务时的默认值。"""
        try:
            from ..settings import load_settings
            return load_settings().get("agent") or {}
        except Exception:
            return {}

    # 发起任务的请求字段名 → 「设置 → Agent 配置」里的字段名
    _SCAN_ALIAS = {"workers": "max_workers", "rounds": "max_rounds",
                   "intents": "planner_max_intents"}

    @staticmethod
    def _pick_num(body: dict, key: str, defaults: dict, fallback: int) -> int:
        """优先用请求显式传入的值，其次用保存的设置，最后用内置兜底值。"""
        v = body.get(key)
        if v is None or v == "":
            v = defaults.get(ApiHandler._SCAN_ALIAS.get(key, key))
        try:
            return int(v)
        except Exception:
            return fallback

    def _route_post(self):
        from . import runner
        path = urlparse(self.path).path
        body = self._read_body()

        # ---------- 代理池 ----------
        if path == "/api/proxies":
            return self._send_json(self._proxy_add(body))
        if path == "/api/proxy/test":
            return self._send_json(self._proxy_test("", body))
        if path == "/api/proxy/activate":
            return self._send_json(self._proxy_activate((body.get("id") or "").strip()))
        if path == "/api/proxy/toggle":
            return self._send_json(self._proxy_set_enabled(
                (body.get("id") or "").strip(), body))
        if path == "/api/proxy/settings":
            return self._send_json(self._proxy_settings(body))
        if path == "/api/proxy/import-url":
            return self._send_json(self._proxy_import_url(body))
        if path == "/api/proxy/import-text":
            return self._send_json(self._proxy_import_text(body))
        if path == "/api/proxy/verify-all":
            return self._send_json(self._proxy_verify_all(body))
        if path == "/api/proxy/rotation":
            return self._send_json(self._proxy_rotation(body))
        if path == "/api/proxy/batch-delete":
            return self._send_json(self._proxy_batch_delete(body))
        if path == "/api/proxy/delete-failed":
            return self._send_json(self._proxy_delete_failed())

        # ---------- 任务批量管理 ----------
        if path == "/api/tasks/batch-delete":
            return self._send_json(self._tasks_batch_delete(body))

        # ---------- Tor 链路出口代理 ----------
        if path == "/api/tor":
            return self._send_json(self._tor_set(body))

        # ---------- 统一出网模式（不使用代理 / 代理池 / Tor） ----------
        if path == "/api/egress":
            return self._send_json(self._egress_set(body))

        # ---------- 限速 / 隐蔽性 ----------
        if path == "/api/rate":
            return self._send_json(self._rate_set(body))

        # ---------- 攻击链管理 ----------
        if path == "/api/chain/review":
            return self._send_json(self._chain_review(body))
        if path == "/api/chain/settings":
            return self._send_json(self._chain_settings(body))
        if path == "/api/chain/memory/rebuild":
            return self._send_json(self._chain_rebuild(body))
        if path == "/api/chain/memory/query":
            return self._send_json(self._chain_query(body))
        if path == "/api/chains/delete":
            return self._send_json(self._chains_delete(body))
        if path.startswith("/api/chain/") and path.endswith("/update"):
            cid = path[len("/api/chain/"):].split("/")[0]
            return self._send_json(self._chain_update(cid, body))

        # ---------- 技能管理 ----------
        if path == "/api/skills/toggle":
            return self._send_json(self._skills_toggle(body))
        if path == "/api/skills/query":
            return self._send_json(self._skills_query(body))

        # ---------- 知识库管理 ----------
        if path == "/api/kb/search":
            return self._send_json(self._kb_search(body))

        # ---------- 多智能体管理 ----------
        if path == "/api/agents":
            return self._send_json(self._agent_add(body))
        if path == "/api/agent/prompt":
            return self._send_json(self._agent_set_prompt(body))
        if path.startswith("/api/agent/") and path.endswith("/update"):
            aid = path[len("/api/agent/"):].split("/")[0]
            return self._send_json(self._agent_update(aid, body))
        if path.startswith("/api/agent/") and path.endswith("/toggle"):
            aid = path[len("/api/agent/"):].split("/")[0]
            return self._send_json(self._agent_toggle(aid, body))

        # ---------- WebShell 管理 ----------
        if path == "/api/webshell/add":
            return self._send_json(self._webshell_add(body))
        if path == "/api/webshell/import":
            return self._send_json(self._webshell_import(body))
        if path == "/api/webshell/export":
            return self._send_json(self._webshell_export())
        if path == "/api/webshell/batch-delete":
            return self._send_json(self._webshell_batch_delete(body))
        if path.startswith("/api/webshell/") and path.endswith("/update"):
            sid = path[len("/api/webshell/"):].split("/")[0]
            return self._send_json(self._webshell_update(sid, body))
        if path.startswith("/api/webshell/") and path.endswith("/test"):
            sid = path[len("/api/webshell/"):].split("/")[0]
            return self._send_json(self._webshell_test(sid))
        if path.startswith("/api/webshell/") and path.endswith("/exec"):
            sid = path[len("/api/webshell/"):].split("/")[0]
            return self._send_json(self._webshell_exec(sid, body))

        if path == "/api/scan":
            target = (body.get("target") or "").strip()
            if not target:
                return self._send_json({"error": "缺少目标 target"}, 400)
            # 界面没显式提交的参数，回落到「设置 → Agent 配置」保存的默认值
            ag = self._agent_defaults()
            ra = body.get("require_approval")
            tid = runner.start_task(
                target=target,
                mode=str(body.get("mode") or ag.get("mode") or "SRC"),
                scope=body.get("scope") or "",
                name=body.get("name") or "",
                workers=self._pick_num(body, "workers", ag, 3),
                rounds=self._pick_num(body, "rounds", ag, 20),
                intents=self._pick_num(body, "intents", ag, 5),
                dry_run=bool(body.get("dry_run")),
                require_approval=bool(ag.get("require_approval", False)
                                      if ra is None else ra),
                approval_timeout=self._pick_num(body, "approval_timeout", ag, 180),
                token_budget=self._pick_num(body, "token_budget", ag, 0),
                logic_agent=bool(ag.get("logic_agent", True)),
                context_compress=bool(ag.get("context_compress", True)),
                compress_every=self._pick_num(body, "compress_every", ag, 3),
                chain_review=bool(ag.get("chain_review", True)
                                  if body.get("chain_review") is None
                                  else body.get("chain_review")),
            )
            return self._send_json({"ok": True, "task_id": tid,
                                    "applied_agent_defaults": ag})

        if path == "/api/demo":
            tid = runner.start_demo(target=body.get("target") or "example.com",
                                    mode=body.get("mode") or "SRC")
            return self._send_json({"ok": True, "task_id": tid})

        if path.startswith("/api/task/") and path.endswith("/stop"):
            parts = path[len("/api/task/"):].split("/")
            task_id = parts[0]
            ok = runner.stop_task(task_id)
            if not ok:
                # 没有存活线程（如进程被强杀后重启的孤儿任务）：直接把 DB 状态置为已停止
                db = get_db()
                t = SessionStore(db).get_task(task_id)
                if t and t.get("status") == "running":
                    SessionStore(db).finish_task(task_id, "stopped")
                    ok = True
            # 取消该任务所有待审批项，释放被阻塞的工作线程，避免残留弹窗
            try:
                from ..human_gate import get_gate
                get_gate().clear_task(task_id)
            except Exception:
                pass
            return self._send_json({"ok": ok})

        # 兼容不支持 DELETE 方法的客户端
        if path.startswith("/api/task/") and path.endswith("/delete"):
            parts = path[len("/api/task/"):].split("/")
            self.path = f"/api/task/{parts[0]}"
            return self._route_delete()

        if path == "/api/reload":
            runner.reload_tools()
            return self._send_json({"ok": True, "tools": runner.tools_count()})

        # ---------- 配置持久化 ----------
        if path == "/api/settings/llm":
            return self._send_json(self._save_settings("llm", body))
        if path == "/api/settings/agent":
            return self._send_json(self._save_settings("agent", body))

        # ---------- 对话（不启动渗透任务） ----------
        if path == "/api/chat":
            return self._send_json(self._chat(body))

        # ---------- 人在环路：审批 / 干预 / 重放 ----------
        if path.startswith("/api/task/") and path.endswith("/approve"):
            from ..human_gate import get_gate
            parts = path[len("/api/task/"):].split("/")
            ok = get_gate().decide(
                body.get("approval_id"), body.get("action") or "approved",
                body.get("reason", ""))
            return self._send_json({"ok": ok})

        if path.startswith("/api/task/") and path.endswith("/intervene"):
            parts = path[len("/api/task/"):].split("/")
            return self._send_json(self._intervene(parts[0], body))

        if path.startswith("/api/task/") and path.endswith("/replay"):
            parts = path[len("/api/task/"):].split("/")
            return self._send_json(self._replay(parts[0], body))

        # ---------- 漏洞优化智能体（一键优化 / 复测 / AI 复测） ----------
        if path == "/api/vulns/optimize":
            return self._send_json(self._start_vuln_job("optimize", body))
        if path == "/api/vulns/retest":
            return self._send_json(self._start_vuln_job("retest", body))
        if path == "/api/vulns/ai-retest":
            return self._send_json(self._start_vuln_job("ai_retest", body))
        # 仅重新审查（去重 + 重评估严重性，不写 POC / 不执行验证）
        if path == "/api/vulns/review":
            b = dict(body or {})
            o = dict(b.get("opts") or {})
            o.update({"dedup": True, "skip_poc": True, "skip_verify": True})
            b["opts"] = o
            return self._send_json(self._start_vuln_job("optimize", b))

        # ---------- 人工修改等级（单个 / 批量） ----------
        if path == "/api/vulns/severity":
            return self._send_json(self._set_severity_bulk(body))
        if path.startswith("/api/finding/") and path.endswith("/severity"):
            nid = path[len("/api/finding/"):].split("/")[0]
            return self._send_json(self._set_severity(nid, body))

        # ---------- 业务逻辑漏洞专项 agent ----------
        if path.startswith("/api/task/") and path.endswith("/logic"):
            parts = path[len("/api/task/"):].split("/")
            return self._send_json(self._start_logic_job(parts[0], body))

        # ---------- 漏洞删除 / 一键清理误报与重复 ----------
        if path == "/api/vulns/delete":
            return self._send_json(self._delete_findings(body))
        if path == "/api/vulns/purge":
            return self._send_json(self._purge_findings(body))
        # 兼容不支持 DELETE 方法的客户端：POST /api/finding/<id>/delete
        if path.startswith("/api/finding/") and path.endswith("/delete"):
            nid = path[len("/api/finding/"):].split("/")[0]
            return self._send_json(self._delete_findings({"ids": [nid],
                                                          "reason": body.get("reason") or "人工删除"}))
        # 人工备注（供 AI 验证时参考）
        if path.startswith("/api/finding/") and path.endswith("/note"):
            nid = path[len("/api/finding/"):].split("/")[0]
            return self._send_json(self._save_note(nid, body))

        self.send_error(404, "Not Found")

    # ---------- 代理池管理 ----------
    @staticmethod
    def _proxy_list():
        from ..proxy_pool import list_proxies
        return list_proxies()

    @staticmethod
    def _proxy_add(body: dict):
        from ..proxy_pool import add_proxy
        b = body or {}
        return add_proxy(b.get("type", "http"), b.get("host", ""), b.get("port", ""),
                        b.get("username", ""), b.get("password", ""),
                        b.get("tags", ""), b.get("note", ""))

    @staticmethod
    def _proxy_remove(pid: str):
        from ..proxy_pool import remove_proxy
        if not pid:
            return {"ok": False, "error": "缺少代理 ID"}
        return remove_proxy(pid)

    @staticmethod
    def _proxy_set_enabled(pid: str, body: dict):
        from ..proxy_pool import set_enabled
        if not pid:
            return {"ok": False, "error": "缺少代理 ID"}
        return set_enabled(pid, body.get("enabled", True))

    @staticmethod
    def _proxy_activate(pid: str):
        from ..proxy_pool import activate
        if not pid:
            return {"ok": False, "error": "缺少代理 ID"}
        return activate(pid)

    @staticmethod
    def _proxy_settings(body: dict):
        from ..proxy_pool import set_use_proxy
        return set_use_proxy(body.get("use_proxy", False))

    @staticmethod
    def _proxy_test(pid: str, body: dict = None):
        from ..proxy_pool import test_proxy
        if not pid:
            # 允许 POST body 传 id
            pid = ((body or {}).get("id") or "").strip()
        if not pid:
            return {"ok": False, "error": "缺少代理 ID"}
        check = ((body or {}).get("check_url") or "").strip()
        return test_proxy(pid, check) if check else test_proxy(pid)

    @staticmethod
    def _proxy_import_url(body: dict):
        from ..proxy_pool import import_from_urls
        b = body or {}
        urls = b.get("urls") or []
        if isinstance(urls, str):
            urls = [u.strip() for u in urls.splitlines() if u.strip()]
        if not urls:
            return {"ok": False, "error": "缺少 urls"}
        return import_from_urls(
            urls,
            default_type=(b.get("default_type") or "http"),
            tags=(b.get("tags") or ""),
            timeout=int(b.get("timeout") or 20))

    @staticmethod
    def _proxy_import_text(body: dict):
        from ..proxy_pool import import_text
        b = body or {}
        text = b.get("text") or ""
        if not text.strip():
            return {"ok": False, "error": "缺少 text"}
        return import_text(
            text,
            default_type=(b.get("default_type") or "http"),
            tags=(b.get("tags") or ""))

    @staticmethod
    def _proxy_verify_all(body: dict = None):
        from ..proxy_pool import verify_all
        b = body or {}
        return verify_all(
            check_url=(b.get("check_url") or "").strip() or None,
            timeout=int(b.get("timeout") or 5),
            max_workers=int(b.get("max_workers") or 100))

    @staticmethod
    def _proxy_rotation(body: dict):
        from ..proxy_pool import set_rotation
        b = body or {}
        return set_rotation(
            b.get("enabled", False),
            seconds=b.get("seconds", 60))

    @staticmethod
    def _proxy_batch_delete(body: dict):
        from ..proxy_pool import batch_delete
        b = body or {}
        ids = b.get("ids") or []
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        if not ids:
            return {"ok": False, "error": "缺少 ids"}
        return batch_delete(ids)

    @staticmethod
    def _proxy_delete_failed():
        from ..proxy_pool import delete_failed
        return delete_failed()

    @staticmethod
    def _tasks_batch_delete(body: dict):
        b = body or {}
        ids = b.get("ids") or []
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        if not ids:
            return {"ok": False, "error": "缺少 ids"}
        ss = SessionStore(get_db())
        deleted = 0
        missing = 0
        for tid in ids:
            # 仅统计确实存在的任务，避免把不存在的 id 计入删除数
            if not ss.get_task(tid):
                missing += 1
                continue
            try:
                ss.delete_task(tid)
                deleted += 1
            except Exception:
                pass
        return {"ok": True, "deleted": deleted, "missing": missing,
                "requested": len(ids)}

    @staticmethod
    def _tor_config():
        from ..tor_proxy import get_config
        return get_config()

    @staticmethod
    def _tor_set(body: dict):
        from ..tor_proxy import set_config
        b = body or {}
        return set_config(
            b.get("enabled", False),
            egress_host=b.get("egress_host"),
            egress_port=b.get("egress_port"),
            compliance_ack=b.get("compliance_ack", False))

    @staticmethod
    def _egress_config():
        from ..egress_config import get_config
        return get_config()

    @staticmethod
    def _egress_set(body: dict):
        from ..egress_config import set_egress_mode
        return set_egress_mode((body or {}).get("mode") or "none")

    # ---------- 技能管理 ----------
    @staticmethod
    def _skills_list(qs):
        from ..skill_admin import list_skills
        g = lambda k: ((qs.get(k) or [""])[0] or "").strip()  # noqa: E731
        return list_skills(kind=g("kind") or None,
                           category=g("category") or None, q=g("q") or None)

    @staticmethod
    def _skills_stats():
        from ..skill_admin import stats
        return stats()

    @staticmethod
    def _skill_detail(name):
        from ..skill_admin import get_skill
        if not name:
            return {"ok": False, "error": "缺少技能名"}
        return get_skill(name)

    @staticmethod
    def _skills_toggle(body: dict):
        from ..skill_admin import batch_toggle
        b = body or {}
        names = b.get("names") or []
        if isinstance(names, str):
            names = [x.strip() for x in names.split(",") if x.strip()]
        return batch_toggle(names, bool(b.get("enabled", True)))

    @staticmethod
    def _skills_query(body: dict):
        from ..skill_admin import query_skill
        b = body or {}
        return query_skill(b.get("name"),
                           query=b.get("query"), section=b.get("section"),
                           list_only=b.get("list_only", False),
                           sanitize=b.get("sanitize", True),
                           max_chars=b.get("max_chars", 6000))

    # ---------- 知识库管理 ----------
    @staticmethod
    def _kb_stats():
        from ..knowledge_admin import stats
        return stats()

    @staticmethod
    def _kb_documents(qs):
        from ..knowledge_admin import list_docs
        g = lambda k: ((qs.get(k) or [""])[0] or "").strip()  # noqa: E731
        return list_docs(source=g("source") or None, q=g("q") or None,
                         category=g("category") or None)

    @staticmethod
    def _kb_document(doc_id, qs):
        from ..knowledge_admin import get_doc
        try:
            sanitize = ((qs.get("sanitize") or ["1"])[0] or "1") not in ("0", "false")
            max_chars = int((qs.get("max_chars") or ["20000"])[0] or 20000)
        except Exception:
            sanitize, max_chars = True, 20000
        return get_doc(doc_id, sanitize=sanitize, max_chars=max_chars)

    @staticmethod
    def _kb_search(body: dict):
        from ..knowledge_admin import search
        b = body or {}
        return search(b.get("q") or "", source=b.get("source") or None,
                      deep=bool(b.get("deep")), limit=int(b.get("limit") or 30))

    # ---------- 多智能体管理 ----------
    @staticmethod
    def _agents_list():
        from ..agent_admin import list_agents
        return list_agents()

    @staticmethod
    def _agent_detail(aid):
        from ..agent_admin import get_agent
        return get_agent(aid)

    @staticmethod
    def _agent_set_prompt(body: dict):
        from ..agent_admin import set_prompt
        b = body or {}
        return set_prompt(b.get("key") or "", b.get("prompt") or "")

    @staticmethod
    def _agent_add(body: dict):
        from ..agent_admin import add_custom
        b = body or {}
        return add_custom(b.get("name"), role=b.get("role", ""),
                          prompt=b.get("prompt", ""), stage=b.get("stage", ""),
                          keywords=b.get("keywords") or [], tools=b.get("tools") or [])

    @staticmethod
    def _agent_update(aid, body: dict):
        from ..agent_admin import update_custom
        b = body or {}
        fields = {k: b[k] for k in
                  ("name", "role", "prompt", "stage", "enabled", "keywords", "tools")
                  if k in b}
        return update_custom(aid, **fields)

    @staticmethod
    def _agent_delete(aid):
        from ..agent_admin import delete_custom
        if not aid:
            return {"ok": False, "error": "缺少 agent id"}
        return delete_custom(aid)

    @staticmethod
    def _agent_toggle(aid, body: dict):
        from ..agent_admin import toggle_custom
        return toggle_custom(aid, (body or {}).get("enabled", True))

    # ---------- 攻击链管理 / 攻击链记忆 ----------
    @staticmethod
    def _chains_list(qs):
        from ..attack_chain import list_chains
        g = lambda k: ((qs.get(k) or [""])[0] or "").strip()  # noqa: E731
        try:
            limit = int(g("limit") or 0)
        except Exception:
            limit = 0
        return list_chains(q=g("q"), target=g("target"), limit=limit,
                           tech=g("tech") or None, vuln=g("vuln") or None,
                           stage=g("stage") or None, kind=g("kind") or None,
                           fp=g("fp") or "")

    @staticmethod
    def _chains_catalog():
        from ..attack_chain import catalog
        return catalog()

    @staticmethod
    def _chain_query(body: dict):
        """按需检索记忆（分类 + 关键词），不返回敏感明文。"""
        from ..attack_chain import query_memory
        b = body or {}
        try:
            limit = int(b.get("limit") or 10)
        except Exception:
            limit = 10
        return query_memory(q=b.get("q") or "", tech=b.get("tech") or None,
                            vuln=b.get("vuln") or None,
                            stage=b.get("stage") or None,
                            kind=b.get("kind") or None, limit=limit)

    @staticmethod
    def _chain_detail(cid):
        from ..attack_chain import get_chain
        if not cid:
            return {"ok": False, "error": "缺少攻击链 id"}
        return get_chain(cid)

    @staticmethod
    def _chain_review(body: dict):
        """异步复盘某个任务（作业在后台线程，前端轮询 /api/vulns/job/<id>）。"""
        tid = (body.get("task_id") or "").strip()
        if not tid:
            return {"ok": False, "error": "缺少 task_id"}
        from ..store import SessionStore
        from ..store.db import get_db
        if not SessionStore(get_db()).get_task(tid):
            return {"ok": False, "error": f"任务不存在: {tid}"}
        from . import jobs
        jid = jobs.start_job("chain_review", [],
                             {"task_id": tid,
                              "source": body.get("source") or "manual",
                              "use_llm": bool(body.get("use_llm", True))})
        return {"ok": True, "job_id": jid, "task_id": tid, "action": "chain_review"}

    @staticmethod
    def _chain_update(cid, body: dict):
        from ..attack_chain import update_chain
        if not cid:
            return {"ok": False, "error": "缺少攻击链 id"}
        body = body or {}
        return update_chain(cid, **{k: body[k] for k in
                                    ("summary", "lessons", "next_steps", "tags", "note")
                                    if k in body})

    @staticmethod
    def _chain_delete(cid):
        from ..attack_chain import delete_chains
        if not cid:
            return {"ok": False, "error": "缺少攻击链 id"}
        return delete_chains([cid])

    @staticmethod
    def _chains_delete(body: dict):
        from ..attack_chain import delete_chains
        ids = (body or {}).get("ids") or []
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        if not ids:
            return {"ok": False, "error": "缺少 ids"}
        if not (body or {}).get("confirm"):
            # 删除记忆不可恢复：批量删除必须显式确认
            return {"ok": False, "error": "批量删除需 confirm=true"}
        return delete_chains(ids)

    @staticmethod
    def _chain_memory():
        from ..attack_chain import memory_text, stats
        out = memory_text()
        out.update({"stats": stats()})
        return out

    @staticmethod
    def _chain_settings(body: dict):
        from ..attack_chain import set_settings
        body = body or {}
        return set_settings(**{k: body[k] for k in
                               ("auto_review", "inject_memory", "inject_limit",
                                "memory_limit")
                               if k in body})

    @staticmethod
    def _chain_rebuild(body: dict):
        from ..attack_chain import rebuild_memory
        try:
            limit = int((body or {}).get("limit") or 0)
        except Exception:
            limit = 0
        return rebuild_memory(limit=limit or None)

    # ---------- 当前出网 IP ----------
    _IP_CACHE = {"ts": 0.0, "mode": "", "data": None}

    @classmethod
    def _egress_ip(cls, force: bool = False):
        """查询当前出口 IP（https://api.ip.sb/ip），并回显是否经代理 / Tor。

        结果缓存 60 秒（失败 20 秒），避免顶部栏轮询打爆外部接口。
        """
        import time as _t
        try:
            from ..egress_config import get_egress_mode, resolve_proxy
            mode = get_egress_mode() or "none"
        except Exception:
            mode, resolve_proxy = "none", None
        c = cls._IP_CACHE
        ttl = 60 if (c.get("data") or {}).get("ok") else 20
        if (not force) and c.get("data") and c.get("mode") == mode \
                and (_t.time() - (c.get("ts") or 0)) < ttl:
            d = dict(c["data"])
            d["cached"] = True
            return d

        proxies = {}
        if resolve_proxy is not None:
            try:
                proxies = resolve_proxy() or {}
            except Exception:
                proxies = {}
        paddr = str(proxies.get("http") or "")
        out = {"ok": False, "ip": "", "mode": mode,
               "proxy": bool(proxies), "tor": mode == "tor",
               "proxy_addr": paddr, "ts": _t.time(),
               "cached": False, "source": "https://api.ip.sb/ip", "error": ""}
        # 是否已把出网模式下沉到「技能自建会话 / 子进程」（否则部分操作会直连）
        try:
            from ..egress_config import env_state
            from ..egress_patch import status as _patch_status
            out["env_applied"] = bool(env_state().get("applied"))
            out["patch"] = _patch_status()
        except Exception:
            out["env_applied"] = False
            out["patch"] = {}
        # 限速状态（顶栏 tooltip 展示）
        try:
            from ..rate_limit import config as _rate_cfg
            rc = _rate_cfg()
            out["rate"] = {"enabled": bool(rc.get("enabled")),
                           "preset": rc.get("preset"),
                           "global_rps": rc.get("global_rps"),
                           "per_host_rps": rc.get("per_host_rps")}
        except Exception:
            out["rate"] = {}
        try:
            import ssl
            import urllib.request
            if proxies:
                handlers = [urllib.request.ProxyHandler(
                    {"http": paddr, "https": proxies.get("https") or paddr})]
            else:
                # 显式清空代理：避免系统/环境变量代理造成「显示的不是真实出口」
                handlers = [urllib.request.ProxyHandler({})]
            req = urllib.request.Request(
                "https://api.ip.sb/ip",
                headers={"User-Agent": "pen-workbench/1.0", "Accept": "text/plain"})

            def _fetch(extra=None):
                op = urllib.request.build_opener(*(handlers + (extra or [])))
                with op.open(req, timeout=8) as r:
                    return r.read(256).decode("utf-8", "ignore").strip()

            try:
                txt = _fetch()
            except Exception as e1:
                # 企业代理 MITM 常导致证书校验失败；该接口仅用于只读自检出口 IP，
                # 因此允许一次「不校验证书」的重试，并在返回里标注 insecure。
                if "CERTIFICATE" not in str(e1).upper() and "SSL" not in str(e1).upper():
                    raise
                txt = _fetch([urllib.request.HTTPSHandler(
                    context=ssl._create_unverified_context())])
                out["insecure_tls"] = True
            ip = (txt.splitlines() or [""])[0].strip()
            if ip and len(ip) <= 64 and all(ch in "0123456789abcdefABCDEF:." for ch in ip):
                out["ip"] = ip
                out["ok"] = True
            else:
                out["error"] = "接口返回异常: " + txt[:80]
        except Exception as e:
            out["error"] = f"查询失败：{e}"
        if mode == "pool" and not proxies:
            out["error"] = (out.get("error") or "") + "｜代理池无可活动代理，实际为直连"
        try:
            cls._IP_CACHE = {"ts": _t.time(), "mode": mode, "data": dict(out)}
        except Exception:
            pass
        return out

    @staticmethod
    def _rate_get():
        from ..rate_limit import stats
        return stats()

    @staticmethod
    def _rate_set(body: dict):
        from ..rate_limit import set_config
        b = body or {}
        fields = {k: b[k] for k in
                  ("enabled", "preset", "global_rps", "per_host_rps", "burst",
                   "jitter", "max_concurrency", "scan_threads_cap",
                   "skill_rps", "command_max_rate", "allow_direct") if k in b}
        cfg = set_config(**fields)
        return {"ok": True, "config": cfg}

    @staticmethod
    def _egress_status():
        """出网落地自检：模式 / 是否写入环境变量 / 补丁是否装上 / 不走代理的主机。"""
        try:
            from ..egress_config import apply_env, bypass_hosts, env_state, get_egress_mode
            from ..egress_patch import status as patch_status
            st = apply_env(force=True)
            return {"ok": True, "mode": get_egress_mode(),
                    "env": {"applied": bool(st.get("applied")),
                            "proxy_set": bool(st.get("url")),
                            "bypass": bypass_hosts()},
                    "patch": patch_status(),
                    "env_state": env_state()}
        except Exception as e:
            return {"ok": False, "error": f"出网自检失败: {e}"}

    # ---------- WebShell 管理 ----------
    @staticmethod
    def _webshell_list(qs):
        from ..webshell import list_shells, export_antsword
        fmt = ((qs.get("format") or [""])[0] or "").strip()
        if fmt == "antsword":
            return export_antsword()
        try:
            page = int((qs.get("page") or ["1"])[0] or 1)
            size = int((qs.get("page_size") or ["0"])[0] or 0)
        except Exception:
            page, size = 1, 0
        q = ((qs.get("q") or [""])[0] or "").strip()
        return list_shells(page=page, page_size=size, q=q or None)

    @staticmethod
    def _webshell_detail(sid):
        from ..webshell import get_shell, _pub
        s = get_shell(sid)
        return {"ok": True, "shell": _pub(s)} if s else {"ok": False, "error": "WebShell 不存在"}

    @staticmethod
    def _webshell_add(body: dict):
        from ..webshell import add_shell
        b = body or {}
        return add_shell(b.get("name"), b.get("url"),
                         method=b.get("method", "GET"), param=b.get("param", "cmd"),
                         password=b.get("password", ""), stype=b.get("type", "php"),
                         os_=b.get("os", ""), note=b.get("note", ""),
                         tags=b.get("tags", ""), encoding=b.get("encoding", ""))

    @staticmethod
    def _webshell_import(body: dict):
        from ..webshell import import_antsword
        b = body or {}
        data = b.get("shells")
        if data is None:
            data = b.get("data")
        if data is None:
            data = b.get("text")
        return import_antsword(data)

    @staticmethod
    def _webshell_export():
        from ..webshell import export_antsword
        return export_antsword()

    @staticmethod
    def _webshell_update(sid, body: dict):
        from ..webshell import update_shell
        b = body or {}
        fields = {k: b[k] for k in
                  ("name", "url", "method", "param", "password", "type", "os",
                   "note", "tags", "enabled", "encoding") if k in b}
        return update_shell(sid, **fields)

    @staticmethod
    def _webshell_delete(sid):
        from ..webshell import delete_shell
        if not sid:
            return {"ok": False, "error": "缺少 id"}
        return delete_shell(sid)

    @staticmethod
    def _webshell_batch_delete(body: dict):
        from ..webshell import batch_delete
        b = body or {}
        ids = b.get("ids") or []
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        return batch_delete(ids)

    @staticmethod
    def _webshell_test(sid):
        from ..webshell import test_shell
        return test_shell(sid)

    @staticmethod
    def _webshell_exec(sid, body: dict):
        from ..webshell import exec_shell
        b = body or {}
        return exec_shell(sid, b.get("cmd"), timeout=int(b.get("timeout") or 10),
                          confirm=bool(b.get("confirm")))

    def _route(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # ---------- 代理池 ----------
        if path == "/api/proxies":
            return self._send_json(self._proxy_list())
        if path == "/api/tor":
            return self._send_json(self._tor_config())
        if path == "/api/egress":
            return self._send_json(self._egress_config())
        # 当前出口 IP（顶部状态栏）：?force=1 跳过缓存
        if path == "/api/egress/ip":
            force = ((qs.get("force") or ["0"])[0] or "0") not in ("0", "", "false")
            return self._send_json(self._egress_ip(force=force))
        # 出网落地自检（环境变量 / 技能补丁 / 白名单）
        if path == "/api/egress/status":
            return self._send_json(self._egress_status())
        # 限速 / 隐蔽性配置
        if path == "/api/rate":
            return self._send_json(self._rate_get())

        # ---------- 攻击链管理 ----------
        if path == "/api/chains":
            return self._send_json(self._chains_list(qs))
        if path == "/api/chains/catalog":
            return self._send_json(self._chains_catalog())
        if path == "/api/chain/memory":
            return self._send_json(self._chain_memory())
        if path.startswith("/api/chain/"):
            cid = unquote(path[len("/api/chain/"):]).strip("/")
            return self._send_json(self._chain_detail(cid))

        # ---------- 技能管理 ----------
        if path == "/api/skills":
            return self._send_json(self._skills_list(qs))
        if path == "/api/skills/stats":
            return self._send_json(self._skills_stats())
        if path.startswith("/api/skill/"):
            nm = unquote(path[len("/api/skill/"):]).strip("/")
            return self._send_json(self._skill_detail(nm))

        # ---------- 知识库管理 ----------
        if path == "/api/kb/stats":
            return self._send_json(self._kb_stats())
        if path == "/api/kb/documents":
            return self._send_json(self._kb_documents(qs))
        if path.startswith("/api/kb/document/"):
            did = unquote(path[len("/api/kb/document/"):]).strip("/")
            return self._send_json(self._kb_document(did, qs))

        # ---------- 多智能体管理 ----------
        if path == "/api/agents":
            return self._send_json(self._agents_list())
        if path.startswith("/api/agent/"):
            aid = unquote(path[len("/api/agent/"):]).strip("/")
            return self._send_json(self._agent_detail(aid))

        # ---------- WebShell 管理 ----------
        if path == "/api/webshell/list":
            return self._send_json(self._webshell_list(qs))
        if path.startswith("/api/webshell/"):
            sid = unquote(path[len("/api/webshell/"):]).strip("/")
            return self._send_json(self._webshell_detail(sid))

        if path in ("/", "/index.html"):
            self._send_file(WEBUI_STATIC_DIR / "index.html")
            return
        if path.startswith("/static/"):
            self._send_file(WEBUI_STATIC_DIR / path[len("/static/"):])
            return
        if path == "/favicon.ico":
            self.send_response(204); self.end_headers(); return

        if path == "/api/health":
            return self._send_json({"ok": True, "service": "agent6-webui"})
        if path == "/api/running":
            from . import runner
            return self._send_json({"running": runner.running(),
                                    "tools": runner.tools_count()})

        # ---------- 配置 / 跨任务聚合列表 ----------
        if path == "/api/settings":
            try:
                from ..settings import public_settings
                return self._send_json(public_settings())
            except Exception as e:
                return self._send_json({"llm": {}, "agent": {},
                                        "error": f"配置读取失败: {e}"})
        if path == "/api/findings":
            return self._send_json(self._findings_all(get_db(), qs))
        # GET /api/finding/<node_id> -> 漏洞详情（POC / 回显 / 验证历史）
        if path.startswith("/api/finding/"):
            nid = path[len("/api/finding/"):]
            if not nid:
                return self._send_json({"ok": False, "error": "缺少漏洞 ID"}, 400)
            return self._send_json(self._finding_detail(get_db(), nid))
        # GET /api/vulns/jobs -> 最近漏洞作业
        if path == "/api/vulns/jobs":
            from . import jobs
            return self._send_json({"jobs": jobs.list_jobs()})
        # GET /api/vulns/job/<job_id> -> 作业进度
        if path.startswith("/api/vulns/job/"):
            from . import jobs
            jid = path[len("/api/vulns/job/"):]
            j = jobs.get_job(jid)
            if not j:
                return self._send_json({"ok": False, "error": f"作业不存在: {jid}"}, 404)
            return self._send_json({"ok": True, "job": j})
        if path == "/api/traffic":
            return self._send_json(self._traffic_all(get_db(), qs))
        if path == "/api/logs":
            return self._send_json(self._logs_all(get_db(), qs))
        if path == "/api/approvals/records":
            return self._send_json(self._approval_records(get_db(), qs))

        db = get_db()
        ss = SessionStore(db)

        if path == "/api/tasks":
            return self._send_json({"tasks": ss.list_tasks()})
        if path == "/api/stats":
            ag = AssetGraph(db)
            try:
                from ..context import cache_stats
                cache = cache_stats()
            except Exception:
                cache = {}
            return self._send_json({"assets": ag.stats(),
                                    "tasks": len(ss.list_tasks()),
                                    "cache": cache})
        if path == "/api/asset_graph":
            try:
                lim = int((qs.get("limit") or ["0"])[0] or 0)
            except Exception:
                lim = 0
            return self._send_json(AssetGraph(db).graph(limit=lim or None))
        if path == "/api/coverage":
            return self._send_json(AssetGraph(db).coverage())

        # GET /api/assets -> 资产清单（分页，避免一次拉取全量节点卡死）
        #   ?page=&page_size=&kind=&task_id=&q=
        if path == "/api/assets":
            return self._send_json(self._assets_all(get_db(), qs))

        # GET /api/asset/<id> -> 资产节点详情（双图悬浮/双击弹窗用）
        if path.startswith("/api/asset/"):
            return self._send_json(AssetGraph(db).detail(path[len("/api/asset/"):]))

        if path.startswith("/api/task/"):
            parts = path[len("/api/task/"):].split("/")
            task_id = parts[0]
            sub = parts[1] if len(parts) > 1 else "overview"
            return self._task_route(db, ss, task_id, sub, qs, parts)

        self.send_error(404, "Not Found")

    def _task_route(self, db, ss, task_id, sub, qs, parts=None):
        parts = parts or []
        # GET /api/task/<id>/report?format=md|html|json
        if sub == "report":
            from ..report import task_report
            fmt = (qs.get("format") or ["html"])[0].lower()
            if fmt not in ("md", "markdown", "html", "json"):
                fmt = "html"
            rep = task_report(task_id, "html" if fmt == "markdown" else fmt)
            if not rep.get("ok"):
                return self._send_json(rep, 404)
            if fmt in ("md", "markdown"):
                return self._send_text(
                    rep["content"], "text/markdown; charset=utf-8",
                    f"report-{task_id}.md")
            if fmt == "json":
                return self._send_json(rep["content"])
            return self._send_text(rep["content"], "text/html; charset=utf-8")

        # GET /api/task/<id>/node/<nid> -> 探索图节点详情
        if sub == "node" and len(parts) > 2:
            return self._send_json(
                ExplorationGraph(db, task_id).detail(parts[2]))
        # GET /api/task/<id>/approvals -> 待审批队列（人在环路）
        if sub == "approvals":
            from ..human_gate import get_gate
            return self._send_json({"approvals": get_gate().pending(task_id),
                                    "require_approval": bool(
                                        (ss.get_task(task_id) or {})
                                        .get("config", {}).get("require_approval", False))})

        if sub == "overview":
            from . import runner
            ov = ss.overview(task_id)
            eg = ExplorationGraph(db, task_id)
            findings = eg.findings()
            g = eg.graph()
            ov["intents"] = len([n for n in g["nodes"] if n["kind"] == "intent"])
            ov["findings_count"] = len(findings)
            ov["facts_count"] = len([n for n in g["nodes"] if n["kind"] == "fact"])
            ov["running"] = runner.is_running(task_id)
            return self._send_json(ov)
        if sub == "findings":
            return self._send_json({"findings": ExplorationGraph(db, task_id).findings()})
        if sub == "exploration":
            return self._send_json(ExplorationGraph(db, task_id).graph())
        if sub == "events":
            limit = int((qs.get("limit") or ["150"])[0])
            return self._send_json({"events": ss.events(task_id, limit)})
        if sub == "toolcalls":
            return self._send_json({"tool_calls": ss.tool_calls(task_id)})
        if sub == "assets":
            ag = AssetGraph(db)
            kind = (qs.get("kind") or [None])[0]
            return self._send_json({"assets": ag.list_assets(kind)})
        self.send_error(404, "Unknown task route")


def create_server(host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    # 启动即复位孤儿运行中任务（进程被强杀后 DB 残留 running 的情况）
    try:
        from . import runner
        runner.reconcile_orphaned_tasks()
    except Exception:
        pass
    # 进程级出网落地：技能自建 HTTP 会话 / curl 等子进程统一遵循出网模式
    try:
        from ..egress_patch import install as _install_egress
        st = _install_egress()
        print(f"[WebUI] 出网补丁: requests={st.get('requests')} "
              f"aiohttp={st.get('aiohttp')} mode={((st.get('egress') or {}).get('mode'))}")
    except Exception as e:
        print(f"[WebUI] 出网补丁安装失败（技能可能直连）: {e}")
    return ThreadingHTTPServer((host, port), ApiHandler)


def serve(host: str = "127.0.0.1", port: int = 8787, background: bool = False):
    httpd = create_server(host, port)
    print(f"[WebUI] 仪表盘已启动: http://{host}:{port}")
    if background:
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        return httpd, t
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    return httpd, None
