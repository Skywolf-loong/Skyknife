"""
工具层 ToolRegistry —— 复用现有 skills/ 与 core/ 执行器，统一给 Worker 调用。

工具分两类：
  * skill    ：项目原有 Skill（port_scan / dns_enum / nmap ... 由 skills/ 提供）
  * command  ：本地 Shell 命令（core.executor.execute_command）
  * http     ：轻量 HTTP 客户端（GET/POST），便于快速探测
"""
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# worker 过程检索工具（只读；依赖由 context 注入，见 ToolRegistry._run_trace_tool）
_TRACE_TOOLS = frozenset({
    "search_all_worker_traces", "list_worker_traces", "get_worker_trace",
})

# ---- 越界防护（scope guard）：任务只允许打自己的目标 ----
_URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9._-]+)(?::\d+)?", re.I)
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HOST_KEYS = {"url", "host", "hostname", "domain", "ip", "target",
              "base_url", "base", "site", "endpoint", "webapp"}
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def _extract_hosts(value: Any, key: str = None, out: Optional[set] = None) -> set:
    """从参数值（可嵌套）里提取所有可能出现的目标主机名/IP。"""
    if out is None:
        out = set()
    if isinstance(value, dict):
        for k, v in value.items():
            _extract_hosts(v, str(k).lower(), out)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            _extract_hosts(v, key, out)
    elif isinstance(value, str):
        for m in _URL_HOST_RE.finditer(value):
            out.add(m.group(1).lower())
        if key in _HOST_KEYS:
            v = value.strip().lower()
            v = re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0].rstrip(".")
            if v and (("." in v) or v in _LOCAL_HOSTS):
                out.add(v)
    return out


def _host_allowed(host: str, allowed) -> bool:
    """host 是否落在允许范围内：精确匹配 / 子域 / 本机回环（OOB 接收端等）。"""
    h = (host or "").lower().rstrip(".")
    if not h or h in _LOCAL_HOSTS:
        return True
    for a in allowed or ():
        a = str(a).lower().strip().lstrip("*.").rstrip(".")
        if not a:
            continue
        if h == a or h.endswith("." + a):
            return True
    return False


class ToolRegistry:
    def __init__(self, skills_dir: str = "skills"):
        self.skill_mgr = None
        self._skill_info: Dict[str, dict] = {}
        self._load_skills(skills_dir)
        # 进程级出网补丁：让技能自建的 requests/aiohttp 会话、以及 curl 等子进程
        # 都遵循统一出网模式（否则只有 tools 自带 http 走代理，其余直连）。
        try:
            from .egress_patch import install as _install_egress
            _install_egress()
        except Exception as e:  # pragma: no cover
            print(f"[ToolRegistry] 出网补丁安装失败（仅影响技能走代理）: {e}")

    def _load_skills(self, skills_dir: str):
        try:
            from core.skill_manager import SkillManager  # type: ignore
            self.skill_mgr = SkillManager(skills_dir, recursive=True)
            try:
                self._skill_info = self.skill_mgr.get_skills_info()
            except Exception:
                self._skill_info = {n: {"description": d, "parameters": {}, "required": []}
                                    for n, d in self.skill_mgr.list_skills().items()}
        except Exception as e:  # pragma: no cover
            print(f"[ToolRegistry] skills 加载失败（将以 command/http 模式运行）: {e}")
            self.skill_mgr = None

    # ---------- 描述 ----------
    def _skill_kind(self, name: str) -> str:
        """返回 Skill 的类别：knowledge（纯知识，默认不进提示词）/ 其它。"""
        cls = self.skill_mgr.get_skill(name) if self.skill_mgr else None
        return str(getattr(cls, "kind", "executable") or "executable")

    def list_tools(self, include_knowledge: bool = False) -> List[dict]:
        """工具清单。

        默认**排除** kind="knowledge" 的纯知识型 Skill（如 Claude-Red 的 77 个方法论
        Skill）：它们数量多且不执行动作，若进提示词会把 http/command 等可执行工具
        挤出 max_tools 截断范围。它们仍可按名字直接 `run()`，或经 claude_red_index
        检索后发现。
        """
        try:
            from .skill_admin import disabled_set
            _disabled = disabled_set()
        except Exception:
            _disabled = set()
        tools = []
        if self.skill_mgr:
            for name, info in self._skill_info.items():
                if not include_knowledge and self._skill_kind(name) == "knowledge":
                    continue
                if name in _disabled:
                    continue
                tools.append({
                    "name": name,
                    "type": "skill",
                    "kind": self._skill_kind(name),
                    "description": info.get("description", ""),
                    "parameters": info.get("parameters", {}),
                    "required": info.get("required", []),
                })
        tools.append({"name": "command", "type": "command",
                      "description": "执行本地 Shell 命令（nmap/nuclei/curl 等）",
                      "parameters": {"command": {"type": "string", "required": True,
                                                 "description": "要执行的命令"}},
                      "required": ["command"]})
        tools.append({"name": "http", "type": "http",
                      "description": "轻量 HTTP 请求（method/url/headers/data）",
                      "parameters": {
                          "method": {"type": "string", "default": "GET"},
                          "url": {"type": "string", "required": True},
                          "headers": {"type": "object"},
                          "data": {"type": "string"}},
                      "required": ["url"]})
        # 自定义专家子代理：存在已启用的自定义子代理时，暴露 invoke_agent 供主 Agent 委派
        try:
            from .agent_admin import custom_agents
            _custom = custom_agents(enabled_only=True)
        except Exception:
            _custom = []
        if _custom:
            tools.append({"name": "invoke_agent", "type": "agent", "kind": "agent",
                          "description": ("委派给自定义专家子代理（提示词由用户编写）。"
                                          "args: agent=子代理名称, task=要它完成的子任务"),
                          "parameters": {"agent": {"type": "string", "required": True,
                                                   "description": "自定义子代理名称"},
                                         "task": {"type": "string", "required": True,
                                                  "description": "委派的子任务"}},
                          "required": ["agent", "task"]})
        # 过程检索工具：让 worker 能读到同任务其它 work 的中间观察，
        # 避免有价值但未沉淀成 fact 的线索随会话丢失。
        if getattr(self, "enable_trace_tools", True):
            tools.append({"name": "search_all_worker_traces", "type": "trace",
                          "description": ("在本任务**其它** work 的执行过程里按关键字检索"
                                          "（自动排除自己）。用于找回报错、响应片段、隐藏参数等"
                                          "未沉淀为 fact 的中间观察。"),
                          "parameters": {"query": {"type": "string", "required": True},
                                         "limit": {"type": "integer", "default": 20}},
                          "required": ["query"]})
            tools.append({"name": "list_worker_traces", "type": "trace",
                          "description": "列出本任务已有哪些 work 跑过（intent_id、步数、预览）。",
                          "parameters": {}, "required": []})
            tools.append({"name": "get_worker_trace", "type": "trace",
                          "description": "取某个 work 具体步骤的完整过程内容。",
                          "parameters": {"intent_id": {"type": "string", "required": True},
                                         "step_ids": {"type": "array"}},
                          "required": ["intent_id"]})
        return tools

    # ---------- worker 跨 work 过程检索（只读，靠 context 注入依赖） ----------
    def _run_trace_tool(self, tool: str, args: Dict[str, Any],
                        context: Dict) -> Dict:
        """三类只读的过程检索工具。

        依赖通过 context 注入（trace_store / task_id / intent_id），避免在 ToolRegistry
        里持有全局状态；没有注入时明确报错，而不是静默返回空。
        """
        store = context.get("trace_store")
        if store is None:
            return {"status": "error",
                    "message": "当前上下文不支持过程检索（未注入 trace_store）"}

        if tool == "search_all_worker_traces":
            q = str(args.get("query") or args.get("q") or "").strip()
            if not q:
                return {"status": "error", "message": "缺少检索关键字 query"}
            limit = int(args.get("limit") or 20)
            # 默认排除调用者自己的 intent，避免自我干扰
            hits = store.search(q, exclude_intent_id=context.get("intent_id"),
                                limit=limit)
            return {"status": "ok", "data": {"hits": hits, "count": len(hits),
                                             "query": q}}

        if tool == "list_worker_traces":
            return {"status": "ok", "data": {"traces": store.list_traces()}}

        if tool == "get_worker_trace":
            intent_id = str(args.get("intent_id") or "").strip()
            if not intent_id:
                return {"status": "error", "message": "缺少 intent_id"}
            step_ids = args.get("step_ids")
            if isinstance(step_ids, str):
                step_ids = [int(x) for x in step_ids.replace(" ", "").split(",")
                            if x.isdigit()]
            steps = store.get_trace(intent_id, step_ids)
            return {"status": "ok", "data": {"intent_id": intent_id,
                                             "steps": steps, "count": len(steps)}}

        return {"status": "error", "message": f"未知过程检索工具: {tool}"}

    def tool_digest(self, max_tools: int = 60, include_knowledge: bool = False) -> str:
        """生成给 LLM 看的工具清单文本。

        include_knowledge=False（默认）：不含纯知识型 Skill，保证可执行工具不被
        max_tools 截断挤出。
        """
        lines = []
        for t in self.list_tools(include_knowledge=include_knowledge)[:max_tools]:
            req = ",".join(t.get("required") or [])
            kind = f"/{t['kind']}" if t.get("kind") == "index" else ""
            lines.append(f"- {t['name']} [{t['type']}{kind}] {t['description']}"
                         + (f" (必填: {req})" if req else ""))
        return "\n".join(lines)

    def knowledge_tools(self) -> List[dict]:
        """返回纯知识型 Skill 清单（供检索/展示，不进提示词）。"""
        return [t for t in self.list_tools(include_knowledge=True)
                if t.get("kind") == "knowledge"]

    def has_skill(self, name: str) -> bool:
        return bool(self.skill_mgr and self.skill_mgr.get_skill(name))

    # ---------- 参数规范化（LLM 常把 object/array/integer 写成字符串） ----------
    def _schema(self, tool: str) -> Dict:
        info = self._skill_info.get(tool)
        if isinstance(info, dict):
            return info.get("parameters") or {}
        return {}

    @staticmethod
    def _coerce(value: Any, decl: Any) -> Any:
        """按 schema 声明把参数值修正为正确类型；无法识别时原样返回。"""
        if not isinstance(decl, dict):
            return value
        t = (decl.get("type") or "").lower()

        if t == "object":
            if isinstance(value, dict):
                return value
            if value is None:
                return {}
            if isinstance(value, str):
                s = value.strip()
                if not s:
                    return {}
                try:
                    d = json.loads(s)
                    if isinstance(d, dict):
                        return d
                except Exception:
                    pass
                if "=" in s:                      # query string: a=1&b=2
                    out = {}
                    for part in s.split("&"):
                        if not part:
                            continue
                        k, _, v = part.partition("=")
                        out[unquote(k)] = unquote(v)
                    return out
                return {s: "1"}                    # 单个参数名
            if isinstance(value, (list, tuple, set)):
                return {str(x): "1" for x in value}
            return {}

        if t == "array":
            if isinstance(value, list):
                return value
            if value is None:
                return []
            if isinstance(value, tuple):
                return list(value)
            if isinstance(value, str):
                s = value.strip()
                if not s:
                    return []
                try:
                    v = json.loads(s)
                    if isinstance(v, list):
                        return v
                except Exception:
                    pass
                return [x.strip() for x in s.split(",") if x.strip()]
            return [value]

        if t == "integer":
            try:
                return int(value)
            except (TypeError, ValueError):
                return value

        if t == "number":
            try:
                return float(value)
            except (TypeError, ValueError):
                return value

        if t == "boolean":
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.strip().lower() in ("1", "true", "yes", "on")
            return bool(value)

        if t == "string":
            if isinstance(value, (dict, list)):
                return json.dumps(value, ensure_ascii=False)
            return value if value is None else str(value)

        return value

    def normalize_args(self, tool: str, args: Dict) -> Dict:
        """按工具 schema 规范化参数类型。"""
        if not isinstance(args, dict):
            return {}
        schema = self._schema(tool)
        if not schema:
            return args
        out = dict(args)
        for k, v in list(out.items()):
            if k in schema:
                out[k] = self._coerce(v, schema[k])
        return out

    def missing_required(self, tool: str, args: Dict) -> List[str]:
        """返回缺失的必填参数名列表。"""
        schema = self._schema(tool)
        args = args if isinstance(args, dict) else {}
        miss = []
        for k, decl in (schema or {}).items():
            if isinstance(decl, dict) and decl.get("required"):
                v = args.get(k)
                if v is None or (isinstance(v, (str, list, dict)) and len(v) == 0):
                    miss.append(k)
        return miss

    # ---------- 执行 ----------
    # 这批技能在 TCP/UDP 层建连（不是 HTTP 请求），HTTP 代理 / Tor 出口无法转发
    _TCP_SKILLS = frozenset({"port_scan", "service_detect", "ssl_info", "weak_ssl",
                             "dns_enum", "whois_lookup", "subdomain_brute"})
    _TCP_CMD_RE = re.compile(
        r"\b(nmap|masscan|zmap|rustscan|nc|netcat|telnet|hping3|"
        r"openssl\s+s_client)\b", re.I)

    def run(self, tool: str, args: Dict[str, Any], context: Dict = None) -> Dict:
        """统一执行入口：同步出网环境 → 限速/并发闸门 → 执行 → 标注出口情况。"""
        args = args or {}
        try:
            from .egress_config import apply_env
            apply_env()          # 1 秒缓存；切换出网模式后最多 1 秒内生效
        except Exception:
            pass
        host = ""
        try:
            hosts = _extract_hosts(args)
            host = sorted(hosts)[0] if hosts else ""
        except Exception:
            host = ""
        scope = None
        try:
            from .rate_limit import limit_scope
            scope = limit_scope(host=host, tool=tool)
        except Exception:
            scope = None
        if scope is None:
            res = self._dispatch(tool, args,
                                 context if context is not None else {})
        else:
            with scope:
                res = self._dispatch(tool, args,
                                     context if context is not None else {})
        return self._annotate_egress(tool, args, res)

    def _annotate_egress(self, tool: str, args: Dict, res: Dict) -> Dict:
        """给工具结果标注出网情况（供 Worker / 界面 / 报告判断是否经代理）。"""
        if not isinstance(res, dict):
            return res
        try:
            from .egress_config import env_state, get_egress_mode
            mode = get_egress_mode()
            st = env_state()
        except Exception:
            return res
        cmd = str(args.get("command") or args.get("cmd") or "")
        tcp = tool in self._TCP_SKILLS or (tool == "command" and
                                           bool(self._TCP_CMD_RE.search(cmd)))
        tunnel = False
        try:
            from .egress_net import proxy_tunnel
            tunnel = proxy_tunnel()
        except Exception:
            tunnel = False
        direct = tcp and not tunnel
        res["egress"] = {"mode": mode, "proxied": bool(st.get("applied")) and not direct,
                         "tcp_direct": direct, "tcp_tunnel": bool(tcp and tunnel)}
        if res.get("egress_cmd"):
            res["egress"]["cmd_note"] = res["egress_cmd"]
        if tcp and mode != "none" and not tunnel:
            note = ("［出网提示］该工具在 TCP/UDP 层直连（端口扫描 / DNS / WHOIS / TLS 握手 / "
                    "外部二进制），HTTP 代理与 Tor 出口无法转发这类流量，目标侧会看到本机真实 IP；"
                    "HTTP(S) 探测仍按当前出网模式经代理。")
            res["egress_note"] = note
            for k in ("response", "message"):
                if isinstance(res.get(k), str) and note not in res[k]:
                    res[k] = res[k] + "\n" + note
        return res

    def _dispatch(self, tool: str, args: Dict[str, Any], context: Dict = None) -> Dict:
        context = context if context is not None else {}
        args = args or {}
        # ---- 越界防护：context["allowed_hosts"] 存在时，参数里出现范围外主机直接拒绝 ----
        allowed = context.get("allowed_hosts")
        if allowed:
            bad = self._scope_violation(tool, args, allowed)
            if bad:
                msg = (f"越界拦截：{tool} 的参数试图访问范围外主机 {bad}。"
                       f"本任务只允许攻击: {', '.join(sorted(map(str, allowed)))}。"
                       f"请严格针对本任务目标重新规划。")
                return {"status": "error", "scope_violation": True,
                        "message": msg, "request": f"{tool} {json.dumps(args, ensure_ascii=False)[:300]}",
                        "response": msg}
        try:
            if tool == "command":
                return self._run_command(args)
            if tool == "http":
                return self._run_http(args)
            if tool in _TRACE_TOOLS:
                return self._run_trace_tool(tool, args, context)
            if self.skill_mgr and self.skill_mgr.get_skill(tool):
                # 统一做参数类型规范化，避免 LLM 把 object/array 写成字符串导致 skill 崩溃
                args = self.normalize_args(tool, args)
                args = self._inject_skill_proxy(tool, args)
                try:                     # 扫描类技能的并发封顶（限速的一部分）
                    from .rate_limit import cap_threads
                    args = cap_threads(tool, args)
                except Exception:
                    pass
                miss = self.missing_required(tool, args)
                if miss:
                    return {"status": "error", "request": f"skill {tool}(args={json.dumps(args, ensure_ascii=False)[:500]})",
                            "response": f"缺少必需参数: {', '.join(miss)}",
                            "message": f"缺少必需参数: {', '.join(miss)}",
                            "hint": f"{tool} 需要参数: {miss}"}
                res = self.skill_mgr.execute(tool, args, context)
                if not isinstance(res, dict):
                    return {"status": "success",
                            "request": f"skill {tool}(args={json.dumps(args, ensure_ascii=False)[:500]})",
                            "response": str(res)[:8000], "data": res}
                # 统一补齐返回结构，便于 Worker 与界面消费
                res.setdefault("status", "success")
                res.setdefault("request", f"skill {tool}(args={json.dumps(args, ensure_ascii=False)[:500]})")
                if "response" not in res and "data" in res:
                    res["response"] = json.dumps(res["data"], ensure_ascii=False)[:8000]
                return res
            # 未知工具 → 当作命令兜底（很多意图其实是命令）
            if "command" in args:
                return self._run_command(args)
            return {"status": "error", "message": f"未知工具: {tool}",
                    "request": f"tool={tool}", "response": f"未知工具: {tool}"}
        except Exception as e:
            return {"status": "error", "message": f"工具执行异常: {e}",
                    "request": f"tool={tool}", "response": f"工具执行异常: {e}"}

    # ---------- 越界防护实现 ----------
    @staticmethod
    def _scope_violation(tool: str, args: Dict, allowed) -> Optional[str]:
        """返回第一个越界主机；无越界返回 None。"""
        if tool in _TRACE_TOOLS:
            return None  # 过程检索是本地只读，无网络目标
        hosts = _extract_hosts(args)
        if tool == "command":
            # 命令串额外提取裸 IP（nmap 1.2.3.4 等无 scheme 场景）
            cmd = str(args.get("command") or "")
            for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", cmd):
                hosts.add(m.group(1))
        for h in hosts:
            if not _host_allowed(h, allowed):
                return h
        return None

    # 常见 CLI 的代理参数（命令类工具不读工作台配置，只能显式注入）
    _PROXY_ARG_TMPL = {
        "curl": '--proxy "{u}"',
        "sqlmap": '--proxy="{u}"',
        "nuclei": '-proxy "{u}"',
        "gobuster": '--proxy "{u}"',
        "feroxbuster": '--proxy "{u}"',
        "ffuf": '-x "{u}"',
        "dirsearch": '--proxy "{u}"',
    }

    @staticmethod
    def _cmd_root(cmd: str) -> str:
        for tok in re.split(r"\s+", str(cmd or "").strip()):
            base = tok.strip('"\'').lower()
            base = base.replace("\\", "/").rsplit("/", 1)[-1]
            if base.endswith(".exe"):
                base = base[:-4]
            if base in ("sudo", "env", "timeout", "start", "cmd"):
                continue
            return base
        return ""

    # 支持 --proxy 参数的技能：参数的键名（命令类/外部二进制不读环境变量）
    _PROXY_SKILL_ARGS = {"p1finger": "proxy"}

    def _inject_skill_proxy(self, tool: str, args: Dict) -> Dict:
        """给支持 proxy 参数的技能补上当前代理（如 p1finger 的 --proxy）。"""
        key = self._PROXY_SKILL_ARGS.get(tool)
        if not key or args.get(key):
            return args
        try:
            from .egress_config import resolve_proxy
            url = str((resolve_proxy() or {}).get("http") or "")
        except Exception:
            url = ""
        if not url:
            return args
        args = dict(args)
        args[key] = url
        return args

    def _apply_proxy_to_cmd(self, cmd: str, url: str) -> tuple:
        """给 command 注入代理参数，并移除显式绕过（--noproxy / --no-proxy）。"""
        if not url:
            return cmd, []
        notes = []
        new = re.sub(r'\s--noproxy(?:\s+|=)("[*]"|\'*\'|\*)', "", cmd)
        new = re.sub(r'\s--no-proxy\b', "", new)
        if new != cmd:
            notes.append("已移除 --noproxy/--no-proxy（出网由工作台统一裁决）")
        root = self._cmd_root(new)
        tmpl = self._PROXY_ARG_TMPL.get(root)
        if tmpl:
            has = re.search(r"(^|\s)(--proxy(=|\s)|-x\s|-useproxy)", new)
            if not has:
                new = new.rstrip() + " " + tmpl.format(u=url)
                notes.append(f"已为 {root} 注入代理参数")
        return new, notes

    def _run_command(self, args: Dict) -> Dict:
        from core.executor import execute_command  # type: ignore
        cmd = args.get("command") or args.get("cmd") or ""
        if not cmd:
            return {"status": "error", "message": "缺少 command",
                    "request": "(空命令)", "response": "缺少 command"}
        timeout = int(args.get("timeout", 60))
        # 子进程（curl/sqlmap/nuclei…）不读工作台配置：注入代理参数 + 移除显式绕过
        proxy_url, proxy_notes = "", []
        try:
            from .egress_config import resolve_proxy
            proxy_url = str((resolve_proxy() or {}).get("http") or "")
        except Exception:
            proxy_url = ""
        if proxy_url:
            # 无法经代理的裸 TCP 扫描器（masscan/nc/hping3…）直接拦下，避免暴露真实 IP
            try:
                from .egress_net import guard_command
                blocked = guard_command(cmd)
                if blocked:
                    return {"status": "error", "blocked_by": "egress_guard",
                            "request": f"$ {cmd}", "response": blocked,
                            "message": blocked}
            except Exception:
                pass
            try:
                cmd, proxy_notes = self._apply_proxy_to_cmd(cmd, proxy_url)
            except Exception:
                proxy_notes = []
            try:
                from .egress_net import rewrite_command
                from .rate_limit import command_rate
                cmd, more = rewrite_command(cmd, proxy_url, command_rate())
                proxy_notes = list(proxy_notes) + list(more)
            except Exception:
                pass
        request = f"$ {cmd}" + (f"  (timeout={timeout}s)" if timeout else "")
        if proxy_notes:
            request += "\n[Egress] " + "；".join(proxy_notes)
        try:
            out = execute_command(cmd, timeout=timeout)
        except Exception as e:
            return {"status": "error", "request": request, "response": f"执行异常: {e}",
                    "message": f"执行异常: {e}"}
        status = "error" if (isinstance(out, str) and out.startswith("[错误]")) else "success"
        response = (out or "")[:8000]
        res = {"status": status, "data": {"output": out}, "output": out,
               "request": request, "response": response, "exit_code": None}
        if proxy_notes:
            res["egress_cmd"] = proxy_notes
        return res

    def _run_http(self, args: Dict) -> Dict:
        import requests
        method = (args.get("method") or "GET").upper()
        url = args.get("url")
        if not url:
            return {"status": "error", "message": "缺少 url",
                    "request": f"{method} (无 url)", "response": "缺少 url"}
        headers = args.get("headers") or {}
        data = args.get("data")
        req_lines = [f"{method} {url} HTTP/1.1"]
        for k, v in (headers.items() if isinstance(headers, dict) else []):
            req_lines.append(f"{k}: {v}")
        if data:
            req_lines.append("")
            req_lines.append(str(data)[:4000])
        request = "\n".join(req_lines)
        try:
            # 统一出网模式裁决：none 直连 / pool 代理池 / tor 出口代理
            # 该模式是唯一的代理路由控制者（见 agent6/egress_config.py）
            proxies = {}
            egress_mode = "none"
            try:
                from .egress_config import get_egress_mode, resolve_proxy
                egress_mode = get_egress_mode() or "none"
                proxies = resolve_proxy() or {}
            except Exception:
                proxies = {}
            if egress_mode == "tor" and proxies:
                req_lines.append("Egress-Mode: tor（流量经出口代理→Tor）")
            elif egress_mode == "pool" and proxies:
                req_lines.append("Egress-Mode: pool（流量经代理池）")
            else:
                req_lines.append("Egress-Mode: none（直连）")
            kwargs = dict(timeout=args.get("timeout", 20), verify=False)
            if proxies:
                kwargs["proxies"] = proxies
                req_lines.append(f"Via-Proxy: {proxies.get('http', '')}")
                request = "\n".join(req_lines)
            resp = requests.request(method, url, headers=headers, data=data, **kwargs)
            body = resp.text[:20000]
            status_line = f"HTTP/1.1 {resp.status_code}"
            resp_lines = [status_line]
            for k, v in resp.headers.items():
                resp_lines.append(f"{k}: {v}")
            resp_lines.append("")
            resp_lines.append(body[:8000])
            return {"status": "success",
                    "data": {"status_code": resp.status_code, "headers": dict(resp.headers),
                             "body": body, "length": len(resp.text)},
                    "request": request, "response": "\n".join(resp_lines)}
        except Exception as e:
            return {"status": "error", "message": f"HTTP 请求失败: {e}",
                    "request": request, "response": f"HTTP 请求失败: {e}"}
