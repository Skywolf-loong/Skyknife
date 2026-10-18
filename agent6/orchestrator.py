"""
Orchestrator —— 编排循环。

闭环：Planner 下发意图 → Worker 执行工具 → 结果写回双图 → Planner 读取新态势 →
      生成下一轮意图，持续迭代直到目标达成或无新攻击面。

对应 ARTEX 的探索-决策-执行-写回 完整自动闭环。
"""
import json
import re
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from .agents import Auditor, Planner, Worker
from .ingest import heuristic_extract, ingest_assets
from .planning_todo import PlanningTodo
from .store import AssetGraph, ExplorationGraph, SessionStore
from .store.db import get_db
from .store.trace_store import TraceStore


class Orchestrator:
    def __init__(self, llm, tool_registry, task_id: str, target: str,
                 scope: str = "", mode: str = "SRC", max_rounds: int = 20,
                 max_workers: int = 3, planner_max_intents: int = 5,
                 worker_max_steps: int = 5, db=None, require_approval: bool = False,
                 approval_timeout: int = 180, token_budget: int = 0,
                 logic_agent: bool = True, context_compress: bool = True,
                 compress_every: int = 3, chain_review: bool = True):
        self.llm = llm
        self.tools = tool_registry
        self.task_id = task_id
        self.target = target
        self.scope = scope or target
        self.mode = mode
        self.max_rounds = max_rounds
        self.max_workers = max_workers
        self.db = db or get_db()
        self.require_approval = require_approval
        self.approval_timeout = approval_timeout
        self.token_budget = token_budget  # 0 = 不限
        # 业务逻辑专项 agent：主流程信息搜集完成后自动介入
        self.logic_enabled = bool(logic_agent)
        self.logic_summary: Dict = {}
        # 攻击链复盘员：任务结束后自动复盘并把攻击链写入记忆文件（下次任务参考）
        self.chain_review_enabled = bool(chain_review)
        self.chain_summary: Dict = {}
        self._chain_memory = ""
        self._chain_hint_used = False
        # 上下文压缩：每 N 轮把较早的事实折叠为摘要，控制 token
        self.context_compress = bool(context_compress)
        self.compress_every = max(1, int(compress_every or 3))

        self.ag = AssetGraph(self.db)
        self.eg = ExplorationGraph(self.db, task_id)
        self.ss = SessionStore(self.db)
        # planner 跨唤醒共享的规划待办 + worker 过程存储（均可重启后继续）
        self.todo = PlanningTodo(self.db, task_id)
        self.traces = TraceStore(self.db, task_id)

        self.planner = Planner(llm, tool_registry, self.ss, task_id, mode, planner_max_intents)
        self.worker = Worker(llm, tool_registry, mode, worker_max_steps,
                             task_id=task_id, require_approval=require_approval,
                             approval_timeout=approval_timeout)
        self.auditor = Auditor()

        self.stopped = False
        self.round = 0
        # 收敛跟踪：连续无新增产出的轮数
        self._stale_rounds = 0
        self._last_knowledge = None
        self._last_audit = None

    # ---------- 工具 ----------
    def _log(self, etype, msg, actor="system", data=None):
        self.ss.add_event(self.task_id, etype, msg, actor, data)
        print(f"[{self.task_id}] [{actor}/{etype}] {msg}")

    def _existing_labels(self) -> set:
        return {n["label"] for n in self.eg.intents()}

    def _existing_sigs(self) -> set:
        """已下发意图的 (tool,args) 签名集合——同签名意图不再重复下发。"""
        sigs = set()
        for n in self.eg.intents():
            d = n.get("data") or {}
            if d.get("_sig"):
                sigs.add(d["_sig"])
            else:
                sigs.add(self._intent_sig(d.get("tool"), d.get("args")))
        return sigs

    @staticmethod
    def _intent_sig(tool, args) -> str:
        try:
            return json.dumps({"t": tool or "", "a": args or {}},
                              sort_keys=True, ensure_ascii=False)
        except Exception:
            return json.dumps({"t": str(tool), "a": str(args)}, ensure_ascii=False)

    # 可辨认的主机形态：域名（含多级）或 IPv4
    _DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
    _IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    # 常见二级域后缀：取主域时要保留三段（如 www.example.edu.cn → example.edu.cn）
    _SLD_SUFFIX = {"com.cn", "net.cn", "gov.cn", "edu.cn", "org.cn", "ac.cn",
                   "co.uk", "com.hk", "com.tw", "com.au", "co.jp"}

    @staticmethod
    def _registrable(host: str) -> str:
        """取注册主域：www.example.edu.cn → example.edu.cn（处理 edu.cn 类后缀）。"""
        parts = host.rstrip(".").split(".")
        if len(parts) >= 3 and ".".join(parts[-2:]) in Orchestrator._SLD_SUFFIX:
            return ".".join(parts[-3:])
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host

    @staticmethod
    def _norm_host(raw: str) -> str:
        p = str(raw or "").strip().lower()
        p = re.sub(r"^[a-z]+://", "", p).split("/")[0].split(":")[0].rstrip(".")
        return p

    def _allowed_hosts(self) -> list:
        """本任务允许攻击的主机范围（供工具层越界拦截）。

        只把**形如域名/IP**的词当放行目标；scope 是「中南大学名下所有网络资产」
        这类自然语言描述时不参与匹配。当 target 是子域且 scope 没有任何显式
        域名时，自动放行其注册主域（宽泛 scope 的常见语义），否则兄弟子域会被
        误拦。解析不出任何有效主机时返回 []（不启用拦截，避免全拦）。
        """
        hosts = set()
        for raw in (self.target, self.scope):
            for part in re.split(r"[,;\s]+", str(raw or "")):
                p = self._norm_host(part)
                if p and (self._DOMAIN_RE.match(p) or self._IPV4_RE.match(p)):
                    hosts.add(p)
        if not hosts:
            return []
        t = self._norm_host(self.target)
        has_domain_scope = any("." in h for h in hosts if h != t)
        if t and self._DOMAIN_RE.match(t) and "." in t and not has_domain_scope:
            hosts.add(self._registrable(t))
        return sorted(hosts)

    @staticmethod
    def _asset_host(key: str) -> str:
        """资产 key（dom:xxx / ip:x.x.x.x / domain:xxx ...）→ 纯主机名。"""
        k = str(key or "").strip().lower()
        k = re.sub(r"^(root_domain|subdomain|domain|dom|host|webapp|ip):", "", k)
        return Orchestrator._norm_host(k)

    def _scope_resolved_ips(self) -> set:
        """资产图里由 **scope 内域名** 解析出的 IP（resolves_to 边）。

        越界拦截只按主机名做字符串匹配；Worker 在 DNS 解析之后经常直接用
        「目标自己的 IP」做端口扫描 / 服务识别，会被误拦（例如某任务解析出
        sub.example.com -> 1.2.3.4，再对 IP 发起 port_scan 就被拦）。
        这里把 scope 覆盖域名解析出的 IP 一并加入放行名单。
        """
        out = set()
        try:
            allowed = set(self._allowed_hosts())
            if not allowed:
                return out
            rows = self.db.query(
                "SELECT a1.key AS dom, a2.key AS ip FROM asset_edges e"
                " JOIN assets a1 ON a1.id = e.src_id"
                " JOIN assets a2 ON a2.id = e.dst_id"
                " WHERE e.rel = 'resolves_to'")
            for r in rows:
                dom = self._asset_host(r["dom"])
                ip = self._asset_host(r["ip"])
                if not self._IPV4_RE.match(ip):
                    continue
                for a in allowed:
                    if dom == a or dom.endswith("." + a):
                        out.add(ip)
                        break
        except Exception:
            pass
        return out

    def _allowed_hosts_full(self) -> list:
        """放行名单 = scope 主机 + scope 域名已解析出的 IP（防误伤自己目标）。"""
        try:
            merged = set(self._allowed_hosts()) | self._scope_resolved_ips()
        except Exception:
            return self._allowed_hosts()
        return sorted(merged)

    def _knowledge_counts(self) -> tuple:
        return (len(self.eg.facts(2000)), len(self.eg.findings()))

    def _intervention_hints(self) -> str:
        """汇总本任务已下发的「人工干预」指令，作为 Planner 的硬约束上下文。"""
        try:
            evs = self.ss.events(self.task_id, limit=300)
            msgs = [e.get("message", "") for e in evs if e.get("type") == "intervention"]
            return "\n".join(f"- {m}" for m in msgs if m) if msgs else ""
        except Exception:
            return ""

    # ---------- 主循环 ----------
    def run(self) -> Dict:
        self.ss.start_task(self.task_id)
        # 目标节点
        if not any(n["kind"] == "goal" for n in self.eg.graph()["nodes"]):
            self.eg.set_goal(f"对 {self.target} 进行渗透测试（{self.mode} 模式）",
                             {"target": self.target, "mode": self.mode})
        self._log("task", f"任务启动：target={self.target} mode={self.mode}", "system")
        self._load_chain_memory()

        for _ in range(self.max_rounds):
            if self.stopped:
                break
            self.round += 1
            pending = self.eg.pending_or_running()

            if not pending:
                # 上一轮审核建议 finish → 不再询问 Planner，直接收敛结束
                if self._last_audit and self._last_audit.get("verdict") == "finish":
                    self._log("task",
                              f"Auditor 判定收敛：{self._last_audit.get('reason','')}",
                              "auditor")
                    break
                hint = self._intervention_hints()
                # 首次规划时注入「历史攻击链记忆」：只注入一次，避免每轮烧 token
                if self._chain_memory and not self._chain_hint_used:
                    hint = (hint + "\n" + self._chain_memory).strip()
                    self._chain_hint_used = True
                if self._last_audit:
                    a = self._last_audit
                    hint += (f"\n- [Auditor 审核] 有效漏洞 {a.get('kept', 0)} 条"
                             f"（剔除重复 {len(a.get('duplicates', []))}、"
                             f"无证据 {len(a.get('fake', []))}）；"
                             f"资产覆盖率 {a.get('coverage', {}).get('coverage', 0):.0%}，"
                             f"未覆盖资产 {a.get('coverage', {}).get('uncovered', 0)} 个；"
                             f"结论：{a.get('reason', '')}。"
                             f"已测试过的 (tool,args) 组合不要重复下发，"
                             f"只在有**新攻击面或新验证思路**时才派新意图。")
                decision = self.planner.plan(
                    self.target, self.scope,
                    self.ag.digest(task_id=self.task_id), self.eg.digest_for_planner(),
                    self.round, extra_hint=hint)
                self._log("plan", decision.get("reasoning", ""), "planner",
                          {"intents": decision.get("intents", [])})
                if decision.get("finish"):
                    self._log("task", f"Planner 判定完成：{decision.get('summary','')}", "planner")
                    break

                # ---- 串行利用链：登记一次，之后跨唤醒由程序决定放行哪一步 ----
                fact_labels = [f["label"] for f in self.eg.facts(500)]
                added = self.todo.sync(decision.get("chain") or [])
                if added:
                    self._log("plan", f"登记串行利用链，新增 {added} 步", "planner")
                auto_done = self.todo.advance_by_facts(fact_labels)
                if auto_done:
                    self._log("plan", f"前置事实已满足，自动完成步骤: {', '.join(auto_done)}",
                              "planner")
                chain_ids = self._materialize_chain_steps(
                    self.todo.ready(fact_labels, limit=self.max_workers))

                intents = self._materialize_intents(decision.get("intents", []))
                if not chain_ids and not intents:
                    snap = self.todo.snapshot()
                    if snap["pending"]:
                        # 允许什么都不派：链路等待前置事实，且本轮无新攻击面 → 收敛退出
                        self._log("task",
                                  f"链路尚有 {snap['pending']} 步等待前置事实，"
                                  f"且无其它可执行攻击面，收敛结束", "planner")
                    else:
                        self._log("task", "无新攻击面，任务结束", "planner")
                    break
                continue

            # 派发 worker（并行）
            self._dispatch(pending[: self.max_workers])

            # ---- 审核：去重 / 去假 / 结束判断 ----
            self._audit_round()

            # ---- 收敛检测：本轮知识无增长则记停滞，连续 2 轮 → 主动结束 ----
            counts = self._knowledge_counts()
            if self._last_knowledge is not None and counts == self._last_knowledge:
                self._stale_rounds += 1
            else:
                self._stale_rounds = 0
            self._last_knowledge = counts
            # ---- 定期压缩上下文：把较早的事实折叠为摘要，抑制 token 膨胀 ----
            if self.context_compress and self.round % self.compress_every == 0:
                self._compress_context()
            if self._stale_rounds >= 2:
                self._log("task",
                          f"连续 {self._stale_rounds} 轮无新增事实/漏洞"
                          f"（facts={counts[0]}, findings={counts[1]}），攻击面已穷尽，"
                          f"主动收敛结束，不再重复测试", "auditor")
                break
        else:
            self._log("task", f"达到最大轮次 {self.max_rounds}，停止", "system")

        # ---- 业务逻辑专项：主流程信息搜集完成后介入，与主 agent 协同 ----
        self._logic_phase()

        # ---- 攻击链复盘员：复盘纵向攻击链并写入记忆文件（下次任务参考） ----
        self._chain_phase()

        summary = self.build_summary()
        self.ss.finish_task(self.task_id, "done" if not self.stopped else "stopped")
        self._log("task", "任务结束", "system")
        return summary

    def stop(self):
        self.stopped = True

    # ---------- 业务逻辑漏洞专项 agent ----------
    def _logic_phase(self):
        """在主 agent 完成资产测绘 / 指纹 / 接口发现之后，启动业务逻辑专项分析。"""
        if not self.logic_enabled or self.stopped:
            return
        try:
            from .logic_agent import LogicAgent
            la = LogicAgent(db=self.db, llm=self.llm, tools=self.tools,
                            mode=self.mode,
                            progress=lambda stage, msg: self._log(
                                "logic", msg, "logic_agent"))
            self._log("logic", "信息搜集完成，启动业务逻辑漏洞专项分析", "logic_agent")
            self.logic_summary = la.run(self.task_id, self.target, self.scope,
                                        allowed=self._allowed_hosts_full())
        except Exception as e:
            self._log("error", f"业务逻辑专项分析异常（跳过）: {e}", "logic_agent")

    # ---------- 攻击链复盘员（记忆沉淀） ----------
    def _load_chain_memory(self):
        """任务启动时载入历史攻击链记忆（同目标/同主域优先），供 Planner 参考。"""
        try:
            from .attack_chain import reference_for
            self._chain_memory = reference_for(self.target, self.scope) or ""
        except Exception as e:
            self._chain_memory = ""
            self._log("chain", f"历史攻击链记忆载入失败（忽略）：{e}", "chain_reviewer")
            return
        n = self._chain_memory.count("\n### ")
        if n:
            self._log("chain",
                      f"已载入 {n} 条历史攻击链记忆作为本次任务参考（仅参考，需重新取证）",
                      "chain_reviewer")

    def _chain_phase(self):
        """任务结束后自动复盘：提炼攻击链 → 写攻击链记录 + 记忆文件。"""
        if not self.chain_review_enabled:
            return
        try:
            from .chain_reviewer import ChainReviewer
            cr = ChainReviewer(db=self.db, llm=self.llm,
                               progress=lambda stage, msg: self._log(
                                   "chain", msg, "chain_reviewer"))
            self._log("chain", "任务收敛，启动攻击链复盘（自动记忆）", "chain_reviewer")
            out = cr.review(self.task_id, source="auto", persist=True)
            self.chain_summary = out or {}
            if out.get("ok"):
                ch = out.get("chain") or {}
                self._log("chain",
                          f"攻击链 {ch.get('id')} 已写入记忆文件"
                          f"（{ch.get('memory_file') or ''}）",
                          "chain_reviewer",
                          {"chain_id": ch.get("id"),
                           "model": out.get("model")})
            else:
                self._log("chain",
                          f"攻击链复盘跳过：{out.get('error') or '无数据'}",
                          "chain_reviewer")
        except Exception as e:
            self._log("error", f"攻击链复盘异常（跳过）: {e}", "chain_reviewer")

    # ---------- 上下文压缩 ----------
    def _compress_context(self, keep_recent: int = 15) -> int:
        """把较早的事实折叠成一条摘要事实；digest 只呈现摘要 + 最近事实。

        被压缩的事实仍保留在图中（计数不变），只是不再逐条塞进 Planner 的 prompt，
        从而显著降低每轮 prompt token。
        """
        try:
            rows = list(reversed(self.eg.facts(5000)))   # 时间升序
        except Exception:
            return 0
        pending = [f for f in rows if not (f.get("data") or {}).get("compressed")
                   and not (f.get("data") or {}).get("compressed_summary")]
        if len(pending) <= keep_recent + 10:
            return 0
        old = pending[:-keep_recent]
        lines = [f"- {str(f.get('label') or '')[:160]}" for f in old[:300]]
        digest = "\n".join(lines)[:6000]
        for f in old:
            d = dict(f.get("data") or {})
            d["compressed"] = True
            try:
                self.eg.update_node(f["id"], data=d)
            except Exception:
                pass
        try:
            self.eg.add_fact(f"历史事实摘要（已压缩 {len(old)} 条）",
                             {"compressed_summary": True, "count": len(old),
                              "digest": digest},
                             parent_id=self._goal_id())
        except Exception:
            pass
        self._log("compress",
                  f"上下文压缩：{len(old)} 条历史事实折叠为 1 条摘要（保留最近 {keep_recent} 条）",
                  "system")
        return len(old)

    # ---------- 审核（Auditor） ----------
    def _audit_round(self):
        """每轮派发后审核发现：去重/去假落库，结束判断存入 _last_audit。"""
        try:
            findings = self.eg.findings()
            cov = self.ag.coverage()
            tok = self.ss.task_token_total(self.task_id)
            rep = self.auditor.audit(findings, coverage=cov, tokens=tok,
                                     token_budget=self.token_budget,
                                     stale_rounds=self._stale_rounds)
            # 落库（可追溯，不删除）：合并 data 字段更新节点
            nodes = {f["id"]: f for f in findings}
            changed = 0
            for d in rep["duplicates"]:
                f = nodes.get(d["drop_id"])
                if not f or (f.get("data") or {}).get("audit_status"):
                    continue
                data = {**(f.get("data") or {}), "audit_status": "duplicate",
                        "merged_into": d["keep_id"], "audit_reason": d["reason"]}
                self.eg.update_node(f["id"], data=data)
                changed += 1
            for fk in rep["fake"]:
                f = nodes.get(fk["id"])
                if not f or (f.get("data") or {}).get("audit_status"):
                    continue
                data = {**(f.get("data") or {}), "audit_status": "fake",
                        "audit_reason": fk["reason"]}
                self.eg.update_node(f["id"], data=data)
                changed += 1
            if changed:
                self._log("audit",
                          f"剔除 {len(rep['duplicates'])} 条重复、"
                          f"{len(rep['fake'])} 条无证据发现（保留 {rep['kept']} 条）",
                          "auditor", {"duplicates": rep["duplicates"],
                                      "fake": rep["fake"]})
            if rep["verdict"] == "finish" or changed:
                self._log("audit",
                          f"审核结论：{rep['verdict']} —— {rep['reason']}",
                          "auditor")
            self._last_audit = rep
        except Exception as e:
            self._log("error", f"Auditor 执行异常（跳过本轮审核）: {e}", "auditor")

    # ---------- 意图物化 ----------
    def _materialize_intents(self, raw_intents: List[dict]) -> List[str]:
        existing = self._existing_labels()
        existing_sigs = self._existing_sigs()
        created = []
        for it in raw_intents:
            label = it.get("label")
            if not label or label in existing:
                continue
            # 签名去重：同 tool+args 的意图（哪怕换了个说法）不再重复下发，
            # 防止「反复测试相同端点直至人工干预」。
            sig = self._intent_sig(it.get("tool"), it.get("args"))
            if sig in existing_sigs:
                self._log("plan", f"跳过重复意图（同工具同参数已执行）: {label}", "planner")
                continue
            existing_sigs.add(sig)
            nid = self.eg.add_intent(
                label,
                {"tool": it.get("tool"), "args": it.get("args") or {},
                 "priority": it.get("priority", "medium"), "_sig": sig},
                parent_id=self._goal_id(),
            )
            existing.add(label)
            created.append(nid)
            self._log("plan", f"新增意图 {nid}: {label}", "planner",
                      {"tool": it.get("tool")})
        return created

    # ---------- 串行链步骤物化 ----------
    def _materialize_chain_steps(self, steps: List[dict]) -> List[str]:
        """把「可执行」的链步骤落成 intent 节点。

        步骤一旦落为 intent，其完成与否由 intent 执行结果决定（见 _run_one 回填），
        所以这里**不**提早标记完成——避免把「已派发」当成「已完成」。
        """
        created = []
        for s in steps:
            existing = self._existing_labels()
            if s["label"] in existing:
                continue
            nid = self.eg.add_intent(
                s["label"],
                {"tool": s.get("tool"), "args": s.get("args") or {},
                 "priority": "high", "chain_step_id": s["id"]},
                parent_id=self._goal_id(),
            )
            created.append(nid)
            self._log("plan", f"链路放行 {s['id']} → 意图 {nid}: {s['label']}", "planner",
                      {"chain_step": s["id"], "tool": s.get("tool")})
        return created

    def _goal_id(self):
        for n in self.eg.graph()["nodes"]:
            if n["kind"] == "goal":
                return n["id"]
        return None

    # ---------- 派发与执行 ----------
    def _dispatch(self, intents: List[dict]):
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futs = {ex.submit(self._run_one, it): it for it in intents}
            for fut in as_completed(futs):
                it = futs[fut]
                try:
                    fut.result()
                except Exception as e:
                    self._log("error", f"意图 {it['id']} 执行异常: {e}", "worker")
                    self.eg.update_node(it["id"], status="failed")

    def _run_one(self, intent: dict):
        iid = intent["id"]
        label = intent["label"]
        self.eg.update_node(iid, status="running")
        self._log("intent", f"开始执行：{label}", "worker", {"intent": iid})

        # 过程检索能力通过 context 注入（只读），职责边界不变：worker 仍只做自己这条意图。
        # allowed_hosts：工具层越界拦截（本任务只打自己的目标，禁止串扰其它任务资产）；
        # 并放行 scope 域名已解析出的 IP，避免「打自己目标 IP」被误拦。
        ctx = {"trace_store": self.traces, "intent_id": iid, "task_id": self.task_id,
               "allowed_hosts": self._allowed_hosts_full()}
        obs = self.worker.execute(intent, self.target,
                                  self.ag.digest(task_id=self.task_id), ctx)

        # 写回资产 + 建立探索锚点（该意图覆盖的资产 → covered）
        asset_keys = ingest_assets(obs.get("assets", []), self.ag, self.task_id)
        for k in asset_keys:
            self.ag.anchor_by_key(iid, k, self.task_id, "targets")
        # 工具调用 + 启发式抽取（从真实输出里补全资产）
        for tc in obs.get("tool_calls", []):
            args = tc.get("args") or {}
            result = tc.get("result") or {"status": tc.get("status"), "data": tc.get("summary")}
            self.ss.log_tool_call(self.task_id, iid, tc.get("tool", "?"), args,
                                  tc.get("status", "?"), tc.get("summary", ""),
                                  raw=tc.get("result"),
                                  request=tc.get("request"), response=tc.get("response"))
            try:
                for f in heuristic_extract(tc.get("tool", ""), args, result, self.ag, self.task_id):
                    obs.setdefault("facts", []).append(f)
            except Exception:
                pass
        # 事实
        for f in obs.get("facts", []):
            self.eg.add_fact(f, parent_id=iid)
        # 漏洞
        for fd in obs.get("findings", []):
            nid = self.eg.add_finding(
                fd.get("title", "未命名漏洞"),
                {"severity": fd.get("severity", "中"), "evidence": fd.get("evidence", "")},
                parent_id=iid, asset_ref=fd.get("asset"))
            # 锚定到资产：asset_ref（label/key）解析为 asset_id 写入锚点表，
            # 支撑「资产覆盖度」——被攻击过的资产记为 covered。
            ref = fd.get("asset")
            if ref:
                self.ag.anchor_by_key(nid, ref, self.task_id, "found_in")

        # ---- 过程落盘：让后面的 worker 能检索到未被总结成 fact 的中间观察 ----
        self._record_trace(iid, obs)

        # ---- 链步骤回填：对应步骤随 intent 成功而完成 ----
        csid = (intent.get("data") or {}).get("chain_step_id")
        if csid:
            self.todo.mark_done(csid, evidence=f"由意图 {iid} 完成", intent_ref=iid)

        status = "done" if obs.get("tool_calls") or obs.get("facts") or obs.get("findings") else "done"
        self.eg.update_node(iid, status=status,
                            data={**(intent.get("data") or {}), "_summary": obs.get("summary", "")})
        self._log("intent", f"完成：{label} → {obs.get('summary','')[:160]}", "worker",
                  {"intent": iid, "tool_calls": len(obs.get("tool_calls", [])),
                   "findings": len(obs.get("findings", []))})
        return obs

    # ---------- 过程记录 ----------
    def _record_trace(self, intent_id: str, obs: Dict):
        """把一次执行的每一步过程落盘（工具调用 / 事实 / 结论）。

        记录原始过程而非只记结论：很多有用观察（报错、响应片段、隐藏参数）
        不会沉淀成 fact，但它们对后续步骤很关键。
        """
        step = 0
        for tc in obs.get("tool_calls") or []:
            step += 1
            self.traces.record(intent_id, step, "tool", {
                "tool": tc.get("tool"), "args": tc.get("args"),
                "status": tc.get("status"), "summary": tc.get("summary"),
                "response": (tc.get("response") or "")[:3000],
            })
        for f in obs.get("facts") or []:
            step += 1
            self.traces.record(intent_id, step, "fact", str(f))
        if obs.get("summary"):
            step += 1
            self.traces.record(intent_id, step, "summary", str(obs["summary"]))

    # ---------- 报告 ----------
    def build_summary(self) -> Dict:
        all_findings = self.eg.findings()
        findings = Auditor.visible(all_findings)
        excluded = [f for f in all_findings if f not in findings]
        st = self.ag.stats(task_id=self.task_id)
        tok = self.ss.task_token_total(self.task_id)
        try:
            from .context import cache_stats
            cache = cache_stats()
        except Exception:
            cache = {}
        sev_rank = {"危急": 0, "高": 1, "中": 2, "低": 3, "信息": 4}
        findings_sorted = sorted(findings, key=lambda f: sev_rank.get(
            (f.get("data") or {}).get("severity", "中"), 9))
        logic_findings = [f for f in findings_sorted
                          if (f.get("data") or {}).get("logic")]
        lines = [f"# 渗透测试报告 - {self.target}",
                 f"模式：{self.mode}｜轮次：{self.round}",
                 "",
                 "## 资产统计（本任务范围）",
                 json.dumps(st, ensure_ascii=False),
                 "",
                 f"## 漏洞发现（{len(findings)}）"]
        for f in findings_sorted:
            d = f.get("data") or {}
            tag = "［业务逻辑］" if d.get("logic") else ""
            lines.append(f"- [{d.get('severity','?')}] {tag}{f['label']}"
                         + (f"  证据: {d.get('evidence','')}" if d.get("evidence") else ""))
        if not findings:
            lines.append("- （未发现明确漏洞）")
        if logic_findings:
            lines.append("")
            lines.append(f"## 业务逻辑专项（{len(logic_findings)} 条假设，需人工/动态验证）")
            for f in logic_findings:
                d = f.get("data") or {}
                lines.append(f"- [{d.get('severity','?')}] {f['label']}"
                             + (f"｜验证思路: {d.get('test_plan','')}" if d.get("test_plan") else ""))
        if excluded:
            # 阴性/剔除结论单列，不计入漏洞数（项目约定）
            lines.append("")
            lines.append(f"## 已排除的发现（Auditor 剔除 {len(excluded)} 条，不计入漏洞数）")
            for f in excluded:
                d = f.get("data") or {}
                lines.append(f"- {f['label']}（{(d.get('audit_reason') or '重复')}）")
        chain = (self.chain_summary or {}).get("chain") or {}
        if chain:
            lines.append("")
            lines.append(f"## 攻击链记忆（{chain.get('id')}）")
            if chain.get("summary"):
                lines.append(f"- 概述：{chain['summary']}")
            if chain.get("stages"):
                lines.append("- 阶段链：" + " → ".join(
                    str(s.get("stage")) for s in chain["stages"]))
            if chain.get("memory_file"):
                lines.append(f"- 记忆文件：{chain['memory_file']}")
        lines.append("")
        lines.append(f"## Token 消耗：{tok['total']} (prompt={tok['prompt']}, completion={tok['completion']})"
                     + (f"｜响应缓存命中 {cache.get('hits',0)} 次，节省约 "
                        f"{cache.get('saved_tokens',0)} token" if cache else ""))
        report_md = "\n".join(lines)
        return {"task_id": self.task_id, "target": self.target,
                "assets": st, "findings": findings_sorted,
                "logic_findings": logic_findings,
                "logic_summary": self.logic_summary,
                "chain_summary": self.chain_summary,
                "excluded_findings": excluded, "tokens": tok,
                "cache": cache,
                "rounds": self.round, "report_md": report_md}
