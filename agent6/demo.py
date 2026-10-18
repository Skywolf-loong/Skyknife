"""
离线演示数据：用 DryRunLLM 跑一个多阶段仿真任务，往双图里灌入真实结构的数据，
便于在没有 API Key / 网络时预览 WebUI 仪表盘。
"""
import json
from typing import Dict, List

from .llm import DryRunLLM
from .orchestrator import Orchestrator
from .store import SessionStore
from .store.db import get_db
from .tools import ToolRegistry

# 一个 4 阶段的仿真剧本：资产测绘 -> 端口 -> 指纹 -> 漏洞
_SCRIPT: List[Dict] = [
    {  # 阶段1：资产测绘
        "reasoning": "起始阶段：先做子域名枚举与 DNS 解析，构建资产底图",
        "intents": [
            {"label": "子域名枚举 example.com", "tool": "command",
             "args": {"command": "echo www.example.com; echo api.example.com; echo mail.example.com"},
             "priority": "high"},
            {"label": "DNS 解析 example.com", "tool": "command",
             "args": {"command": "echo 93.184.216.34"}, "priority": "high"},
        ],
    },
    {  # 阶段2：端口与服务
        "reasoning": "已获得存活 IP，进入端口扫描与服务识别阶段",
        "intents": [
            {"label": "对 93.184.216.34 做端口扫描", "tool": "command",
             "args": {"command": "echo 80/tcp open; echo 443/tcp open; echo 22/tcp open"},
             "priority": "high"},
            {"label": "识别 443 服务指纹", "tool": "command",
             "args": {"command": "echo nginx/1.24.0; echo X-Powered-By: PHP/7.4.3"},
             "priority": "medium"},
        ],
    },
    {  # 阶段3：漏洞探测
        "reasoning": "已识别 nginx + PHP 7.4 技术栈，针对 Web 服务做漏洞验证",
        "intents": [
            {"label": "对 https://example.com 做敏感信息泄露检测", "tool": "command",
             "args": {"command": "echo /.env -> 200; echo /.git/config -> 200"},
             "priority": "high"},
            {"label": "对 /search?q= 做 SQL 注入验证", "tool": "command",
             "args": {"command": "echo time-based delay 5.1s => possible SQLi"},
             "priority": "high"},
            {"label": "对 /login 做弱口令与默认凭据检测", "tool": "command",
             "args": {"command": "echo admin/admin -> 302 logged in"}, "priority": "medium"},
        ],
    },
    {  # 收尾
        "reasoning": "攻击面已覆盖，无新增可测目标，收敛",
        "intents": [],
        "finish": True,
        "summary": "完成对 example.com 的自动化渗透：发现 3 个漏洞，资产 12 项。",
    },
]

# 每个 intent 完成时回报的事实/漏洞/资产
_WORKER_OUT = {
    "子域名枚举 example.com": {
        "facts": ["发现子域 www.example.com", "发现子域 api.example.com", "发现子域 mail.example.com"],
        "assets": [
            {"kind": "subdomain", "name": "www.example.com", "parent": "example.com"},
            {"kind": "subdomain", "name": "api.example.com", "parent": "example.com"},
            {"kind": "subdomain", "name": "mail.example.com", "parent": "example.com"},
        ],
    },
    "DNS 解析 example.com": {
        "facts": ["example.com -> 93.184.216.34"],
        "assets": [{"kind": "ip", "ip": "93.184.216.34", "domain": "example.com"}],
    },
    "对 93.184.216.34 做端口扫描": {
        "facts": ["80/tcp open (http)", "443/tcp open (https)", "22/tcp open (ssh)"],
        "assets": [
            {"kind": "port", "ip": "93.184.216.34", "port": 80, "service": "http"},
            {"kind": "port", "ip": "93.184.216.34", "port": 443, "service": "https"},
            {"kind": "port", "ip": "93.184.216.34", "port": 22, "service": "ssh"},
        ],
    },
    "识别 443 服务指纹": {
        "facts": ["nginx/1.24.0", "PHP/7.4.3（已停止维护）"],
        "assets": [
            {"kind": "service", "ip": "93.184.216.34", "port": 443, "name": "nginx", "version": "1.24.0"},
            {"kind": "webapp", "url": "https://www.example.com/"},
            {"kind": "endpoint", "url": "https://www.example.com/search?q=", "method": "GET",
             "webapp": "https://www.example.com/"},
            {"kind": "endpoint", "url": "https://www.example.com/login", "method": "POST",
             "webapp": "https://www.example.com/"},
        ],
    },
    "对 https://example.com 做敏感信息泄露检测": {
        "facts": [".env 可访问（200）", ".git/config 可访问（200）"],
        "findings": [
            {"title": "敏感配置文件泄露（.env / .git）", "severity": "危急",
             "evidence": "GET /.env 返回 200，含 DB_PASSWORD 等字段（已脱敏）",
             "asset": "web:https://www.example.com/"},
        ],
    },
    "对 /search?q= 做 SQL 注入验证": {
        "facts": ["参数 q 触发时间盲注，延迟 5.1s"],
        "findings": [
            {"title": "SQL 注入（时间盲注）@ /search", "severity": "高",
             "evidence": "payload: q=1' AND SLEEP(5)-- , 响应延迟 5.1s",
             "asset": "ep:GET:https://www.example.com/search?q="},
        ],
    },
    "对 /login 做弱口令与默认凭据检测": {
        "facts": ["admin/admin 登录成功（默认凭据）"],
        "findings": [
            {"title": "默认弱口令 admin/admin @ /login", "severity": "高",
             "evidence": "POST /login 使用 admin/admin 返回 302 并设置会话 Cookie",
             "asset": "ep:POST:https://www.example.com/login"},
        ],
    },
}


class _DemoLLM(DryRunLLM):
    def __init__(self, session_store=None, task_id=None):
        super().__init__(session_store=session_store, task_id=task_id)
        self.plan_idx = 0
        self.worker_seen = {}

    def chat(self, messages, agent="planner", **kw):
        # 记录 token 用量（DryRun 模拟）
        if self.session_store and self.task_id:
            self.session_store.log_usage(self.task_id, agent, "demo", 180, 90)
        if agent == "worker":
            # 从 user 消息里解析当前意图 label（形如「意图：xxx」）
            label = ""
            for m in messages:
                if m.get("role") == "user" and "意图：" in (m.get("content") or ""):
                    for line in m["content"].splitlines():
                        if line.strip().startswith("意图："):
                            label = line.strip()[len("意图："):].strip()
                            break
                    if label:
                        break
            out = _WORKER_OUT.get(label, {})
            return json.dumps({
                "thought": f"执行：{label}",
                "tool": "command",
                "args": {"command": f"echo [demo] {label}"},
                "facts": out.get("facts", [f"[demo] 完成 {label}"]),
                "findings": out.get("findings", []),
                "assets": out.get("assets", []),
                "done": True,
                "summary": f"完成：{label}",
            })
        # planner
        if self.plan_idx < len(_SCRIPT):
            s = _SCRIPT[self.plan_idx]
            self.plan_idx += 1
            return json.dumps(s)
        return json.dumps({"reasoning": "收敛", "intents": [], "finish": True,
                           "summary": "演示任务完成"})


def seed_demo(target: str = "example.com", mode: str = "SRC", task_id: str = None,
              db=None) -> Dict:
    db = db or get_db()
    ss = SessionStore(db)
    tools = ToolRegistry("skills")
    from .scheduler import next_task_id
    task_id = task_id or next_task_id(db)
    if not ss.get_task(task_id):
        ss.create_task(task_id, "演示任务", target, target, mode)
    llm = _DemoLLM(session_store=ss, task_id=task_id)
    orch = Orchestrator(llm, tools, task_id, target, scope=target, mode=mode,
                        max_rounds=10, max_workers=2, db=db)
    return orch.run()
