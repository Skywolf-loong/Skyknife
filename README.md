# Skyknife自主渗透测试工作台（整合版）


---

## 一、快速开始

```bash
python main.py                 # 打开 Web 工作台（默认 http://127.0.0.1:8787，自动开浏览器）
```

Windows 下也可双击 **`启动工作台.bat`**。

其他用法：

| 命令 | 说明 |
|---|---|
| `python main.py` | 打开图形化工作台（默认行为） |
| `python main.py --port 9000` | 指定端口（端口被占用时自动顺延） |
| `python main.py --no-browser` | 只起服务，不自动开浏览器 |
| `python main.py --demo` | 先灌入离线演示数据再打开界面 |
| `python main.py scan example.com` | 命令行自主渗透 |
| `python main.py scan a.com b.com --mode HVV` | 多目标批量 |
| `python main.py resume T1` | 断点续跑指定任务 |
| `python main.py report T1` | 生成 Markdown 渗透报告（默认 `agent6_data/output/reports/report-T1.md`） |
| `python main.py report T1 --format html` | HTML 报告，自动打开浏览器，可打印为 PDF |
| `python main.py demo --no-web` | 只灌演示数据 |

---

## 二、界面功能

顶部控制台：输入目标 → 选模式（SRC / HVV / 测绘）→「开始扫描」，任务在后台线程执行，界面实时刷新。

- **运行条**：显示正在执行的任务，可一键「停止」
- **KPI 看板**：资产总数、漏洞发现、攻击意图、事实、工具调用、Token 消耗
- **资产图谱**：全局共享资产图（root_domain / subdomain / ip / port / service / webapp / endpoint），力导向渲染
- **攻击链路**：单任务探索图血缘（goal → intent → fact / finding）
- **任务队列**：多任务列表，点击切换查看，含状态（排队/运行/完成/失败）
- **漏洞发现**：按危急 > 高 > 中 > 低 排序，含 Evidence
- **活动流 / 工具调用**：Planner 决策、Worker 执行、每次工具调用的结果摘要
- **报告导出**：任务行「报告」或顶部「导出报告」→ 一键生成渗透测试报告（HTML 可打印为 PDF / Markdown 可下载）
  含漏洞清单与修复建议、资产清单、攻击链路、执行统计、活动时间线；
  Agent「测试过但确认没问题」的阴性结论会单列为「已排除的攻击面」，不计入漏洞数
- **人在环路（安全审批 + 干预）**：「安全审批」开关默认开启，Worker 执行高危操作（命令执行、利用类技能、HTTP 写操作）前会
  **阻塞并弹出审批卡片**，你在界面点「批准执行 / 拒绝」后才继续（超时默认自动放行，保证无人值守不卡死）；
  也可随时「干预」下发指令——追加为新攻击意图（立即进入待执行队列）或作为硬约束注入下一轮 Planner 规划
- **流量录制与重放**：每次 http/command 工具调用的**请求原文与响应原文**自动留存，工具调用列表点「流量」查看 / 复制，
  并支持一键「重放」（原样再发起一次调用，便于对比验证）

无 API Key 时点「演示数据」即可离线预览完整效果。

---

## 三、整合后的目录结构

```
src/
├── main.py              ★ 统一入口（运行即开图形界面，同时保留 CLI 子命令）
├── 启动工作台.bat        ★ 双击启动
├── config.yaml          LLM / Shodan / 资源限制配置
├── core/                
│   ├── skill_manager.py 技能装载与执行
│   ├── executor.py      命令执行
│   ├── llm_broker.py    LLM 调用与用量统计
│   └── context.py / security.py / utils.py
├── skills/              36 个渗透技能（当前环境装载 21 个，其余因缺可选依赖跳过）
│   ├── info_gathering/  端口扫描 / DNS / 子域爆破 / 指纹 / 爬虫 / Shodan ...
│   ├── vulnerability_analysis/  SQLi / XSS / LFI / 命令注入 / 越权 / 上传 ...
│   ├── privesc/         linpeas / winpeas / sudo / cron / suid
│   └── custom/          手动登录会话
├── tools/               随项目携带的外部二进制工具（见「七、外部工具」）
│   └── p1finger/        资产指纹识别 P1finger
├── agent6/              引擎（对标 ARTEX 的核心）
│   ├── store/           双图持久化：AssetGraph(资产图) + ExplorationGraph(探索图)
│   ├── agents/          Planner（规划者）+ Worker（执行者，ReAct）
│   ├── orchestrator.py  规划→派单→执行→写回→再规划 的闭环
│   ├── scheduler.py     多任务调度 / 断点续跑 / 批量
│   ├── report.py        渗透测试报告生成（Markdown / HTML，零依赖）
│   ├── tools.py         ToolRegistry：复用 skills/ + command + http（含流量原文录制）
│   ├── human_gate.py    人在环路审批门禁（阻塞式队列，超时默认放行）
│   ├── llm.py           真实 LLM 客户端 + DryRunLLM（离线）
│   ├── demo.py          离线演示剧本（无需 Key）
│   └── webui/           标准库 http.server + 原生 JS/Canvas 仪表盘
│       ├── server.py    REST API（含 POST 发起任务 / 停止 / 演示数据）
│       ├── runner.py    后台任务运行器（线程隔离，不阻塞界面）
│       └── static/index.html
├── agent6_data/         SQLite（WAL）：assets/asset_edges/nodes/edges/tasks/events/tool_calls(含 traffic 流量原文)/llm_usage
└──
```

---

## 四、版本整合对照

| 能力 | v5.1 (less_token) | v5.2 (plan) | v6 (agent6) | 整合后 |
|---|---|---|---|---|
| 记忆方式 | 对话上下文 | 对话上下文 + 计划文件 | **双图持久化（SQLite）** | ✅ 双图 |
| 架构 | 单智能体 ReAct | 单智能体 + 计划 | **Planner + N×Worker** | ✅ 多智能体 |
| 可视化 | 命令行 | 命令行 | **Web 仪表盘** | ✅ `main.py` 自动打开 |
| 运行方式 | 单目标 | 单目标 | 多任务 + 断点续跑 | ✅ 均可 |
| 入口 | `main.py`(1946行) | `main.py`(3165行) | `python -m agent6.main` | ✅ 统一 `main.py` |



---

## 五、依赖

核心链路**零第三方依赖**（标准库 http.server + sqlite3 即可运行界面）。可选依赖缺失时相关技能自动跳过：

```bash
pip install pyyaml requests beautifulsoup4 aiohttp dnspython python-whois colorama
```

---

## 六、数据

- 数据库：`agent6_data/agent6.db`（WAL 模式，界面可并发读）
- 资产图全局共享、跨任务复用；探索图按任务隔离，记录攻击链路血缘
- 关闭界面后再次运行 `python main.py`，历史任务与图谱仍在

---
