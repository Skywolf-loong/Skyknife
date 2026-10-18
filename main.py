#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
==============================================================================
 自主渗透测试工作台  ·  统一入口
==============================================================================

直接运行即可打开图形化界面：

    python main.py

常用方式：

    python main.py                      # 打开 Web 工作台（默认 8787，自动开浏览器）
    python main.py --port 9000          # 指定端口
    python main.py --no-browser         # 只起服务，不自动打开浏览器
    python main.py --demo               # 无数据时先灌入离线演示数据再打开界面

    python main.py scan example.com     # 命令行自主渗透（--web 同时开界面）
    python main.py scan a.com b.com     # 多目标批量
    python main.py resume T1            # 断点续跑
    python main.py demo                 # 灌入离线演示数据（无需 API Key）
    python main.py report T1            # 生成渗透测试报告（reports/report-T1.md）
    python main.py report T1 --format html  # HTML 报告，自动打开可打印为 PDF
    python main.py legacy --ver 5.2     # 调用整合前的旧版单智能体 CLI

架构：
    双图持久化记忆   AssetGraph(全局资产图) + ExplorationGraph(单任务血缘图)
    Planner + Worker 多智能体并行编排闭环
    Web 可视化工作台  看板 / 资产图谱 / 攻击链路 / 漏洞 / 活动流 / 工具调用
    会话持久化        多任务、断点续跑、Token 统计
"""
import argparse
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Windows 控制台/重定向编码兜底，避免中文提示乱码
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DEFAULT_PORT = 8787
DEFAULT_HOST = "127.0.0.1"

BANNER = r"""
    ___    _      _   _  _      _ __    _       __    ___   
   / __|  | | __ | | | | | | __ | '_ \  (_)   / _|  / _ \  
  \__ \   | |/ / | |_| | | |/ / | | | | | |  |  _| |  __/ 
  |___/   |_|\_\  \__, | |_|\_\ |_| |_| |_|  |_|    \___|
                   __| |  
         Skyknife Autonomous Red-Team Workbench  ·  v6
"""


# ----------------------------------------------------------------------------
# 工具函数
# ----------------------------------------------------------------------------
def c(text: str, color: str = "") -> str:
    """彩色输出；Windows 无 colorama 时自动降级为纯文本。"""
    if not color:
        return text
    try:
        import colorama
        colorama.init(autoreset=False)
        return getattr(colorama.Fore, color.upper(), "") + text + colorama.Style.RESET_ALL
    except Exception:
        return text


def pick_port(host: str, start: int, tries: int = 30) -> int:
    """从 start 开始找第一个可用端口，避免端口占用导致启动失败。"""
    for p in range(start, start + tries):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, p))
            return p
        except OSError:
            continue
        finally:
            s.close()
    return start


OPTIONAL_DEPS = {
    "yaml": "配置文件解析（缺失时自动降级为内置极简解析）",
    "requests": "HTTP 探测工具 / LLM 调用",
    "bs4": "网页解析类技能（crawler 等）",
    "aiohttp": "高并发扫描类技能",
    "dns": "DNS 枚举类技能（dnspython）",
    "whois": "WHOIS 查询技能",
}


def env_check() -> dict:
    """启动前自检：skills 数量、LLM 配置、可选依赖。"""
    import importlib.util
    import os

    info = {"skills": 0, "api_key": False, "missing": []}
    try:
        from core.skill_manager import SkillManager  # type: ignore
        mgr = SkillManager("skills", recursive=True)
        info["skills"] = len(mgr.list_skills())
    except Exception as e:
        info["missing"].append(f"skills: {e}")
    try:
        from agent6.paths import load_config
        cfg = load_config()
        info["api_key"] = bool(cfg.get("api_key") or os.environ.get("DEEPSEEK_API_KEY"))
    except Exception:
        pass
    miss = [k for k in OPTIONAL_DEPS if importlib.util.find_spec(k) is None]
    info["deps_missing"] = miss
    return info


def print_startup(url: str, info: dict, port: int):
    print(BANNER)
    print(c("  ▶ 工作台已启动", "green") + f"   {c(url, 'cyan')}")
    print(f"  ├─ 数据目录  : {ROOT / 'agent6_data'}")
    print(f"  ├─ 已装载技能: {info['skills']} 个")
    print(f"  ├─ LLM 配置  : {'已检测到 API Key' if info['api_key'] else '未配置（可用「演示数据」离线预览）'}")
    print(f"  └─ 退出      : 在本窗口按 {c('Ctrl+C', 'yellow')}")
    miss = info.get("deps_missing") or []
    if miss:
        print()
        print(c("  ⚠ 缺少可选依赖（不影响界面，相关技能会被跳过）：", "yellow"))
        for k in miss:
            print(f"      - {k:<10s} {OPTIONAL_DEPS[k]}")
        print("      安装：pip install " + " ".join(
            {"dns": "dnspython", "bs4": "beautifulsoup4"}.get(k, k) for k in miss))
    print()
    print("  提示：在界面顶部输入目标后点「开始扫描」即可自主渗透；")
    print("        无 API Key 时请先点「演示数据」离线预览。")
    print()


# ----------------------------------------------------------------------------
# Web 工作台
# ----------------------------------------------------------------------------
def launch_web(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
               open_browser: bool = True, seed_demo: bool = False,
               auto_port: bool = True):
    """启动 Web 工作台并（可选）自动打开浏览器，阻塞直到 Ctrl+C。"""
    from agent6.webui.server import create_server

    port = pick_port(host, port) if auto_port else port
    httpd = create_server(host, port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    if seed_demo:
        try:
            from agent6.demo import seed_demo
            r = seed_demo()
            print(c(f"  [demo] 已灌入演示数据：{r.get('task_id')}", "green"))
        except Exception as e:
            print(c(f"  [demo] 失败：{e}", "red"))

    url = f"http://{host}:{port}"
    info = env_check()
    print_startup(url, info, port)

    if open_browser:
        # 延迟一点，确保端口已真正 listen
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n" + c("  正在关闭工作台…", "yellow"))
        httpd.shutdown()
        httpd.server_close()
        print(c("  已退出。", "green"))
    return 0


# ----------------------------------------------------------------------------
# CLI 子命令
# ----------------------------------------------------------------------------
def cmd_gui(args):
    return launch_web(host=args.host, port=args.port,
                      open_browser=not args.no_browser, seed_demo=args.demo)


def _run_cli_task(args, targets):
    from agent6.scheduler import run_batch, run_task
    from agent6.tools import ToolRegistry

    tools = ToolRegistry("skills")
    if len(targets) == 1:
        r = run_task(targets[0], mode=args.mode, scope=args.scope,
                     max_rounds=args.rounds, max_workers=args.workers,
                     planner_max_intents=args.intents, tools=tools,
                     dry_run=args.dry_run)
        _print_report(r)
    else:
        for r in run_batch([{"target": t, "mode": args.mode} for t in targets],
                           tools=tools, max_rounds=args.rounds,
                           max_workers=args.workers, dry_run=args.dry_run):
            _print_report(r)
    return 0


def cmd_scan(args):
    _run_cli_task(args, args.targets)
    if args.web:
        return launch_web(host=args.host, port=args.port,
                          open_browser=not args.no_browser)
    return 0


def cmd_resume(args):
    from agent6.scheduler import resume_task
    r = resume_task(args.task_id, max_rounds=args.rounds, max_workers=args.workers)
    _print_report(r)
    if args.web:
        return launch_web(host=args.host, port=args.port,
                          open_browser=not args.no_browser)
    return 0


def cmd_demo(args):
    from agent6.demo import seed_demo
    r = seed_demo(target=args.target, mode=args.mode)
    _print_report(r)
    if getattr(args, "no_web", False):
        return 0
    return launch_web(host=args.host, port=args.port,
                      open_browser=not args.no_browser)


def cmd_report(args):
    """按任务 ID 生成渗透测试报告（md / html / json）。"""
    from agent6.report import task_report
    fmt = args.format
    if fmt == "markdown":
        fmt = "md"
    r = task_report(args.task_id, fmt)
    if not r.get("ok"):
        print(c(f"  报告生成失败：{r.get('error')}", "red"))
        return 1
    text = r["content"]
    out = args.out
    if not out:
        suffix = {"md": ".md", "html": ".html", "json": ".json"}[fmt]
        # 默认落盘到统一输出目录的 reports 子目录（agent6_data/output/reports）
        from agent6.paths import REPORTS_DIR
        out = str(REPORTS_DIR / f"report-{args.task_id}{suffix}")
    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        import json
        p.write_text(json.dumps(text, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        p.write_text(text, encoding="utf-8")
    s = r["data"]["summary"]
    print(c("  ▶ 报告已生成", "green"))
    print(f"  ├─ 文件    : {p}（{p.stat().st_size} 字节）")
    print(f"  ├─ 任务    : {args.task_id} · {r['data']['task'].get('target','')}")
    print(f"  ├─ 漏洞    : {s['findings']} 个"
          + "（" + "、".join(f"{k} {v}" for k, v in s["sev_count"].items() if v) + "）")
    print(f"  └─ 资产    : {s['assets']} 个 / 工具调用 {s['tool_calls']} 次"
          f" / Token {s['tokens']}")
    if fmt == "html" and not args.no_open:
        webbrowser.open(p.as_uri())
    return 0


def cmd_legacy(args):
    """调用整合前的旧版单智能体 CLI（v5.1 less_token / v5.2 plan）。"""
    import subprocess
    cand = {
        "5.1": ROOT / "agent5.1(less_token)" / "main.py",
        "5.2": ROOT / "agent5.2(plan)" / "main.py",
    }
    target = cand.get(args.ver)
    if not target or not target.exists():
        print(c(f"  未找到旧版入口：{target}", "red"))
        return 1
    print(c(f"  调用旧版 v{args.ver}：{target}", "yellow"))
    return subprocess.call([sys.executable, str(target)] + list(args.rest))


def _print_report(summary: dict):
    print("\n" + "=" * 72)
    print(summary.get("report_md", "(无报告)"))
    print("=" * 72 + "\n")


# ----------------------------------------------------------------------------
# 参数解析
# ----------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="自主渗透测试工作台（整合 v5.1/v5.2/v6，对标 ARTEX）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="直接运行 `python main.py` 即打开图形化工作台。",
    )
    p.add_argument("--host", default=DEFAULT_HOST, help="监听地址（默认 127.0.0.1）")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"端口（默认 {DEFAULT_PORT}）")
    p.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    p.add_argument("--demo", action="store_true", help="启动时先灌入离线演示数据")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("scan", help="对目标执行自主渗透")
    sp.add_argument("targets", nargs="+")
    sp.add_argument("--mode", default="SRC", choices=["SRC", "HVV", "测绘"])
    sp.add_argument("--scope", default="")
    sp.add_argument("--rounds", type=int, default=20)
    sp.add_argument("--workers", type=int, default=3)
    sp.add_argument("--intents", type=int, default=5)
    sp.add_argument("--dry-run", action="store_true", help="离线假 LLM，不消耗 Token")
    sp.add_argument("--web", action="store_true", help="结束后打开工作台")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("resume", help="断点续跑指定任务")
    sp.add_argument("task_id")
    sp.add_argument("--rounds", type=int, default=20)
    sp.add_argument("--workers", type=int, default=3)
    sp.add_argument("--web", action="store_true")
    sp.set_defaults(func=cmd_resume)

    sp = sub.add_parser("demo", help="灌入离线演示数据")
    sp.add_argument("--target", default="example.com")
    sp.add_argument("--mode", default="SRC")
    sp.add_argument("--no-web", action="store_true", help="只灌数据不开界面")
    sp.set_defaults(func=cmd_demo)

    sp = sub.add_parser("report", help="生成渗透测试报告")
    sp.add_argument("task_id")
    sp.add_argument("--format", default="md", choices=["md", "markdown", "html", "json"])
    sp.add_argument("-o", "--out", default="", help="输出文件（默认 agent6_data/output/reports/report-<id>.<ext>）")
    sp.add_argument("--no-open", action="store_true", help="html 报告不自动用浏览器打开")
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("legacy", help="调用整合前的旧版 CLI（v5.1 / v5.2）")
    sp.add_argument("--ver", default="5.2", choices=["5.1", "5.2"])
    sp.add_argument("rest", nargs=argparse.REMAINDER)
    sp.set_defaults(func=cmd_legacy)

    p.set_defaults(func=cmd_gui)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
