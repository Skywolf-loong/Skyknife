"""
agent6 CLI 入口（与旧版 main.py 并存，互不影响）。

用法：
  # 自主扫描（默认会同时打印仪表盘地址，--web 启动 WebUI）
  python -m agent6.main scan example.com --mode SRC --workers 3 --web

  # 多目标批量
  python -m agent6.main scan a.com b.com --mode 测绘

  # 断点续跑
  python -m agent6.main resume T1 --web

  # 只启动仪表盘
  python -m agent6.main web --port 8787

  # 离线演示（灌入仿真数据，无需 API Key）
  python -m agent6.main demo --web
"""
import argparse
import sys
from pathlib import Path

# 允许 `python agent6/main.py` 直接运行
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _print_report(summary: dict):
    print("\n" + "=" * 72)
    print(summary.get("report_md", "(无报告)"))
    print("=" * 72 + "\n")


def cmd_scan(args):
    from .scheduler import run_batch, run_task
    from .tools import ToolRegistry

    tools = ToolRegistry("skills")
    if len(args.targets) == 1:
        r = run_task(args.targets[0], mode=args.mode, scope=args.scope,
                     max_rounds=args.rounds, max_workers=args.workers,
                     planner_max_intents=args.intents, tools=tools, dry_run=False
                     if not args.dry_run else True)
        _print_report(r)
        results = [r]
    else:
        results = run_batch([{"target": t, "mode": args.mode} for t in args.targets],
                            tools=tools, max_rounds=args.rounds, max_workers=args.workers)
        for r in results:
            _print_report(r)
    if args.web:
        from .webui import serve
        serve(port=args.port)
    return results


def cmd_resume(args):
    from .scheduler import resume_task
    r = resume_task(args.task_id, max_rounds=args.rounds, max_workers=args.workers)
    _print_report(r)
    if args.web:
        from .webui import serve
        serve(port=args.port)
    return r


def cmd_web(args):
    from .webui import serve
    serve(host=args.host, port=args.port)


def cmd_demo(args):
    from .demo import seed_demo
    r = seed_demo(target=args.target, mode=args.mode)
    _print_report(r)
    from .webui import serve
    serve(port=args.port)


def build_parser():
    p = argparse.ArgumentParser(prog="agent6", description="agent6 自主渗透测试智能体（对标 ARTEX）")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--mode", default="SRC", choices=["SRC", "HVV", "测绘"])
        sp.add_argument("--rounds", type=int, default=20, help="最大迭代轮次")
        sp.add_argument("--workers", type=int, default=3, help="并行 Worker 数")
        sp.add_argument("--port", type=int, default=8787)
        sp.add_argument("--web", action="store_true", help="任务结束后启动 WebUI")

    sp = sub.add_parser("scan", help="对目标执行自主渗透")
    sp.add_argument("targets", nargs="+")
    sp.add_argument("--scope", default="")
    sp.add_argument("--intents", type=int, default=5, help="Planner 每轮意图数")
    sp.add_argument("--dry-run", action="store_true", help="离线假 LLM（不调 API）")
    add_common(sp)
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("resume", help="断点续跑指定任务")
    sp.add_argument("task_id")
    add_common(sp)
    sp.set_defaults(func=cmd_resume)

    sp = sub.add_parser("web", help="仅启动 Web 仪表盘")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8787)
    sp.set_defaults(func=cmd_web)

    sp = sub.add_parser("demo", help="灌入离线演示数据并打开仪表盘")
    sp.add_argument("--target", default="example.com")
    sp.add_argument("--mode", default="SRC")
    sp.add_argument("--port", type=int, default=8787)
    sp.set_defaults(func=cmd_demo)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    main()
