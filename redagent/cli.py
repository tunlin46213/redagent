"""redagent CLI entry point.

  redagent task "<task>"              single autonomous operator
  redagent team "<task>"             recon/web/reporter team (writes report.md)
  redagent hunt "<target-url>"       worklist-driven chained scan (writes report.md)
  redagent chat                      interactive session (plain REPL)
  redagent tui                       interactive session (Textual full-screen UI)
  redagent scope                     print the current engagement scope

All target-touching tools enforce the scope in config.yaml (RoE allowlist).
"""

import sys
import asyncio
import argparse

from .config import Config
from . import modes


def main() -> None:
    ap = argparse.ArgumentParser(prog="redagent", description="Local pentest agent (scope-enforced).")
    ap.add_argument("-c", "--config", help="path to config.yaml")
    sub = ap.add_subparsers(dest="mode", required=True)
    for m in ("task", "team"):
        s = sub.add_parser(m)
        s.add_argument("prompt", nargs="+", help="the task description")
    h = sub.add_parser("hunt")
    h.add_argument("prompt", nargs="+", help="the target URL (e.g. http://localhost:3001)")
    sub.add_parser("chat")
    sub.add_parser("tui")
    sub.add_parser("scope")
    args = ap.parse_args()

    cfg = Config(args.config)

    if args.mode == "scope":
        print(f"config: {cfg.path}")
        print(f"model : {cfg.model} @ {cfg.base_url}")
        print("allowed_targets:")
        for h in sorted(cfg.scope.hosts):
            print(f"  - {h}")
        for n in cfg.scope.nets:
            print(f"  - {n}")
        if cfg.scope.authorized_until:
            print(f"authorized_until: {cfg.scope.authorized_until}")
        return

    if args.mode == "chat":
        asyncio.run(modes.run_chat(cfg))
        return

    if args.mode == "tui":
        from .tui import run_tui
        run_tui(cfg)
        return

    if args.mode == "hunt":
        from . import hunt
        hunt.run_hunt(" ".join(args.prompt), cfg)
        return

    task = " ".join(args.prompt)
    runner = modes.run_task if args.mode == "task" else modes.run_team
    asyncio.run(runner(task, cfg))


if __name__ == "__main__":
    main()
