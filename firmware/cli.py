"""Command-line interface for the F1 orchestrator."""

import argparse
import sys
from pathlib import Path

from . import __version__
from . import selftest
from .config import load_config
from .errors import EXIT_OK, EXIT_USAGE
from .orchestrator import DRY_RUN_BANNER, run_campaign
from .plugins import all_plugins


def build_parser():
    parser = argparse.ArgumentParser(
        prog="f1-redteam",
        description="F1 - agentic red-team campaign orchestrator. "
                    "Own-lab only. Dry-run by default; see --execute and the "
                    "Safety Rails section of the README.")
    parser.add_argument("--version", action="version",
                        version="f1-agentic-redteam %s" % __version__)
    sub = parser.add_subparsers(dest="cmd", metavar="COMMAND")

    run = sub.add_parser("run", help="run a campaign (default: dry-run)")
    run.add_argument("--campaign", required=True, metavar="PATH",
                     help="campaign YAML file (see campaigns/)")
    run.add_argument("--execute", action="store_true",
                     help="actually execute actions (default is dry-run)")
    run.add_argument("--interactive", action="store_true",
                     help="prompt for approval at security gates")
    run.add_argument("--max-phases", type=int, default=None,
                     help="hard cap on executed phases (overrides campaign)")
    run.add_argument("--config", default=None, metavar="PATH",
                     help="orchestrator config YAML (default config/orchestrator.yaml)")
    run.add_argument("--out-dir", default=None, metavar="PATH",
                     help="reports output dir (default from config)")
    run.add_argument("--audit-log", default=None, metavar="PATH",
                     help="JSONL audit log path (default from config)")
    run.add_argument("--log-level", default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                     help="logging verbosity (default from config)")

    sub.add_parser("list-plugins", help="list registered plugins")
    sub.add_parser("selftest", help="run the offline self-test suite")
    return parser


def _print_plugins():
    print("%-18s %-8s %-10s %s" % ("NAME", "PHASE", "APPROVAL", "DESCRIPTION"))
    print("-" * 80)
    for cls in all_plugins():
        print("%-18s %-8s %-10s %s" % (
            cls.name, cls.phase,
            "required" if cls.requires_approval else "no",
            (cls.description or "")[:55]))


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd is None:
        parser.print_help()
        return EXIT_USAGE
    if args.cmd == "selftest":
        return selftest.run_selftest()
    if args.cmd == "list-plugins":
        _print_plugins()
        return EXIT_OK

    cfg_path = Path(args.config) if args.config else Path("config/orchestrator.yaml")
    try:
        config = load_config(cfg_path)
    except Exception as exc:
        print("ERROR: cannot load config %s: %s" % (cfg_path, exc), file=sys.stderr)
        return EXIT_USAGE

    if args.out_dir:
        config.output_dir = args.out_dir
    if args.audit_log:
        config.audit_log = args.audit_log
    if args.log_level:
        config.log_level = args.log_level

    interactive = args.interactive or (sys.stdin.isatty() and sys.stdout.isatty())
    if not args.execute:
        print(DRY_RUN_BANNER)

    return run_campaign(
        args.campaign,
        config,
        execute=args.execute,
        interactive=interactive,
        max_phases=args.max_phases,
        out_dir=config.output_dir,
        audit_path=config.audit_log,
        log_dir=config.log_dir,
        log_level=config.log_level,
    )