"""RootGuard — File integrity scanner and rootkit detector."""

import argparse
import logging
import os
import sys
import time

from config.settings import BASELINE_PATH, CRITICAL_PATHS, LOG_LEVEL, LOG_PATH
from core.baseline import build_baseline, load_baseline, save_baseline
from core.exceptions import BaselineNotFoundError
from core.reporter import report
from core.scanner import scan


def _setup_logging() -> None:
    """Configure logging with file and console handlers."""
    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format=fmt,
        handlers=[
            logging.FileHandler(LOG_PATH),
            logging.StreamHandler(sys.stderr),
        ],
    )


def cmd_baseline(_args: argparse.Namespace) -> int:
    """Generate and save a new baseline."""
    logger = logging.getLogger("rootguard.baseline")
    logger.info("Building baseline...")
    data = build_baseline()
    save_baseline(data, BASELINE_PATH)
    print(f"Baseline generated: {len(data)} files → {BASELINE_PATH}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan the filesystem and compare against the baseline."""
    logger = logging.getLogger("rootguard.scan")
    try:
        baseline = load_baseline(BASELINE_PATH)
    except BaselineNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    logger.info("Starting scan (%d files in baseline)...", len(baseline))
    start = time.monotonic()
    results = scan(baseline)
    duration = time.monotonic() - start

    mode = getattr(args, "output", "terminal") or "terminal"
    report(results, mode=mode, duration=duration, total=len(baseline))

    anomalies = sum(len(v) for v in results.values())
    return 1 if anomalies > 0 else 0


def cmd_config(args: argparse.Namespace) -> int:
    """Display configuration information."""
    if args.list_paths:
        print("Monitored paths:")
        for p in CRITICAL_PATHS:
            print(f"  {p}")
    return 0


def main() -> None:
    """Entry point — parse arguments and dispatch to subcommands."""
    _setup_logging()

    parser = argparse.ArgumentParser(
        prog="rootguard",
        description="File integrity scanner and rootkit detector.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # baseline
    subparsers.add_parser("baseline", help="Generate a new baseline snapshot.")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan and compare against baseline.")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output.")
    scan_parser.add_argument(
        "--output", choices=["terminal", "json"], default="terminal",
        help="Output format (default: terminal).",
    )

    # config
    config_parser = subparsers.add_parser("config", help="Show configuration.")
    config_parser.add_argument("--list-paths", action="store_true", help="List monitored paths.")

    args = parser.parse_args()

    dispatch = {
        "baseline": cmd_baseline,
        "scan": cmd_scan,
        "config": cmd_config,
    }
    exit_code = dispatch[args.command](args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
