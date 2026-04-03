"""RootGuard — File integrity scanner and rootkit detector."""

import argparse
import logging
import os
import sys
import time

from config.settings import (
    BASELINE_ENC_PATH,
    BASELINE_PATH,
    BASELINE_SIG_PATH,
    CRITICAL_PATHS,
    DAEMON_INTERVAL,
    LOG_LEVEL,
    LOG_PATH,
)
from core.baseline import build_baseline, load_baseline, save_baseline
from core.exceptions import BaselineNotFoundError, SignatureError
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


def cmd_baseline(args: argparse.Namespace) -> int:
    """Generate and save a new baseline, optionally encrypted."""
    logger = logging.getLogger("rootguard.baseline")
    logger.info("Building baseline...")
    data = build_baseline()
    save_baseline(data, BASELINE_PATH)
    print(f"Baseline generated: {len(data)} files → {BASELINE_PATH}")

    if args.encrypt:
        encrypt_key = os.environ.get("ROOTGUARD_ENCRYPT_KEY")
        if not encrypt_key:
            print("ERROR: ROOTGUARD_ENCRYPT_KEY env var required for --encrypt.", file=sys.stderr)
            return 2
        from core.crypto import encrypt_baseline, sign_baseline
        sign_baseline(BASELINE_PATH, BASELINE_SIG_PATH)
        encrypt_baseline(BASELINE_PATH, encrypt_key, BASELINE_ENC_PATH)
        print(f"Baseline signed   : {BASELINE_SIG_PATH}")
        print(f"Baseline encrypted: {BASELINE_ENC_PATH}")

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan the filesystem and compare against the baseline."""
    logger = logging.getLogger("rootguard.scan")
    encrypt_key = os.environ.get("ROOTGUARD_ENCRYPT_KEY")

    try:
        if encrypt_key and os.path.exists(BASELINE_ENC_PATH):
            if args.verify and os.path.exists(BASELINE_SIG_PATH):
                from core.crypto import verify_signature
                try:
                    verify_signature(BASELINE_ENC_PATH, BASELINE_SIG_PATH)
                    logger.info("Baseline signature verified.")
                except SignatureError as exc:
                    print(f"ERROR: {exc}", file=sys.stderr)
                    return 2
            from core.crypto import decrypt_baseline
            baseline = decrypt_baseline(BASELINE_ENC_PATH, encrypt_key)
        else:
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


def cmd_daemon(args: argparse.Namespace) -> int:
    """Run RootGuard as a periodic scan daemon."""
    from core.scheduler import run_daemon
    encrypt_key = os.environ.get("ROOTGUARD_ENCRYPT_KEY")
    interval = args.interval or DAEMON_INTERVAL
    run_daemon(interval_seconds=interval, baseline_path=BASELINE_PATH, encrypt_key=encrypt_key)
    return 0


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
    baseline_parser = subparsers.add_parser("baseline", help="Generate a new baseline snapshot.")
    baseline_parser.add_argument(
        "--encrypt", action="store_true",
        help="Sign and encrypt the baseline (requires ROOTGUARD_ENCRYPT_KEY).",
    )

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan and compare against baseline.")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output.")
    scan_parser.add_argument(
        "--output", choices=["terminal", "json"], default="terminal",
        help="Output format (default: terminal).",
    )
    scan_parser.add_argument(
        "--verify", action="store_true",
        help="Verify baseline signature before scanning.",
    )

    # daemon
    daemon_parser = subparsers.add_parser("daemon", help="Run periodic scan daemon.")
    daemon_parser.add_argument(
        "--interval", type=int, default=None,
        help="Scan interval in seconds (default: ROOTGUARD_INTERVAL or 3600).",
    )

    # config
    config_parser = subparsers.add_parser("config", help="Show configuration.")
    config_parser.add_argument("--list-paths", action="store_true", help="List monitored paths.")

    args = parser.parse_args()

    dispatch = {
        "baseline": cmd_baseline,
        "scan": cmd_scan,
        "daemon": cmd_daemon,
        "config": cmd_config,
    }
    exit_code = dispatch[args.command](args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
