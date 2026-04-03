"""Periodic scan daemon for RootGuard."""

import logging
import os
import signal
import time
from typing import Any

from config.settings import (
    BASELINE_PATH,
    BASELINE_SIG_PATH,
    DAEMON_INTERVAL,
    SLACK_WEBHOOK,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_TO,
    SMTP_USE_TLS,
    SMTP_USER,
)
from core.alerting import notify
from core.baseline import load_baseline
from core.reporter import report
from core.scanner import scan

logger = logging.getLogger(__name__)


def run_daemon(
    interval_seconds: int = DAEMON_INTERVAL,
    baseline_path: str = BASELINE_PATH,
    encrypt_key: str | None = None,
) -> None:
    """Run RootGuard as a periodic scan daemon.

    Args:
        interval_seconds: Seconds between scans.
        baseline_path: Path to the baseline JSON (or .enc if encrypted).
        encrypt_key: AES decryption key if baseline is encrypted, else None.
    """
    _running = True

    def _stop(signum: int, frame: Any) -> None:
        nonlocal _running
        logger.info("Daemon stopping (signal %d)...", signum)
        _running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    cycle = 0
    logger.info("RootGuard daemon started (interval=%ds).", interval_seconds)

    while _running:
        cycle += 1
        logger.info("[DAEMON] Cycle %d starting...", cycle)
        try:
            if encrypt_key:
                from core.crypto import decrypt_baseline, verify_signature

                enc_path = baseline_path.replace(".json", ".enc")
                if os.path.exists(BASELINE_SIG_PATH):
                    verify_signature(enc_path, BASELINE_SIG_PATH)
                baseline = decrypt_baseline(enc_path, encrypt_key)
            else:
                baseline = load_baseline(baseline_path)

            results = scan(baseline)
            report(results, mode="terminal", duration=0.0, total=len(baseline))

            anomalies = sum(len(v) for v in results.values())
            if anomalies > 0:
                channels: dict = {}
                if SMTP_HOST and SMTP_TO:
                    channels["email"] = {
                        "host": SMTP_HOST,
                        "port": SMTP_PORT,
                        "user": SMTP_USER,
                        "password": SMTP_PASSWORD,
                        "to": SMTP_TO,
                        "use_tls": SMTP_USE_TLS,
                    }
                if SLACK_WEBHOOK:
                    channels["slack"] = {"webhook_url": SLACK_WEBHOOK}
                notify(results, channels)

            logger.info(
                "[DAEMON] Cycle %d — %d files — %d anomalies — next scan in %ds",
                cycle,
                len(baseline),
                anomalies,
                interval_seconds,
            )
        except KeyboardInterrupt:
            break
        except Exception as exc:
            logger.error("[DAEMON] Cycle %d failed: %s", cycle, exc)

        if _running:
            try:
                time.sleep(interval_seconds)
            except KeyboardInterrupt:
                break

    logger.info("[DAEMON] Stopped after %d cycle(s).", cycle)
