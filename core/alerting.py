"""Email and Slack alerting for RootGuard scan anomalies."""

import json
import logging
import smtplib
import urllib.request
from email.mime.text import MIMEText
from typing import Any

logger = logging.getLogger(__name__)


def notify(results: dict[str, list[dict[str, Any]]], channels: dict[str, dict]) -> None:
    """Send alerts to all configured channels if anomalies were found.

    Args:
        results: Scan results dict with keys ``modified``, ``new``, ``missing``.
        channels: Dict of channel name to config dict.
                  Supported keys: ``"email"``, ``"slack"``.
    """
    anomalies = sum(len(v) for v in results.values())
    if anomalies == 0:
        logger.debug("No anomalies — skipping alerts.")
        return

    if "email" in channels:
        try:
            send_email(results, channels["email"])
            logger.info("Email alert sent.")
        except Exception as exc:
            logger.error("Failed to send email alert: %s", exc)

    if "slack" in channels:
        try:
            send_slack(results, channels["slack"])
            logger.info("Slack alert sent.")
        except Exception as exc:
            logger.error("Failed to send Slack alert: %s", exc)


def send_email(results: dict[str, list[dict[str, Any]]], cfg: dict) -> None:
    """Send an SMTP email alert with the scan anomalies.

    Args:
        results: Scan results dict.
        cfg: Email config with keys ``host``, ``port``, ``user``, ``password``,
             ``to``, ``use_tls``.
    """
    anomalies = sum(len(v) for v in results.values())

    lines = [f"RootGuard detected {anomalies} anomaly(ies):\n"]
    for category, items in results.items():
        if items:
            lines.append(f"[{category.upper()}] ({len(items)})")
            for item in items:
                lines.append(f"  {item['path']}")
            lines.append("")

    body = "\n".join(lines)
    msg = MIMEText(body)
    msg["Subject"] = f"[RootGuard] {anomalies} anomaly(ies) detected"
    msg["From"] = cfg["user"]
    msg["To"] = cfg["to"]

    with smtplib.SMTP(cfg["host"], cfg["port"]) as server:
        if cfg.get("use_tls", True):
            server.starttls()
        if cfg.get("user") and cfg.get("password"):
            server.login(cfg["user"], cfg["password"])
        server.send_message(msg)


def send_slack(results: dict[str, list[dict[str, Any]]], cfg: dict) -> None:
    """Send a Slack webhook alert with the scan anomalies.

    Args:
        results: Scan results dict.
        cfg: Slack config with key ``webhook_url``.
    """
    anomalies = sum(len(v) for v in results.values())

    lines = [f"*RootGuard* detected *{anomalies}* anomaly(ies):"]
    for category, items in results.items():
        if items:
            lines.append(f"\n*{category.upper()}* ({len(items)}):")
            for item in items:
                lines.append(f"  • `{item['path']}`")

    text = "\n".join(lines)
    payload = json.dumps({"text": text}).encode()

    req = urllib.request.Request(
        cfg["webhook_url"],
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=10)  # nosec B310 — URL comes from config, not user input
