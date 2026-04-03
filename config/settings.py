"""RootGuard configuration constants."""

import os

# Paths to monitor (Linux critical paths)
CRITICAL_PATHS: list[str] = [
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/etc",
    "/lib",
    "/lib64",
    "/boot",
]

# File extensions to skip (dynamic/ephemeral files)
EXTENSIONS_IGNORE: set[str] = {".log", ".tmp", ".pid", ".lock", ".swp"}

# Pseudo-filesystems to never enter
PSEUDO_FS_EXCLUDE: set[str] = {"/proc", "/sys", "/dev"}

# Storage paths (relative to project root)
BASELINE_PATH: str = "db/baseline.json"
BASELINE_ENC_PATH: str = "db/baseline.enc"
BASELINE_SIG_PATH: str = "db/baseline.sig"
LOG_PATH: str = "logs/scan_history.log"

# Hash computation chunk size (bytes)
CHUNK_SIZE: int = 8192

# Log level from environment, default INFO
LOG_LEVEL: str = os.environ.get("ROOTGUARD_LOG_LEVEL", "INFO")

# Daemon scan interval (seconds)
DAEMON_INTERVAL: int = int(os.environ.get("ROOTGUARD_INTERVAL", "3600"))

# SMTP alerting — all values from environment only
SMTP_HOST: str = os.environ.get("ROOTGUARD_SMTP_HOST", "")
SMTP_PORT: int = int(os.environ.get("ROOTGUARD_SMTP_PORT", "587"))
SMTP_USER: str = os.environ.get("ROOTGUARD_SMTP_USER", "")
SMTP_PASSWORD: str = os.environ.get("ROOTGUARD_SMTP_PASSWORD", "")
SMTP_TO: str = os.environ.get("ROOTGUARD_SMTP_TO", "")
SMTP_USE_TLS: bool = os.environ.get("ROOTGUARD_SMTP_TLS", "true").lower() == "true"

# Slack alerting
SLACK_WEBHOOK: str = os.environ.get("ROOTGUARD_SLACK_WEBHOOK", "")
