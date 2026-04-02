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
LOG_PATH: str = "logs/scan_history.log"

# Hash computation chunk size (bytes)
CHUNK_SIZE: int = 8192

# Log level from environment, default INFO
LOG_LEVEL: str = os.environ.get("ROOTGUARD_LOG_LEVEL", "INFO")
