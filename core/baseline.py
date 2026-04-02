"""Baseline generation, persistence, and loading."""

import json
import logging
import os
import platform
import stat
from datetime import datetime, timezone
from typing import Any

from config.settings import (
    BASELINE_PATH,
    CRITICAL_PATHS,
    EXTENSIONS_IGNORE,
    PSEUDO_FS_EXCLUDE,
)
from core.exceptions import BaselineNotFoundError, HashError
from core.hasher import hash_file

logger = logging.getLogger(__name__)


def _should_skip(path: str) -> bool:
    """Return True if the path should be excluded from scanning."""
    _, ext = os.path.splitext(path)
    if ext in EXTENSIONS_IGNORE:
        return True
    for pseudo in PSEUDO_FS_EXCLUDE:
        if path.startswith(pseudo + os.sep) or path == pseudo:
            return True
    return False


def build_baseline() -> dict[str, dict[str, Any]]:
    """Recursively scan CRITICAL_PATHS and compute hashes for each file.

    Returns:
        Mapping of absolute file path to metadata dict
        ``{"hash": str, "size": int, "mtime": float}``.
    """
    baseline: dict[str, dict[str, Any]] = {}
    for root_path in CRITICAL_PATHS:
        if not os.path.exists(root_path):
            logger.warning("Critical path does not exist, skipping: %s", root_path)
            continue
        for dirpath, _dirnames, filenames in os.walk(root_path):
            if _should_skip(dirpath):
                _dirnames.clear()
                continue
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if _should_skip(filepath):
                    continue
                try:
                    file_stat = os.stat(filepath)
                    file_hash = hash_file(filepath)
                    baseline[filepath] = {
                        "hash": file_hash,
                        "size": file_stat.st_size,
                        "mtime": file_stat.st_mtime,
                    }
                except HashError as exc:
                    logger.warning("Skipping unreadable file: %s", exc)
                except OSError as exc:
                    logger.warning("Cannot stat file %s: %s", filepath, exc)
    return baseline


def save_baseline(data: dict[str, dict[str, Any]], path: str = BASELINE_PATH) -> None:
    """Serialize the baseline dict to a JSON file and set it read-only.

    Args:
        data: Baseline dict as returned by ``build_baseline()``.
        path: Destination file path (created if needed).
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "system": {
            "node": platform.uname().node,
            "system": platform.uname().system,
            "release": platform.uname().release,
            "machine": platform.uname().machine,
        },
        "files": data,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    try:
        os.chmod(path, stat.S_IRUSR)  # chmod 400
    except OSError as exc:
        logger.warning("Could not set baseline read-only: %s", exc)
    logger.info("Baseline saved to %s (%d files)", path, len(data))


def load_baseline(path: str = BASELINE_PATH) -> dict[str, dict[str, Any]]:
    """Load and return the baseline file dict.

    Args:
        path: Path to the baseline JSON file.

    Returns:
        The ``files`` dict from the baseline JSON.

    Raises:
        BaselineNotFoundError: If the file does not exist.
    """
    if not os.path.exists(path):
        raise BaselineNotFoundError(path)
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    return payload["files"]
