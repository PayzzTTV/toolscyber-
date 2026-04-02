"""File system scan and comparison against a baseline."""

import logging
import os
from typing import Any

from config.settings import CRITICAL_PATHS, EXTENSIONS_IGNORE, PSEUDO_FS_EXCLUDE
from core.exceptions import HashError
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


def _collect_current_files() -> dict[str, str]:
    """Walk CRITICAL_PATHS and return {path: current_hash} for all readable files."""
    current: dict[str, str] = {}
    for root_path in CRITICAL_PATHS:
        if not os.path.exists(root_path):
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
                    current[filepath] = hash_file(filepath)
                except HashError as exc:
                    logger.warning("Skipping unreadable file during scan: %s", exc)
    return current


def scan(baseline: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Compare current filesystem state against the baseline.

    Args:
        baseline: Dict as returned by ``load_baseline()`` — maps path to metadata.

    Returns:
        Dict with keys ``"modified"``, ``"new"``, ``"missing"``.
        Each value is a list of dicts ``{"path": str, "old_hash": str|None, "new_hash": str|None}``.
    """
    current = _collect_current_files()

    modified: list[dict[str, Any]] = []
    new: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []

    baseline_paths = set(baseline.keys())
    current_paths = set(current.keys())

    for path in baseline_paths & current_paths:
        old_hash = baseline[path]["hash"]
        new_hash = current[path]
        if old_hash != new_hash:
            modified.append({"path": path, "old_hash": old_hash, "new_hash": new_hash})

    for path in baseline_paths - current_paths:
        missing.append({"path": path, "old_hash": baseline[path]["hash"], "new_hash": None})

    for path in current_paths - baseline_paths:
        new.append({"path": path, "old_hash": None, "new_hash": current[path]})

    return {"modified": modified, "new": new, "missing": missing}
