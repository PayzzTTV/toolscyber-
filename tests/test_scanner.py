"""Tests for core/scanner.py"""

import hashlib
import os
from unittest.mock import patch

import pytest

from core.scanner import scan


def _make_baseline(tmp_path, files: dict[str, bytes]) -> dict:
    """Helper : crée des fichiers sur disque et retourne une baseline fictive."""
    baseline = {}
    for name, content in files.items():
        p = tmp_path / name
        p.write_bytes(content)
        h = hashlib.sha256(content).hexdigest()
        file_stat = p.stat()
        baseline[str(p)] = {
            "hash": h,
            "size": file_stat.st_size,
            "mtime": file_stat.st_mtime,
        }
    return baseline


def test_scan_no_changes(tmp_path):
    """scan returns empty lists when nothing changed."""
    baseline = _make_baseline(tmp_path, {"a.txt": b"hello", "b.txt": b"world"})
    with patch("core.scanner.CRITICAL_PATHS", [str(tmp_path)]):
        results = scan(baseline)
    assert results["modified"] == []
    assert results["new"] == []
    assert results["missing"] == []


def test_scan_detects_modified(tmp_path):
    """scan detects a file whose content changed."""
    baseline = _make_baseline(tmp_path, {"a.txt": b"original"})
    (tmp_path / "a.txt").write_bytes(b"tampered")
    with patch("core.scanner.CRITICAL_PATHS", [str(tmp_path)]):
        results = scan(baseline)
    assert len(results["modified"]) == 1
    assert results["modified"][0]["path"] == str(tmp_path / "a.txt")


def test_scan_detects_missing(tmp_path):
    """scan detects a file that was deleted."""
    baseline = _make_baseline(tmp_path, {"gone.txt": b"data"})
    os.remove(str(tmp_path / "gone.txt"))
    with patch("core.scanner.CRITICAL_PATHS", [str(tmp_path)]):
        results = scan(baseline)
    assert len(results["missing"]) == 1
    assert results["missing"][0]["path"] == str(tmp_path / "gone.txt")


def test_scan_detects_new(tmp_path):
    """scan detects a file that was not in the baseline."""
    baseline = _make_baseline(tmp_path, {"a.txt": b"hello"})
    (tmp_path / "new.txt").write_bytes(b"new file")
    with patch("core.scanner.CRITICAL_PATHS", [str(tmp_path)]):
        results = scan(baseline)
    assert any(r["path"] == str(tmp_path / "new.txt") for r in results["new"])
