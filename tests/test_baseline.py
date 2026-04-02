"""Tests for core/baseline.py"""

import json
import os
import stat
from unittest.mock import patch

import pytest

from core.baseline import build_baseline, load_baseline, save_baseline
from core.exceptions import BaselineNotFoundError


def test_build_baseline_scans_files(tmp_path):
    """build_baseline returns a dict with hash, size, mtime for each file."""
    (tmp_path / "file.txt").write_bytes(b"hello")
    with patch("core.baseline.CRITICAL_PATHS", [str(tmp_path)]):
        result = build_baseline()
    key = str(tmp_path / "file.txt")
    assert key in result
    assert "hash" in result[key]
    assert "size" in result[key]
    assert "mtime" in result[key]
    assert result[key]["size"] == 5


def test_build_baseline_skips_extensions(tmp_path):
    """build_baseline skips files with ignored extensions."""
    (tmp_path / "data.log").write_bytes(b"log data")
    (tmp_path / "data.txt").write_bytes(b"real data")
    with patch("core.baseline.CRITICAL_PATHS", [str(tmp_path)]):
        result = build_baseline()
    assert str(tmp_path / "data.log") not in result
    assert str(tmp_path / "data.txt") in result


def test_build_baseline_missing_path(tmp_path):
    """build_baseline logs a warning and skips nonexistent paths."""
    with patch("core.baseline.CRITICAL_PATHS", ["/nonexistent/path/xyz"]):
        result = build_baseline()
    assert result == {}


def test_save_baseline_creates_file(tmp_path):
    """save_baseline writes valid JSON with generated_at and system fields."""
    data = {"files": {}}
    path = str(tmp_path / "baseline.json")
    save_baseline(data, path)
    assert os.path.exists(path)
    with open(path) as f:
        payload = json.load(f)
    assert "generated_at" in payload
    assert "system" in payload
    assert "files" in payload


def test_save_baseline_sets_readonly(tmp_path):
    """save_baseline sets the file to chmod 400."""
    data = {}
    path = str(tmp_path / "baseline.json")
    save_baseline(data, path)
    mode = os.stat(path).st_mode
    # Owner read-only: S_IRUSR set, S_IWUSR not set
    assert mode & stat.S_IRUSR
    assert not (mode & stat.S_IWUSR)


def test_load_baseline_returns_files(tmp_path):
    """load_baseline returns the files dict from a valid baseline JSON."""
    payload = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "system": {},
        "files": {"/etc/passwd": {"hash": "abc123", "size": 1, "mtime": 0.0}},
    }
    path = str(tmp_path / "baseline.json")
    with open(path, "w") as f:
        json.dump(payload, f)
    result = load_baseline(path)
    assert "/etc/passwd" in result
    assert result["/etc/passwd"]["hash"] == "abc123"


def test_load_baseline_raises_when_missing(tmp_path):
    """load_baseline raises BaselineNotFoundError when file does not exist."""
    with pytest.raises(BaselineNotFoundError):
        load_baseline(str(tmp_path / "nonexistent.json"))
