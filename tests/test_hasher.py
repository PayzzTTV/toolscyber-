"""Tests for core/hasher.py"""

import hashlib
import os

import pytest

from core.exceptions import HashError
from core.hasher import hash_file

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "sample.txt")


def _expected_hash(path: str) -> str:
    """Compute expected SHA-256 for a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def test_hash_known_file():
    """hash_file returns the correct SHA-256 for a known file."""
    expected = _expected_hash(FIXTURE_PATH)
    assert hash_file(FIXTURE_PATH) == expected


def test_hash_empty_file(tmp_path):
    """hash_file returns SHA-256 of empty bytes for an empty file."""
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    expected = hashlib.sha256(b"").hexdigest()
    assert hash_file(str(empty)) == expected


def test_hash_nonexistent_file_raises():
    """hash_file raises HashError for a nonexistent file."""
    with pytest.raises(HashError) as exc_info:
        hash_file("/nonexistent/path/to/file.txt")
    assert "/nonexistent/path/to/file.txt" in str(exc_info.value)


def test_hash_permission_error(tmp_path, monkeypatch):
    """hash_file raises HashError when file is unreadable."""
    locked = tmp_path / "locked.txt"
    locked.write_bytes(b"secret")

    def mock_open(*args, **kwargs):
        raise PermissionError("Permission denied")

    monkeypatch.setattr("builtins.open", mock_open)
    with pytest.raises(HashError):
        hash_file(str(locked))
