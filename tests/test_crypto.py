"""Tests for core/crypto.py"""

import json
import os
import stat

import pytest

from core.crypto import decrypt_baseline, encrypt_baseline, sign_baseline, verify_signature
from core.exceptions import SignatureError


def _write_baseline(tmp_path, data: dict) -> str:
    """Helper : écrit un fichier baseline JSON sur disque."""
    path = str(tmp_path / "baseline.json")
    with open(path, "w") as f:
        json.dump({"generated_at": "2026-01-01", "system": {}, "files": data}, f)
    return path


def test_encrypt_decrypt_roundtrip(tmp_path):
    """encrypt + decrypt retourne les données originales."""
    files = {"/etc/passwd": {"hash": "abc123", "size": 1, "mtime": 0.0}}
    path = _write_baseline(tmp_path, files)
    enc_path = str(tmp_path / "baseline.enc")

    encrypt_baseline(path, "secretkey", enc_path)
    result = decrypt_baseline(enc_path, "secretkey")

    assert result == files


def test_encrypt_creates_readonly_file(tmp_path):
    """encrypt_baseline met le fichier .enc en chmod 400."""
    path = _write_baseline(tmp_path, {})
    enc_path = str(tmp_path / "baseline.enc")

    encrypt_baseline(path, "secretkey", enc_path)

    mode = os.stat(enc_path).st_mode
    assert mode & stat.S_IRUSR
    assert not (mode & stat.S_IWUSR)


def test_wrong_key_raises(tmp_path):
    """decrypt_baseline lève une exception si la clé est mauvaise."""
    path = _write_baseline(tmp_path, {"/etc/hosts": {"hash": "xyz", "size": 5, "mtime": 1.0}})
    enc_path = str(tmp_path / "baseline.enc")

    encrypt_baseline(path, "correctkey", enc_path)

    with pytest.raises(Exception):
        decrypt_baseline(enc_path, "wrongkey")


def test_sign_and_verify(tmp_path):
    """sign_baseline + verify_signature ne lève rien sur un fichier intact."""
    path = _write_baseline(tmp_path, {})
    sig_path = str(tmp_path / "baseline.sig")

    sign_baseline(path, sig_path)
    verify_signature(path, sig_path)  # doit passer sans exception


def test_sign_creates_readonly_file(tmp_path):
    """sign_baseline met le fichier .sig en chmod 400."""
    path = _write_baseline(tmp_path, {})
    sig_path = str(tmp_path / "baseline.sig")

    sign_baseline(path, sig_path)

    mode = os.stat(sig_path).st_mode
    assert mode & stat.S_IRUSR
    assert not (mode & stat.S_IWUSR)


def test_verify_tampered_raises(tmp_path):
    """verify_signature lève SignatureError si le fichier a été altéré."""
    path = _write_baseline(tmp_path, {})
    sig_path = str(tmp_path / "baseline.sig")

    sign_baseline(path, sig_path)

    # Altérer le fichier baseline
    with open(path, "a") as f:
        f.write("tampered")

    with pytest.raises(SignatureError):
        verify_signature(path, sig_path)
