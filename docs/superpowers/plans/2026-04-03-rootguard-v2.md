# RootGuard V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ajouter au CLI RootGuard V1 le chiffrement AES-256-GCM de la baseline, la signature d'intégrité, les alertes email/Slack, et un mode daemon de scan périodique.

**Architecture:** Quatre nouveaux modules (`crypto`, `alerting`, `scheduler`, extension de `exceptions`) s'ajoutent sans toucher au code V1. `main.py` et `config/settings.py` sont étendus avec de nouvelles commandes et variables d'environnement.

**Tech Stack:** Python 3.11+, `cryptography` (AES-256-GCM + PBKDF2), `smtplib` stdlib (email), `urllib.request` stdlib (Slack), `signal` stdlib (daemon).

**Base dir:** `/Users/alexisdelburg/Desktop/Claude/rootguard/`

---

## Carte des fichiers

| Fichier | Action | Rôle |
|---|---|---|
| `core/exceptions.py` | Modifier | Ajouter `SignatureError` |
| `core/crypto.py` | Créer | Chiffrement AES-256-GCM + signature SHA-256 |
| `core/alerting.py` | Créer | Envoi email SMTP + Slack webhook |
| `core/scheduler.py` | Créer | Daemon de scan périodique |
| `config/settings.py` | Modifier | Ajouter constantes SMTP, Slack, daemon, crypto |
| `main.py` | Modifier | Ajouter commandes `daemon` et `baseline --encrypt` / `scan --verify` |
| `requirements.txt` | Modifier | Ajouter `cryptography>=41.0.0` |
| `tests/test_crypto.py` | Créer | Tests TDD pour crypto |
| `tests/test_alerting.py` | Créer | Tests TDD pour alerting |
| `tests/test_scheduler.py` | Créer | Tests TDD pour scheduler |
| `CLAUDE.md` | Modifier | Cocher V2 comme terminée |

---

## Task 1 : SignatureError dans exceptions.py

**Files:**
- Modify: `core/exceptions.py`

- [ ] **Step 1 : Ajouter `SignatureError` à `core/exceptions.py`**

```python
"""Custom exceptions for RootGuard."""


class HashError(Exception):
    """Raised when a file cannot be hashed."""

    def __init__(self, path: str, original: Exception) -> None:
        self.path = path
        self.original = original
        super().__init__(f"Cannot hash '{path}': {original}")


class BaselineNotFoundError(Exception):
    """Raised when the baseline file does not exist."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Baseline not found at '{path}'. Run 'baseline' first.")


class SignatureError(Exception):
    """Raised when the baseline signature does not match (tampering detected)."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Baseline signature mismatch for '{path}'. File may have been tampered with.")
```

- [ ] **Step 2 : Vérifier l'import**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -c "from core.exceptions import SignatureError; print('OK')"
```
Expected: `OK`

---

## Task 2 : Mettre à jour requirements.txt

**Files:**
- Modify: `requirements.txt`

- [ ] **Step 1 : Mettre à jour `requirements.txt`**

```
# Core — stdlib only, no mandatory dependencies
# Optional UI enhancement
rich>=13.0.0

# Encryption (V2)
cryptography>=41.0.0

# Development / testing
pytest>=7.4.0
pytest-cov>=4.1.0
```

- [ ] **Step 2 : Installer**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
pip3 install cryptography>=41.0.0 --quiet
```
Expected: installation sans erreur

- [ ] **Step 3 : Vérifier**

```bash
python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('OK')"
```
Expected: `OK`

---

## Task 3 : core/crypto.py — TDD

**Files:**
- Create: `core/crypto.py`
- Create: `tests/test_crypto.py`

- [ ] **Step 1 : Écrire les tests (ils doivent ÉCHOUER)**

```python
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
```

- [ ] **Step 2 : Lancer les tests, vérifier qu'ils échouent**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -m pytest tests/test_crypto.py -v 2>&1 | tail -5
```
Expected: `ImportError` ou `ModuleNotFoundError`

- [ ] **Step 3 : Implémenter `core/crypto.py`**

```python
"""AES-256-GCM encryption and SHA-256 signature for the baseline file."""

import hashlib
import json
import logging
import os
import stat

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from core.exceptions import SignatureError

logger = logging.getLogger(__name__)

_PBKDF2_ITERATIONS = 100_000
_SALT_SIZE = 16
_NONCE_SIZE = 12
_KEY_SIZE = 32


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt_baseline(path: str, key: str, enc_path: str) -> str:
    """Encrypt a baseline JSON file with AES-256-GCM.

    The output format is: [salt 16B][nonce 12B][ciphertext+tag].
    The authentication tag (16B) is appended to the ciphertext by AESGCM.

    Args:
        path: Path to the plaintext baseline JSON file.
        key: Encryption password (from ROOTGUARD_ENCRYPT_KEY env var).
        enc_path: Destination path for the encrypted file.

    Returns:
        Path to the encrypted file.
    """
    with open(path, "rb") as f:
        data = f.read()

    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    derived = _derive_key(key, salt)
    aesgcm = AESGCM(derived)
    ciphertext = aesgcm.encrypt(nonce, data, None)  # includes 16B tag

    os.makedirs(os.path.dirname(enc_path) or ".", exist_ok=True)
    with open(enc_path, "wb") as f:
        f.write(salt + nonce + ciphertext)

    try:
        os.chmod(enc_path, stat.S_IRUSR)
    except OSError as exc:
        logger.warning("Could not set .enc read-only: %s", exc)

    logger.info("Baseline encrypted to %s", enc_path)
    return enc_path


def decrypt_baseline(enc_path: str, key: str) -> dict:
    """Decrypt an AES-256-GCM encrypted baseline file.

    Args:
        enc_path: Path to the encrypted baseline file.
        key: Decryption password.

    Returns:
        The ``files`` dict from the decrypted baseline JSON.

    Raises:
        cryptography.exceptions.InvalidTag: If key is wrong or file is corrupted.
    """
    with open(enc_path, "rb") as f:
        raw = f.read()

    salt = raw[:_SALT_SIZE]
    nonce = raw[_SALT_SIZE:_SALT_SIZE + _NONCE_SIZE]
    ciphertext = raw[_SALT_SIZE + _NONCE_SIZE:]

    derived = _derive_key(key, salt)
    aesgcm = AESGCM(derived)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    payload = json.loads(plaintext)
    return payload["files"]


def sign_baseline(path: str, sig_path: str) -> str:
    """Compute and store the SHA-256 hash of the baseline file.

    Args:
        path: Path to the baseline JSON file.
        sig_path: Destination path for the signature file.

    Returns:
        The hexadecimal SHA-256 digest.
    """
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()

    os.makedirs(os.path.dirname(sig_path) or ".", exist_ok=True)
    with open(sig_path, "w") as f:
        f.write(digest)

    try:
        os.chmod(sig_path, stat.S_IRUSR)
    except OSError as exc:
        logger.warning("Could not set .sig read-only: %s", exc)

    logger.info("Baseline signed: %s", sig_path)
    return digest


def verify_signature(path: str, sig_path: str) -> None:
    """Verify the SHA-256 signature of a baseline file.

    Args:
        path: Path to the file to verify.
        sig_path: Path to the signature file produced by ``sign_baseline()``.

    Raises:
        SignatureError: If the current hash does not match the stored signature.
    """
    with open(path, "rb") as f:
        current = hashlib.sha256(f.read()).hexdigest()

    with open(sig_path, "r") as f:
        expected = f.read().strip()

    if current != expected:
        raise SignatureError(path)
```

- [ ] **Step 4 : Lancer les tests, vérifier qu'ils passent**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -m pytest tests/test_crypto.py -v
```
Expected: 6 PASSED

- [ ] **Step 5 : Commit**

```bash
git add core/crypto.py core/exceptions.py tests/test_crypto.py requirements.txt
git commit -m "feat(v2): add AES-256-GCM encryption and baseline signature

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 4 : core/alerting.py — TDD

**Files:**
- Create: `core/alerting.py`
- Create: `tests/test_alerting.py`

- [ ] **Step 1 : Écrire les tests (ils doivent ÉCHOUER)**

```python
"""Tests for core/alerting.py"""

import json
from unittest.mock import MagicMock, patch

import pytest

from core.alerting import notify, send_email, send_slack

RESULTS_WITH_ANOMALIES = {
    "modified": [{"path": "/etc/passwd", "old_hash": "aaa", "new_hash": "bbb"}],
    "new": [],
    "missing": [{"path": "/bin/ls", "old_hash": "ccc", "new_hash": None}],
}
RESULTS_EMPTY = {"modified": [], "new": [], "missing": []}

EMAIL_CFG = {
    "host": "smtp.example.com",
    "port": 587,
    "user": "alert@example.com",
    "password": "secret",
    "to": "admin@example.com",
    "use_tls": True,
}
SLACK_CFG = {"webhook_url": "https://hooks.slack.com/services/FAKE"}


def test_notify_skips_if_no_anomalies():
    """notify() n'appelle aucun canal si 0 anomalies."""
    with patch("core.alerting.send_email") as mock_email, \
         patch("core.alerting.send_slack") as mock_slack:
        notify(RESULTS_EMPTY, {"email": EMAIL_CFG, "slack": SLACK_CFG})
        mock_email.assert_not_called()
        mock_slack.assert_not_called()


def test_notify_calls_email_if_configured():
    """notify() appelle send_email si le canal email est dans channels."""
    with patch("core.alerting.send_email") as mock_email:
        notify(RESULTS_WITH_ANOMALIES, {"email": EMAIL_CFG})
        mock_email.assert_called_once_with(RESULTS_WITH_ANOMALIES, EMAIL_CFG)


def test_notify_calls_slack_if_configured():
    """notify() appelle send_slack si le canal slack est dans channels."""
    with patch("core.alerting.send_slack") as mock_slack:
        notify(RESULTS_WITH_ANOMALIES, {"slack": SLACK_CFG})
        mock_slack.assert_called_once_with(RESULTS_WITH_ANOMALIES, SLACK_CFG)


def test_send_email_builds_correct_message():
    """send_email construit un email avec sujet et corps corrects."""
    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        send_email(RESULTS_WITH_ANOMALIES, EMAIL_CFG)

        mock_server.send_message.assert_called_once()
        msg = mock_server.send_message.call_args[0][0]
        assert "[RootGuard]" in msg["Subject"]
        assert "2" in msg["Subject"]  # 2 anomalies
        assert "/etc/passwd" in msg.get_payload()
        assert "/bin/ls" in msg.get_payload()


def test_send_slack_posts_correct_payload():
    """send_slack envoie un payload JSON valide au webhook."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__ = MagicMock()
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        send_slack(RESULTS_WITH_ANOMALIES, SLACK_CFG)

        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode())
        assert "text" in payload
        assert "/etc/passwd" in payload["text"]
```

- [ ] **Step 2 : Lancer les tests, vérifier qu'ils échouent**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -m pytest tests/test_alerting.py -v 2>&1 | tail -5
```
Expected: `ModuleNotFoundError`

- [ ] **Step 3 : Implémenter `core/alerting.py`**

```python
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
    urllib.request.urlopen(req, timeout=10)
```

- [ ] **Step 4 : Lancer les tests, vérifier qu'ils passent**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -m pytest tests/test_alerting.py -v
```
Expected: 5 PASSED

- [ ] **Step 5 : Commit**

```bash
git add core/alerting.py tests/test_alerting.py
git commit -m "feat(v2): add email and Slack alerting

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 5 : Étendre config/settings.py

**Files:**
- Modify: `config/settings.py`

- [ ] **Step 1 : Remplacer le contenu de `config/settings.py`**

```python
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
```

- [ ] **Step 2 : Vérifier l'import**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -c "from config.settings import BASELINE_ENC_PATH, DAEMON_INTERVAL, SLACK_WEBHOOK; print('OK')"
```
Expected: `OK`

---

## Task 6 : core/scheduler.py — TDD

**Files:**
- Create: `core/scheduler.py`
- Create: `tests/test_scheduler.py`

- [ ] **Step 1 : Écrire les tests (ils doivent ÉCHOUER)**

```python
"""Tests for core/scheduler.py"""

from unittest.mock import MagicMock, call, patch

import pytest

from core.scheduler import run_daemon


BASELINE = {"/etc/passwd": {"hash": "abc", "size": 1, "mtime": 0.0}}
RESULTS_CLEAN = {"modified": [], "new": [], "missing": []}
RESULTS_ANOMALY = {
    "modified": [{"path": "/etc/passwd", "old_hash": "abc", "new_hash": "xyz"}],
    "new": [],
    "missing": [],
}


def test_daemon_calls_scan_each_cycle():
    """run_daemon appelle scan() à chaque cycle avant de s'arrêter."""
    call_count = 0

    def fake_sleep(n):
        nonlocal call_count
        call_count += 1
        if call_count >= 2:
            raise KeyboardInterrupt

    with patch("core.scheduler.load_baseline", return_value=BASELINE), \
         patch("core.scheduler.scan", return_value=RESULTS_CLEAN) as mock_scan, \
         patch("core.scheduler.report"), \
         patch("core.scheduler.time.sleep", side_effect=fake_sleep):
        run_daemon(interval_seconds=1, baseline_path="db/baseline.json")

    assert mock_scan.call_count == 2


def test_daemon_calls_notify_on_anomaly():
    """run_daemon appelle notify() si des anomalies sont détectées."""
    call_count = 0

    def fake_sleep(n):
        nonlocal call_count
        call_count += 1
        if call_count >= 1:
            raise KeyboardInterrupt

    with patch("core.scheduler.load_baseline", return_value=BASELINE), \
         patch("core.scheduler.scan", return_value=RESULTS_ANOMALY), \
         patch("core.scheduler.report"), \
         patch("core.scheduler.notify") as mock_notify, \
         patch("core.scheduler.time.sleep", side_effect=fake_sleep):
        run_daemon(interval_seconds=1, baseline_path="db/baseline.json")

    mock_notify.assert_called_once()


def test_daemon_skips_notify_if_clean():
    """run_daemon n'appelle pas notify() si aucune anomalie."""
    call_count = 0

    def fake_sleep(n):
        nonlocal call_count
        call_count += 1
        if call_count >= 1:
            raise KeyboardInterrupt

    with patch("core.scheduler.load_baseline", return_value=BASELINE), \
         patch("core.scheduler.scan", return_value=RESULTS_CLEAN), \
         patch("core.scheduler.report"), \
         patch("core.scheduler.notify") as mock_notify, \
         patch("core.scheduler.time.sleep", side_effect=fake_sleep):
        run_daemon(interval_seconds=1, baseline_path="db/baseline.json")

    mock_notify.assert_not_called()


def test_daemon_stops_on_keyboard_interrupt():
    """run_daemon s'arrête proprement sur KeyboardInterrupt."""
    with patch("core.scheduler.load_baseline", return_value=BASELINE), \
         patch("core.scheduler.scan", return_value=RESULTS_CLEAN), \
         patch("core.scheduler.report"), \
         patch("core.scheduler.time.sleep", side_effect=KeyboardInterrupt):
        # Ne doit pas lever d'exception
        run_daemon(interval_seconds=1, baseline_path="db/baseline.json")
```

- [ ] **Step 2 : Lancer les tests, vérifier qu'ils échouent**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -m pytest tests/test_scheduler.py -v 2>&1 | tail -5
```
Expected: `ModuleNotFoundError`

- [ ] **Step 3 : Implémenter `core/scheduler.py`**

```python
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
                cycle, len(baseline), anomalies, interval_seconds,
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
```

- [ ] **Step 4 : Lancer les tests, vérifier qu'ils passent**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -m pytest tests/test_scheduler.py -v
```
Expected: 4 PASSED

- [ ] **Step 5 : Commit**

```bash
git add core/scheduler.py tests/test_scheduler.py config/settings.py
git commit -m "feat(v2): add periodic scan daemon with signal handling

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 7 : Étendre main.py

**Files:**
- Modify: `main.py`

- [ ] **Step 1 : Remplacer le contenu de `main.py`**

```python
"""RootGuard — File integrity scanner and rootkit detector."""

import argparse
import logging
import os
import sys
import time

from config.settings import (
    BASELINE_ENC_PATH,
    BASELINE_PATH,
    BASELINE_SIG_PATH,
    CRITICAL_PATHS,
    DAEMON_INTERVAL,
    LOG_LEVEL,
    LOG_PATH,
)
from core.baseline import build_baseline, load_baseline, save_baseline
from core.exceptions import BaselineNotFoundError, SignatureError
from core.reporter import report
from core.scanner import scan


def _setup_logging() -> None:
    """Configure logging with file and console handlers."""
    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format=fmt,
        handlers=[
            logging.FileHandler(LOG_PATH),
            logging.StreamHandler(sys.stderr),
        ],
    )


def cmd_baseline(args: argparse.Namespace) -> int:
    """Generate and save a new baseline, optionally encrypted."""
    logger = logging.getLogger("rootguard.baseline")
    logger.info("Building baseline...")
    data = build_baseline()
    save_baseline(data, BASELINE_PATH)
    print(f"Baseline generated: {len(data)} files → {BASELINE_PATH}")

    if args.encrypt:
        encrypt_key = os.environ.get("ROOTGUARD_ENCRYPT_KEY")
        if not encrypt_key:
            print("ERROR: ROOTGUARD_ENCRYPT_KEY env var required for --encrypt.", file=sys.stderr)
            return 2
        from core.crypto import encrypt_baseline, sign_baseline
        sign_baseline(BASELINE_PATH, BASELINE_SIG_PATH)
        encrypt_baseline(BASELINE_PATH, encrypt_key, BASELINE_ENC_PATH)
        print(f"Baseline signed   : {BASELINE_SIG_PATH}")
        print(f"Baseline encrypted: {BASELINE_ENC_PATH}")

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan the filesystem and compare against the baseline."""
    logger = logging.getLogger("rootguard.scan")
    encrypt_key = os.environ.get("ROOTGUARD_ENCRYPT_KEY")

    try:
        if encrypt_key and os.path.exists(BASELINE_ENC_PATH):
            if args.verify and os.path.exists(BASELINE_SIG_PATH):
                from core.crypto import verify_signature
                try:
                    verify_signature(BASELINE_ENC_PATH, BASELINE_SIG_PATH)
                    logger.info("Baseline signature verified.")
                except SignatureError as exc:
                    print(f"ERROR: {exc}", file=sys.stderr)
                    return 2
            from core.crypto import decrypt_baseline
            baseline = decrypt_baseline(BASELINE_ENC_PATH, encrypt_key)
        else:
            baseline = load_baseline(BASELINE_PATH)
    except BaselineNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    logger.info("Starting scan (%d files in baseline)...", len(baseline))
    start = time.monotonic()
    results = scan(baseline)
    duration = time.monotonic() - start

    mode = getattr(args, "output", "terminal") or "terminal"
    report(results, mode=mode, duration=duration, total=len(baseline))

    anomalies = sum(len(v) for v in results.values())
    return 1 if anomalies > 0 else 0


def cmd_daemon(args: argparse.Namespace) -> int:
    """Run RootGuard as a periodic scan daemon."""
    from core.scheduler import run_daemon
    encrypt_key = os.environ.get("ROOTGUARD_ENCRYPT_KEY")
    interval = args.interval or DAEMON_INTERVAL
    run_daemon(interval_seconds=interval, baseline_path=BASELINE_PATH, encrypt_key=encrypt_key)
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    """Display configuration information."""
    if args.list_paths:
        print("Monitored paths:")
        for p in CRITICAL_PATHS:
            print(f"  {p}")
    return 0


def main() -> None:
    """Entry point — parse arguments and dispatch to subcommands."""
    _setup_logging()

    parser = argparse.ArgumentParser(
        prog="rootguard",
        description="File integrity scanner and rootkit detector.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # baseline
    baseline_parser = subparsers.add_parser("baseline", help="Generate a new baseline snapshot.")
    baseline_parser.add_argument(
        "--encrypt", action="store_true",
        help="Sign and encrypt the baseline (requires ROOTGUARD_ENCRYPT_KEY).",
    )

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan and compare against baseline.")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output.")
    scan_parser.add_argument(
        "--output", choices=["terminal", "json"], default="terminal",
        help="Output format (default: terminal).",
    )
    scan_parser.add_argument(
        "--verify", action="store_true",
        help="Verify baseline signature before scanning.",
    )

    # daemon
    daemon_parser = subparsers.add_parser("daemon", help="Run periodic scan daemon.")
    daemon_parser.add_argument(
        "--interval", type=int, default=None,
        help="Scan interval in seconds (default: ROOTGUARD_INTERVAL or 3600).",
    )

    # config
    config_parser = subparsers.add_parser("config", help="Show configuration.")
    config_parser.add_argument("--list-paths", action="store_true", help="List monitored paths.")

    args = parser.parse_args()

    dispatch = {
        "baseline": cmd_baseline,
        "scan": cmd_scan,
        "daemon": cmd_daemon,
        "config": cmd_config,
    }
    exit_code = dispatch[args.command](args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2 : Vérifier le help**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 main.py --help
python3 main.py baseline --help
python3 main.py daemon --help
```
Expected: aide affichée pour chaque commande, `--encrypt` visible dans `baseline`, `--interval` dans `daemon`

---

## Task 8 : Tests complets V2

- [ ] **Step 1 : Lancer tous les tests**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -m pytest tests/ -v --cov=core --cov=config --cov-report=term-missing
```
Expected: tous les tests PASSED, coverage global > 80%

- [ ] **Step 2 : Corriger tout test en échec avant de continuer**

Si un test échoue, lire l'erreur, corriger, relancer.

---

## Task 9 : Mettre à jour CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1 : Marquer V2 comme terminée dans CLAUDE.md**

Remplacer dans `CLAUDE.md` :

```markdown
### 🔜 V2 — Robustesse & Automatisation
```

par :

```markdown
### ✅ V2 — Robustesse & Automatisation (TERMINÉ)
```

Et cocher toutes les cases de la V2 :

```markdown
- [x] **Scheduling** : mode daemon avec scan périodique via `schedule`
- [x] **Alerting email** : notification SMTP si anomalie détectée
- [x] **Alerting Slack** : webhook Slack sur anomalie
- [x] **Chiffrement de la baseline** : AES-256-GCM via `cryptography`
- [x] **Signature de la baseline** : hash de la baseline elle-même, stocké dans `db/baseline.sig`
```

- [ ] **Step 2 : Commit final V2**

```bash
git add .
git commit -m "feat(v2): complete V2 — daemon, alerting, AES-256 encryption, signature

- core/crypto.py: AES-256-GCM + PBKDF2-HMAC-SHA256 + SHA-256 signature
- core/alerting.py: SMTP email + Slack webhook (stdlib only)
- core/scheduler.py: periodic daemon with SIGINT/SIGTERM graceful stop
- main.py: new commands baseline --encrypt, scan --verify, daemon --interval
- config/settings.py: SMTP, Slack, daemon interval constants
- tests: 15 new tests (crypto x6, alerting x5, scheduler x4)
- CLAUDE.md: V2 marked complete

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
git push
```

---

## Self-Review

- [x] **Couverture spec** : crypto (encrypt/decrypt/sign/verify), alerting (email/Slack/notify), scheduler (daemon/signal), main (--encrypt/--verify/daemon) — tous couverts
- [x] **Pas de placeholder** : tout le code est complet dans chaque step
- [x] **Cohérence des types** :
  - `encrypt_baseline(path, key, enc_path)` → cohérent entre Task 3 et Task 7
  - `decrypt_baseline(enc_path, key)` → cohérent entre Task 3 et Task 6
  - `sign_baseline(path, sig_path)` → cohérent entre Task 3 et Task 7
  - `verify_signature(path, sig_path)` → cohérent entre Task 3 et Task 7
  - `notify(results, channels)` → cohérent entre Task 4 et Task 6
  - `run_daemon(interval_seconds, baseline_path, encrypt_key)` → cohérent entre Task 6 et Task 7
- [x] **Sécurité** : `ROOTGUARD_ENCRYPT_KEY` uniquement via env var, jamais loggée
