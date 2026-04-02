# RootGuard V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construire un CLI Python qui génère une baseline SHA-256 des fichiers critiques d'un système Linux et détecte toute modification, ajout ou suppression lors d'un scan.

**Architecture:** Modules découplés à responsabilité unique (`hasher`, `baseline`, `scanner`, `reporter`) orchestrés par un point d'entrée CLI `main.py`. Chaque module expose des interfaces typées et testables indépendamment.

**Tech Stack:** Python 3.10+, stdlib uniquement (`hashlib`, `json`, `os`, `stat`, `logging`, `argparse`, `platform`), `rich` optionnel pour l'UI terminal.

**Base dir:** `/Users/alexisdelburg/Desktop/Claude/rootguard/`

---

## Carte des fichiers

| Fichier | Rôle |
|---|---|
| `core/exceptions.py` | Exceptions typées : `HashError`, `BaselineNotFoundError` |
| `config/__init__.py` | Package marker |
| `config/settings.py` | Constantes : chemins, extensions, chunk size |
| `core/__init__.py` | Package marker |
| `core/hasher.py` | `hash_file(path) -> str` — SHA-256 par chunks |
| `core/baseline.py` | `build_baseline()`, `save_baseline()`, `load_baseline()` |
| `core/scanner.py` | `scan(baseline) -> dict` — détection modified/new/missing |
| `core/reporter.py` | `report(results, mode, duration, total)` — terminal + JSON |
| `main.py` | CLI argparse, orchestre les modules |
| `tests/fixtures/sample.txt` | Fichier fixe pour tests reproductibles |
| `tests/test_hasher.py` | Tests unitaires de `hash_file` |
| `tests/test_scanner.py` | Tests unitaires de `scan` |
| `requirements.txt` | Dépendances (rich optionnel) |
| `README.md` | Installation, usage, exemples |

---

## Task 1 : Exceptions typées

**Files:**
- Create: `core/exceptions.py`

- [ ] **Step 1 : Créer `core/exceptions.py`**

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
```

- [ ] **Step 2 : Créer les `__init__.py` vides**

```bash
touch /Users/alexisdelburg/Desktop/Claude/rootguard/core/__init__.py
touch /Users/alexisdelburg/Desktop/Claude/rootguard/config/__init__.py
touch /Users/alexisdelburg/Desktop/Claude/rootguard/tests/__init__.py
```

- [ ] **Step 3 : Vérifier que Python importe sans erreur**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -c "from core.exceptions import HashError, BaselineNotFoundError; print('OK')"
```
Expected: `OK`

---

## Task 2 : Configuration

**Files:**
- Create: `config/settings.py`

- [ ] **Step 1 : Créer `config/settings.py`**

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
LOG_PATH: str = "logs/scan_history.log"

# Hash computation chunk size (bytes)
CHUNK_SIZE: int = 8192

# Log level from environment, default INFO
LOG_LEVEL: str = os.environ.get("ROOTGUARD_LOG_LEVEL", "INFO")
```

- [ ] **Step 2 : Vérifier l'import**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -c "from config.settings import CRITICAL_PATHS, CHUNK_SIZE; print(CHUNK_SIZE)"
```
Expected: `8192`

---

## Task 3 : Hasher — TDD

**Files:**
- Create: `core/hasher.py`
- Create: `tests/fixtures/sample.txt`
- Create: `tests/test_hasher.py`

- [ ] **Step 1 : Créer le fichier fixture**

Contenu exact (ne pas modifier — le SHA-256 attendu en dépend) :

```
Hello RootGuard
```

Fichier : `tests/fixtures/sample.txt`

- [ ] **Step 2 : Calculer le SHA-256 attendu**

```bash
python3 -c "
import hashlib
with open('tests/fixtures/sample.txt', 'rb') as f:
    print(hashlib.sha256(f.read()).hexdigest())
"
```
Nota : noter la valeur affichée, elle servira dans les tests.

- [ ] **Step 3 : Écrire les tests (ils doivent ÉCHOUER)**

```python
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
```

- [ ] **Step 4 : Lancer les tests, vérifier qu'ils échouent**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -m pytest tests/test_hasher.py -v
```
Expected: 4 erreurs `ModuleNotFoundError` ou `ImportError` (hasher pas encore créé)

- [ ] **Step 5 : Implémenter `core/hasher.py`**

```python
"""SHA-256 file hashing with chunked reads."""

import hashlib
import logging

from config.settings import CHUNK_SIZE
from core.exceptions import HashError

logger = logging.getLogger(__name__)


def hash_file(path: str) -> str:
    """Compute the SHA-256 hash of a file using chunked reads.

    Args:
        path: Absolute path to the file.

    Returns:
        Hexadecimal SHA-256 digest string.

    Raises:
        HashError: If the file cannot be read (permission denied or not found).
    """
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                hasher.update(chunk)
    except (PermissionError, FileNotFoundError) as exc:
        raise HashError(path, exc) from exc
    return hasher.hexdigest()
```

- [ ] **Step 6 : Lancer les tests, vérifier qu'ils passent**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -m pytest tests/test_hasher.py -v
```
Expected: 4 PASSED

---

## Task 4 : Baseline — génération et persistance

**Files:**
- Create: `core/baseline.py`

- [ ] **Step 1 : Implémenter `core/baseline.py`**

```python
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
```

- [ ] **Step 2 : Vérifier l'import**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -c "from core.baseline import build_baseline, save_baseline, load_baseline; print('OK')"
```
Expected: `OK`

---

## Task 5 : Scanner — TDD

**Files:**
- Create: `core/scanner.py`
- Create: `tests/test_scanner.py`

- [ ] **Step 1 : Écrire les tests (ils doivent ÉCHOUER)**

```python
"""Tests for core/scanner.py"""

import os
import pytest
from unittest.mock import patch
from core.scanner import scan


def _make_baseline(tmp_path, files: dict[str, bytes]) -> dict:
    """Helper : crée des fichiers sur disque et retourne une baseline fictive."""
    import hashlib
    baseline = {}
    for name, content in files.items():
        p = tmp_path / name
        p.write_bytes(content)
        h = hashlib.sha256(content).hexdigest()
        stat = p.stat()
        baseline[str(p)] = {"hash": h, "size": stat.st_size, "mtime": stat.st_mtime}
    return baseline


def test_scan_no_changes(tmp_path):
    """scan returns empty lists when nothing changed."""
    baseline = _make_baseline(tmp_path, {"a.txt": b"hello", "b.txt": b"world"})
    results = scan(baseline)
    assert results["modified"] == []
    assert results["new"] == []
    assert results["missing"] == []


def test_scan_detects_modified(tmp_path):
    """scan detects a file whose content changed."""
    baseline = _make_baseline(tmp_path, {"a.txt": b"original"})
    # Modify the file content
    (tmp_path / "a.txt").write_bytes(b"tampered")
    results = scan(baseline)
    assert len(results["modified"]) == 1
    assert results["modified"][0]["path"] == str(tmp_path / "a.txt")


def test_scan_detects_missing(tmp_path):
    """scan detects a file that was deleted."""
    baseline = _make_baseline(tmp_path, {"gone.txt": b"data"})
    os.remove(str(tmp_path / "gone.txt"))
    results = scan(baseline)
    assert len(results["missing"]) == 1
    assert results["missing"][0]["path"] == str(tmp_path / "gone.txt")


def test_scan_detects_new(tmp_path):
    """scan detects a file that was not in the baseline."""
    # Baseline contains a.txt only
    baseline = _make_baseline(tmp_path, {"a.txt": b"hello"})
    # A new file appears in the same directory
    (tmp_path / "new.txt").write_bytes(b"new file")

    # Patch CRITICAL_PATHS to point to tmp_path
    with patch("core.scanner.CRITICAL_PATHS", [str(tmp_path)]):
        results = scan(baseline)

    assert any(r["path"] == str(tmp_path / "new.txt") for r in results["new"])
```

- [ ] **Step 2 : Lancer les tests, vérifier qu'ils échouent**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -m pytest tests/test_scanner.py -v
```
Expected: `ImportError` ou `ModuleNotFoundError`

- [ ] **Step 3 : Implémenter `core/scanner.py`**

```python
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
```

- [ ] **Step 4 : Lancer les tests, vérifier qu'ils passent**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -m pytest tests/test_scanner.py -v
```
Expected: 4 PASSED

---

## Task 6 : Reporter

**Files:**
- Create: `core/reporter.py`

- [ ] **Step 1 : Implémenter `core/reporter.py`**

```python
"""Scan results reporter — terminal (rich or ASCII) and JSON modes."""

import json
import logging
import sys
from typing import Any

logger = logging.getLogger(__name__)

# Severity labels per category
_SEVERITY = {
    "modified": ("CRITICAL", "red"),
    "new": ("HIGH", "yellow"),
    "missing": ("MEDIUM", "cyan"),
}

try:
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint
    _RICH_AVAILABLE = True
    _console = Console()
except ImportError:
    _RICH_AVAILABLE = False


def _report_terminal_rich(results: dict, duration: float, total: int) -> None:
    """Rich terminal report with colors and table."""
    anomalies = sum(len(v) for v in results.values())

    _console.print(f"\n[bold]RootGuard Scan Report[/bold]")
    _console.print(f"  Files scanned : {total}")
    _console.print(f"  Anomalies     : {anomalies}")
    _console.print(f"  Duration      : {duration:.2f}s\n")

    for category, items in results.items():
        if not items:
            continue
        severity, color = _SEVERITY[category]
        _console.print(f"[bold {color}][{severity}] {category.upper()} ({len(items)})[/bold {color}]")
        for item in items:
            _console.print(f"  [{color}]•[/{color}] {item['path']}")
            if item.get("old_hash"):
                _console.print(f"    old: {item['old_hash']}")
            if item.get("new_hash"):
                _console.print(f"    new: {item['new_hash']}")

    if anomalies == 0:
        _console.print("[bold green]✓ No anomalies detected.[/bold green]")


def _report_terminal_ascii(results: dict, duration: float, total: int) -> None:
    """Plain ASCII terminal report (no external dependencies)."""
    anomalies = sum(len(v) for v in results.values())

    print("\n=== RootGuard Scan Report ===")
    print(f"  Files scanned : {total}")
    print(f"  Anomalies     : {anomalies}")
    print(f"  Duration      : {duration:.2f}s\n")

    for category, items in results.items():
        if not items:
            continue
        severity, _ = _SEVERITY[category]
        print(f"[{severity}] {category.upper()} ({len(items)})")
        for item in items:
            print(f"  * {item['path']}")
            if item.get("old_hash"):
                print(f"    old: {item['old_hash']}")
            if item.get("new_hash"):
                print(f"    new: {item['new_hash']}")

    if anomalies == 0:
        print("OK: No anomalies detected.")


def report(
    results: dict[str, list[dict[str, Any]]],
    mode: str = "terminal",
    duration: float = 0.0,
    total: int = 0,
) -> None:
    """Display scan results in the requested format.

    Args:
        results: Dict with keys ``modified``, ``new``, ``missing``.
        mode: ``"terminal"`` or ``"json"``.
        duration: Scan duration in seconds.
        total: Number of files scanned.
    """
    if mode == "json":
        output = {
            "summary": {
                "files_scanned": total,
                "anomalies": sum(len(v) for v in results.values()),
                "duration_seconds": round(duration, 3),
            },
            "results": results,
        }
        print(json.dumps(output, indent=2))
        return

    if _RICH_AVAILABLE:
        _report_terminal_rich(results, duration, total)
    else:
        _report_terminal_ascii(results, duration, total)
```

- [ ] **Step 2 : Vérifier l'import**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -c "from core.reporter import report; print('OK')"
```
Expected: `OK`

---

## Task 7 : CLI principal

**Files:**
- Create: `main.py`

- [ ] **Step 1 : Implémenter `main.py`**

```python
"""RootGuard — File integrity scanner and rootkit detector."""

import argparse
import logging
import os
import sys
import time

from config.settings import BASELINE_PATH, CRITICAL_PATHS, LOG_LEVEL, LOG_PATH
from core.baseline import build_baseline, load_baseline, save_baseline
from core.exceptions import BaselineNotFoundError
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


def cmd_baseline(_args: argparse.Namespace) -> int:
    """Generate and save a new baseline."""
    logger = logging.getLogger("rootguard.baseline")
    logger.info("Building baseline...")
    data = build_baseline()
    save_baseline(data, BASELINE_PATH)
    print(f"Baseline generated: {len(data)} files → {BASELINE_PATH}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan the filesystem and compare against the baseline."""
    logger = logging.getLogger("rootguard.scan")
    try:
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
    subparsers.add_parser("baseline", help="Generate a new baseline snapshot.")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan and compare against baseline.")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output.")
    scan_parser.add_argument(
        "--output", choices=["terminal", "json"], default="terminal",
        help="Output format (default: terminal).",
    )

    # config
    config_parser = subparsers.add_parser("config", help="Show configuration.")
    config_parser.add_argument("--list-paths", action="store_true", help="List monitored paths.")

    args = parser.parse_args()

    dispatch = {
        "baseline": cmd_baseline,
        "scan": cmd_scan,
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
```
Expected: aide argparse avec les commandes `baseline`, `scan`, `config`

---

## Task 8 : requirements.txt

**Files:**
- Create: `requirements.txt`

- [ ] **Step 1 : Créer `requirements.txt`**

```
# Core — stdlib only, no mandatory dependencies
# Optional UI enhancement
rich>=13.0.0

# Development / testing
pytest>=7.4.0
pytest-cov>=4.1.0
```

- [ ] **Step 2 : Installer les dépendances**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
pip3 install -r requirements.txt
```
Expected: installation sans erreur

---

## Task 9 : Tests complets + coverage

- [ ] **Step 1 : Lancer tous les tests avec coverage**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 -m pytest tests/ -v --cov=core --cov=config --cov-report=term-missing
```
Expected: tous les tests PASSED, coverage > 80%

- [ ] **Step 2 : Corriger tout test en échec avant de continuer**

Si un test échoue, lire l'erreur, corriger le code, relancer jusqu'à PASSED.

---

## Task 10 : Smoke test end-to-end

- [ ] **Step 1 : Tester `config --list-paths`**

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 main.py config --list-paths
```
Expected: liste des 8 chemins critiques

- [ ] **Step 2 : Générer une baseline sur un dossier de test**

Modifier temporairement `CRITICAL_PATHS` dans `config/settings.py` pour pointer vers `tests/fixtures` (pour éviter le besoin de sudo) :

```python
CRITICAL_PATHS: list[str] = ["tests/fixtures"]
```

Puis :

```bash
cd /Users/alexisdelburg/Desktop/Claude/rootguard
python3 main.py baseline
```
Expected: `Baseline generated: 1 files → db/baseline.json`

- [ ] **Step 3 : Scanner — aucune anomalie**

```bash
python3 main.py scan
```
Expected: rapport avec 0 anomalie, exit code 0

```bash
echo $?
```
Expected: `0`

- [ ] **Step 4 : Modifier le fichier fixture, scanner — anomalie détectée**

```bash
echo "tampered" >> tests/fixtures/sample.txt
python3 main.py scan
```
Expected: rapport avec 1 anomalie MODIFIED, exit code 1

```bash
echo $?
```
Expected: `1`

- [ ] **Step 5 : Restaurer le fichier fixture**

```bash
# Restaurer sample.txt à son contenu original
printf "Hello RootGuard\n" > tests/fixtures/sample.txt
```

- [ ] **Step 6 : Restaurer `CRITICAL_PATHS` dans `config/settings.py`**

Remettre les vrais chemins Linux :

```python
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
```

---

## Task 11 : README

**Files:**
- Create: `README.md`

- [ ] **Step 1 : Créer `README.md`**

```markdown
# RootGuard — Scanner d'Intégrité & Détection de Rootkits

Outil CLI Python qui surveille l'intégrité des fichiers critiques d'un système Linux. Il génère une baseline cryptographique (SHA-256) de l'état sain, puis la compare lors de chaque scan pour détecter toute modification, ajout ou suppression suspecte.

## Installation

```bash
git clone <repo>
cd rootguard
pip install -r requirements.txt
```

## Usage

```bash
# Générer la baseline (sur système sain, en root)
sudo python3 main.py baseline

# Scanner le système
sudo python3 main.py scan

# Rapport en JSON
sudo python3 main.py scan --output json

# Voir les chemins surveillés
python3 main.py config --list-paths
```

## Codes de sortie

| Code | Signification |
|---|---|
| `0` | Aucune anomalie |
| `1` | Anomalies détectées |
| `2` | Erreur de configuration |

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `ROOTGUARD_LOG_LEVEL` | `INFO` | Niveau de log (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

## Structure

```
core/       — Moteur (hasher, baseline, scanner, reporter)
config/     — Constantes et chemins surveillés
db/         — baseline.json (généré, chmod 400)
logs/       — Historique des scans
tests/      — Tests unitaires
```

## Tests

```bash
python3 -m pytest tests/ -v --cov=core
```
```

---

## Self-Review Checklist

- [x] **Couverture spec** : tous les modules du CLAUDE.md sont couverts (hasher, baseline, scanner, reporter, main, tests, README)
- [x] **Exit codes** : 0 (propre), 1 (anomalies), 2 (config error) — tous implémentés
- [x] **Sécurité** : chmod 400, pas de log de contenu, gestion PermissionError — présents
- [x] **TDD** : tests écrits avant implémentation pour hasher et scanner
- [x] **Pas de placeholder** : tout le code est complet
- [x] **Cohérence des types** : `hash_file() -> str`, `build_baseline() -> dict[str, dict]`, `scan(baseline: dict) -> dict` — cohérents entre tasks
- [x] **Smoke test end-to-end** : Task 10 couvre les 3 cas (baseline, scan propre, scan avec anomalie)
