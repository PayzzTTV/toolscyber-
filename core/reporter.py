"""Scan results reporter — terminal (rich or ASCII) and JSON modes."""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Severity labels per category
_SEVERITY: dict[str, tuple[str, str]] = {
    "modified": ("CRITICAL", "red"),
    "new": ("HIGH", "yellow"),
    "missing": ("MEDIUM", "cyan"),
}

try:
    from rich.console import Console
    _RICH_AVAILABLE = True
    _console = Console()
except ImportError:
    _RICH_AVAILABLE = False


def _report_terminal_rich(results: dict, duration: float, total: int) -> None:
    """Rich terminal report with colors."""
    anomalies = sum(len(v) for v in results.values())

    _console.print("\n[bold]RootGuard Scan Report[/bold]")
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
