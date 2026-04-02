"""Tests for core/reporter.py"""

import json
import sys
from io import StringIO
from unittest.mock import patch

import pytest

from core.reporter import report


EMPTY_RESULTS = {"modified": [], "new": [], "missing": []}
SAMPLE_RESULTS = {
    "modified": [{"path": "/etc/passwd", "old_hash": "aaa", "new_hash": "bbb"}],
    "new": [{"path": "/bin/evil", "old_hash": None, "new_hash": "ccc"}],
    "missing": [{"path": "/bin/ls", "old_hash": "ddd", "new_hash": None}],
}


def test_report_json_output(capsys):
    """report in json mode outputs valid JSON with summary and results."""
    report(SAMPLE_RESULTS, mode="json", duration=1.5, total=100)
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["summary"]["files_scanned"] == 100
    assert output["summary"]["anomalies"] == 3
    assert output["summary"]["duration_seconds"] == 1.5
    assert "modified" in output["results"]
    assert "new" in output["results"]
    assert "missing" in output["results"]


def test_report_json_empty(capsys):
    """report in json mode outputs 0 anomalies for empty results."""
    report(EMPTY_RESULTS, mode="json", duration=0.1, total=50)
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["summary"]["anomalies"] == 0


def test_report_terminal_ascii_no_anomalies(capsys):
    """ASCII terminal report prints 'No anomalies' when results are empty."""
    with patch("core.reporter._RICH_AVAILABLE", False):
        report(EMPTY_RESULTS, mode="terminal", duration=0.5, total=10)
    captured = capsys.readouterr()
    assert "No anomalies" in captured.out
    assert "10" in captured.out


def test_report_terminal_ascii_with_anomalies(capsys):
    """ASCII terminal report lists modified, new, missing files."""
    with patch("core.reporter._RICH_AVAILABLE", False):
        report(SAMPLE_RESULTS, mode="terminal", duration=2.0, total=200)
    captured = capsys.readouterr()
    assert "MODIFIED" in captured.out
    assert "/etc/passwd" in captured.out
    assert "NEW" in captured.out
    assert "/bin/evil" in captured.out
    assert "MISSING" in captured.out
    assert "/bin/ls" in captured.out
