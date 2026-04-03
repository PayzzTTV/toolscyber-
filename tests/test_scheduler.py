"""Tests for core/scheduler.py"""

from unittest.mock import MagicMock, patch

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
        run_daemon(interval_seconds=1, baseline_path="db/baseline.json")
