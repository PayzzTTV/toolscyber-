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
    with patch("core.alerting.send_email") as mock_email, patch(
        "core.alerting.send_slack"
    ) as mock_slack:
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
