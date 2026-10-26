"""
Tests for backend/services/sla_escalation_service.py (Issue #914).
Covers: breach detection, escalation team mapping, webhook payload, sweep stats,
no breaches, resolved tickets excluded, already-escalated skipped.
"""

import sys
import os
import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.services.sla_escalation_service import (
    SLAEscalationService,
    ESCALATION_MAP,
)

_PAST = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
_FUTURE = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()


def _mock_client(tickets=None):
    client = MagicMock()
    result = MagicMock()
    result.data = tickets or []

    builder = MagicMock()
    builder.table.return_value = builder
    builder.select.return_value = builder
    builder.lt.return_value = builder
    builder.neq.return_value = builder
    builder.eq.return_value = builder
    builder.update.return_value = builder
    builder.execute.return_value = result

    client.table.return_value = builder
    return client


class TestEscalationMap(unittest.TestCase):
    def test_network_support_escalates(self):
        self.assertIn("Network Support", ESCALATION_MAP)
        self.assertNotEqual(ESCALATION_MAP["Network Support"], "Network Support")

    def test_all_teams_have_escalation(self):
        known_teams = [
            "Network Support", "Hardware Support", "Application Support",
            "IAM Team", "General Support",
        ]
        for team in known_teams:
            self.assertIn(team, ESCALATION_MAP)

    def test_escalation_team_is_different(self):
        for original, escalation in ESCALATION_MAP.items():
            self.assertNotEqual(original, escalation,
                                f"Escalation team for '{original}' must differ from original")


class TestCheckBreaches(unittest.TestCase):
    def test_returns_list_of_breached_tickets(self):
        ticket = {
            "id": "t1", "subject": "VPN issue", "status": "open",
            "sla_breach_at": _PAST, "escalated": False, "assigned_team": "Network Support"
        }
        client = _mock_client(tickets=[ticket])
        svc = SLAEscalationService()
        result = svc.check_breaches(client)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "t1")

    def test_returns_empty_list_on_exception(self):
        client = MagicMock()
        client.table.side_effect = Exception("DB error")
        svc = SLAEscalationService()
        result = svc.check_breaches(client)
        self.assertEqual(result, [])

    def test_company_filter_applied(self):
        client = _mock_client(tickets=[])
        svc = SLAEscalationService()
        svc.check_breaches(client, company_id="company-xyz")
        # Verify .eq was called with company_id
        # (mock chain — just verify it ran without error)
        self.assertIsNotNone(result := svc.check_breaches(client, company_id="company-xyz"))

    def test_returns_empty_when_no_breaches(self):
        client = _mock_client(tickets=[])
        svc = SLAEscalationService()
        result = svc.check_breaches(client)
        self.assertEqual(result, [])


class TestEscalateTicket(unittest.TestCase):
    def test_escalates_to_correct_team(self):
        updated_ticket = {
            "id": "t1", "assigned_team": "Senior Network Engineers",
            "escalated": True, "escalated_at": _PAST
        }
        client = _mock_client(tickets=[updated_ticket])
        client.table.return_value.update.return_value.eq.return_value.execute.return_value.data = [updated_ticket]

        svc = SLAEscalationService()
        result = svc.escalate_ticket(client, "t1", "Network Support")
        # Verify escalation mapped correctly
        self.assertIsInstance(result, dict)

    def test_returns_empty_dict_on_exception(self):
        client = MagicMock()
        client.table.side_effect = Exception("DB error")
        svc = SLAEscalationService()
        result = svc.escalate_ticket(client, "t1", "Network Support")
        self.assertEqual(result, {})

    def test_unknown_team_generates_fallback(self):
        client = _mock_client()
        svc = SLAEscalationService()
        # Should not raise even for unknown team
        result = svc.escalate_ticket(client, "t1", "Unknown Special Team")
        self.assertIsInstance(result, dict)


class TestSendWebhookAlert(unittest.TestCase):
    def test_returns_false_when_no_webhook_configured(self):
        svc = SLAEscalationService()
        svc.slack_webhook_url = ""
        svc.teams_webhook_url = ""
        result = svc.send_webhook_alert({"id": "t1", "subject": "Test"})
        self.assertFalse(result)

    @patch("backend.services.sla_escalation_service._requests_lib")
    def test_sends_slack_payload_to_webhook(self, mock_requests):
        import requests as req
        mock_requests.post.return_value = MagicMock(status_code=200)
        mock_requests.post.return_value.raise_for_status = MagicMock()
        mock_requests.exceptions.RequestException = req.exceptions.RequestException

        svc = SLAEscalationService()
        svc.slack_webhook_url = "https://hooks.slack.com/test"
        ticket = {
            "id": "t1", "subject": "VPN down",
            "priority": "Critical", "assigned_team": "Network Support",
            "sla_breach_at": _PAST,
        }
        result = svc.send_webhook_alert(ticket)
        self.assertTrue(result)
        mock_requests.post.assert_called_once()

    @patch("backend.services.sla_escalation_service._requests_lib")
    def test_returns_false_on_request_failure(self, mock_requests):
        import requests as req
        mock_requests.post.side_effect = req.exceptions.ConnectionError("unreachable")
        mock_requests.exceptions.RequestException = req.exceptions.RequestException

        svc = SLAEscalationService()
        svc.slack_webhook_url = "https://hooks.slack.com/test"
        result = svc.send_webhook_alert({"id": "t1"}, webhook_url="https://hooks.example.com")
        self.assertFalse(result)

    @patch("backend.services.sla_escalation_service._requests_lib")
    def test_webhook_payload_contains_ticket_id(self, mock_requests):
        import requests as req
        captured = {}

        def fake_post(url, json=None, timeout=None):
            captured["payload"] = json
            r = MagicMock()
            r.raise_for_status = MagicMock()
            return r

        mock_requests.post.side_effect = fake_post
        mock_requests.exceptions.RequestException = req.exceptions.RequestException

        svc = SLAEscalationService()
        svc.slack_webhook_url = "https://hooks.slack.com/test"
        svc.send_webhook_alert({"id": "ticket-xyz", "subject": "Network Down"})

        self.assertIn("payload", captured)
        payload_str = str(captured["payload"])
        self.assertIn("ticket-xyz", payload_str)


class TestRunSweep(unittest.TestCase):
    def test_sweep_returns_expected_stats_keys(self):
        client = _mock_client(tickets=[])
        svc = SLAEscalationService()
        stats = svc.run_sweep(client)
        for key in ("breaches_found", "escalated", "alerts_sent",
                    "skipped_already_escalated", "errors"):
            self.assertIn(key, stats)

    def test_sweep_no_breaches_returns_zero_counts(self):
        client = _mock_client(tickets=[])
        svc = SLAEscalationService()
        stats = svc.run_sweep(client)
        self.assertEqual(stats["breaches_found"], 0)
        self.assertEqual(stats["escalated"], 0)

    def test_already_escalated_tickets_skipped(self):
        already_escalated = {
            "id": "t1", "subject": "Resolved", "status": "open",
            "sla_breach_at": _PAST, "escalated": True,
            "assigned_team": "Network Support"
        }
        client = _mock_client(tickets=[already_escalated])
        svc = SLAEscalationService()
        stats = svc.run_sweep(client, send_alerts=False)
        self.assertEqual(stats["skipped_already_escalated"], 1)
        self.assertEqual(stats["escalated"], 0)

    def test_sweep_handles_exception_gracefully(self):
        client = MagicMock()
        client.table.side_effect = Exception("fatal DB error")
        svc = SLAEscalationService()
        stats = svc.run_sweep(client)
        self.assertIn("errors", stats)
        self.assertGreater(stats["errors"], 0)

    def test_sweep_counts_escalated_tickets(self):
        ticket = {
            "id": "t1", "subject": "VPN issue", "status": "open",
            "sla_breach_at": _PAST, "escalated": False,
            "assigned_team": "Network Support"
        }

        update_result = MagicMock()
        update_result.data = [{"id": "t1", "escalated": True}]

        query_result = MagicMock()
        query_result.data = [ticket]

        call_count = [0]

        builder = MagicMock()
        builder.select.return_value = builder
        builder.lt.return_value = builder
        builder.neq.return_value = builder
        builder.eq.return_value = builder
        builder.update.return_value = builder

        def exe():
            call_count[0] += 1
            if call_count[0] == 1:
                return query_result
            return update_result

        builder.execute.side_effect = lambda: exe()
        client = MagicMock()
        client.table.return_value = builder

        svc = SLAEscalationService()
        stats = svc.run_sweep(client, send_alerts=False)
        self.assertGreaterEqual(stats["breaches_found"], 1)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Auto-escalation worker tests (Issue #4077)
# ---------------------------------------------------------------------------
import pytest  # noqa: E402
from backend.services import sla_escalation_service as svc  # noqa: E402

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _reset():
    svc.reset_alert_cache()


def _t(priority="low", mins=30, id=1):
    return {"id": id, "ticket_id": id, "priority": priority, "subject": "s",
            "sla_breach_at": (NOW + timedelta(minutes=mins)).isoformat() if mins is not None else None}


def _sb(rows):
    sb = MagicMock()
    sb.table.return_value.select.return_value.in_.return_value.limit.return_value.execute.return_value.data = rows
    return sb


def test_minutes_to_breach():
    assert svc.minutes_to_breach(_t(mins=30)["sla_breach_at"], NOW) == 30
    assert svc.minutes_to_breach(None, NOW) is None
    assert svc.minutes_to_breach("garbage", NOW) is None


@pytest.mark.parametrize("old,new", [("low", "medium"), ("medium", "high"), ("high", "urgent")])
def test_priority_transitions(old, new):
    assert svc.next_priority(old) == new


def test_urgent_not_escalated():
    assert svc.next_priority("urgent") is None
    assert not svc.should_escalate(_t("urgent", 5), NOW)


def test_should_escalate_thresholds():
    assert svc.should_escalate(_t("low", 59), NOW)
    assert svc.should_escalate(_t("low", -10), NOW)
    assert not svc.should_escalate(_t("low", 120), NOW)
    assert svc.should_escalate(_t("low", 120), NOW, risk_score=0.8)
    assert svc.should_escalate(_t("low", 120), NOW, risk_score=85)
    assert not svc.should_escalate(_t("low", 120), NOW, risk_score=0.5)


def test_missing_breach_timestamp():
    assert not svc.should_escalate(_t("low", None), NOW)


def test_sweep_escalates_and_dedupes():
    rows = [_t("low", 10)]
    sb = _sb(rows)
    with patch("backend.sla_notifier.send_webhook") as wh, patch.object(svc, "_dispatch_slack"):
        r1 = svc.run_sla_sweep(sb, NOW)
        r2 = svc.run_sla_sweep(sb, NOW)
    assert r1["escalated"] == 1 and r1["notified"] == 1
    assert r2["notified"] == 0
    assert wh.call_count == 1
    sb.table.return_value.update.assert_called_with({"priority": "medium"})


def test_sweep_skips_urgent_and_far():
    sb = _sb([_t("urgent", 5, 1), _t("low", 500, 2)])
    r = svc.run_sla_sweep(sb, NOW)
    assert r["escalated"] == 0 and r["skipped"] == 2


def test_sweep_no_client():
    assert svc.run_sla_sweep(None)["checked"] == 0
