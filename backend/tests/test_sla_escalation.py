from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from backend.services import sla_escalation_service as svc

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
