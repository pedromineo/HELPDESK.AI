"""Periodic SLA breach auto-escalation & deduplicated notification worker."""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

ACTIVE_STATUSES = ["open", "in_progress", "pending"]
ESCALATION_THRESHOLD_MINUTES = 60
RISK_THRESHOLD = 0.80
PRIORITY_LADDER = {"low": "medium", "medium": "high", "high": "urgent"}

# (ticket_id, target_priority) pairs already alerted; at most one alert per threshold.
_ALERTED: set = set()
_ALERT_LOCK = threading.Lock()


def reset_alert_cache() -> None:
    with _ALERT_LOCK:
        _ALERTED.clear()


def parse_breach_time(value) -> datetime | None:
    if not value:
        return None
    try:
        if isinstance(value, datetime):
            dt = value
        else:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def minutes_to_breach(sla_breach_at, now: datetime | None = None) -> float | None:
    deadline = parse_breach_time(sla_breach_at)
    if deadline is None:
        return None
    now = now or datetime.now(timezone.utc)
    return (deadline - now).total_seconds() / 60.0


def next_priority(priority) -> str | None:
    return PRIORITY_LADDER.get(str(priority or "").strip().lower())


def should_escalate(ticket: dict, now: datetime | None = None, risk_score: float | None = None) -> bool:
    """True when under 60 minutes to breach (or overdue), or risk >= 0.80."""
    if next_priority(ticket.get("priority")) is None:
        return False
    remaining = minutes_to_breach(ticket.get("sla_breach_at"), now)
    if remaining is not None and remaining < ESCALATION_THRESHOLD_MINUTES:
        return True
    if risk_score is not None:
        normalized = risk_score / 100.0 if risk_score > 1 else risk_score
        return normalized >= RISK_THRESHOLD
    return False


def _claim_alert(ticket_id, target_priority) -> bool:
    key = (str(ticket_id), target_priority)
    with _ALERT_LOCK:
        if key in _ALERTED:
            return False
        _ALERTED.add(key)
        return True


def _record_audit(supabase, ticket: dict, old_p: str, new_p: str) -> None:
    try:
        supabase.table("audit_logs").insert({
            "ticket_id": ticket.get("id"),
            "company_id": ticket.get("company_id"),
            "action": "sla_auto_escalation",
            "old_value": old_p,
            "new_value": new_p,
        }).execute()
    except Exception as exc:
        logger.warning("SLA audit log failed for %s: %s", ticket.get("id"), exc)


def _dispatch(ticket: dict, new_p: str, deadline: datetime | None) -> None:
    from backend.sla_notifier import send_webhook

    send_webhook({
        "type": "sla_auto_escalation",
        "ticket_id": ticket.get("ticket_id") or ticket.get("id"),
        "subject": ticket.get("subject"),
        "priority": new_p,
        "deadline": deadline.isoformat() if deadline else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    _dispatch_slack(ticket, deadline)


def _dispatch_slack(ticket: dict, deadline: datetime | None) -> None:
    try:
        from backend.sla_checker import dispatch_slack_alert

        dispatch_slack_alert(
            str(ticket.get("ticket_id") or ticket.get("id")),
            ticket.get("subject") or "",
            ticket.get("category") or "",
            str(ticket.get("assigned_to") or ""),
            deadline or datetime.now(timezone.utc),
        )
    except Exception as exc:
        logger.warning("Slack dispatch failed: %s", exc)


def run_sla_sweep(supabase, now: datetime | None = None, batch_size: int = 500) -> dict:
    """Sweep active tickets, escalate priority, and send deduplicated alerts."""
    summary = {"checked": 0, "escalated": 0, "notified": 0, "skipped": 0, "errors": 0}
    if not supabase:
        return summary
    try:
        res = (
            supabase.table("tickets")
            .select("id,ticket_id,subject,priority,status,sla_breach_at,category,company_id,assigned_to")
            .in_("status", ACTIVE_STATUSES)
            .limit(batch_size)
            .execute()
        )
    except Exception as exc:
        logger.error("SLA sweep query failed: %s", exc)
        summary["errors"] += 1
        return summary

    for ticket in res.data or []:
        summary["checked"] += 1
        if not should_escalate(ticket, now):
            summary["skipped"] += 1
            continue
        old_p = str(ticket.get("priority")).strip().lower()
        new_p = next_priority(old_p)
        try:
            supabase.table("tickets").update({"priority": new_p}).eq("id", ticket["id"]).execute()
        except Exception as exc:
            logger.error("SLA escalation update failed for %s: %s", ticket.get("id"), exc)
            summary["errors"] += 1
            continue
        summary["escalated"] += 1
        _record_audit(supabase, ticket, old_p, new_p)
        if _claim_alert(ticket.get("id"), new_p):
            try:
                _dispatch(ticket, new_p, parse_breach_time(ticket.get("sla_breach_at")))
                summary["notified"] += 1
            except Exception as exc:
                logger.warning("SLA alert failed for %s: %s", ticket.get("id"), exc)
    return summary
