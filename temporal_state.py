"""Temporal gating helpers for monitoring windows and async action waits."""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# MONITORING_BLOCKED_ACTIONS — keys withheld until monitor_until expires
# ---------------------------------------------------------------------------
# These are "resolution / closure" steps that would be premature while we are
# still watching the device. The narrative still references the full watch
# window (e.g. 36h) via get_monitoring_narrative_hours(); only the *demo*
# unlock timer is compressed via PROTOTYPE_MONITOR_MINUTES.
MONITORING_BLOCKED_ACTIONS = frozenset({
    "trust_device",              # Would reverse containment before watch ends
    "mark_false_positive",       # Would close case before watch ends
    "generate_incident_report",  # Documentation before monitoring completes
    "skip_to_documentation",     # Skip shortcut also blocked during watch
})

# ---------------------------------------------------------------------------
# Incident-update type strings — stored on incident_updates.update_type
# ---------------------------------------------------------------------------
UPDATE_TYPE_MONITORING_COMPLETE = "monitoring_complete"
UPDATE_TYPE_ASYNC_ACTION_COMPLETE = "async_action_complete"
UPDATE_TYPE_INVESTIGATION_REFRESH = "investigation_refresh"
UPDATE_TYPE_STATUS_CHANGE = "status_change"


def get_prototype_monitor_minutes() -> int:
    """Return compressed demo wait before monitoring-gated steps unlock."""
    raw = os.getenv("PROTOTYPE_MONITOR_MINUTES", "3")
    try:
        return max(1, int(raw))
    except ValueError:
        return 3


def actions_blocked_during_monitoring() -> frozenset[str]:
    """Return the canonical frozenset of action keys blocked during active monitoring."""
    return MONITORING_BLOCKED_ACTIONS


def parse_monitor_until(incident: dict | None) -> datetime | None:
    """Parse ``incident['monitor_until']`` into a naive local ``datetime``."""
    if not incident:
        return None
    raw = incident.get("monitor_until")
    if not raw:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(str(raw), fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(str(raw))
    except ValueError:
        return None


def is_monitoring_active(incident: dict | None) -> bool:
    """Return True while ``monitor_until`` is set and still in the future."""
    until = parse_monitor_until(incident)
    if until is None:
        return False
    return until > datetime.now()


def monitoring_remaining_seconds(incident: dict | None) -> int:
    """Seconds until the monitoring gate expires; 0 if inactive or already past."""
    until = parse_monitor_until(incident)
    if until is None:
        return 0
    delta = (until - datetime.now()).total_seconds()
    return max(0, int(delta))


def format_monitoring_remaining(incident: dict | None) -> str:
    """Human-readable countdown for UI and chat (e.g. ``2m 05s`` or ``1h 3m``)."""
    seconds = monitoring_remaining_seconds(incident)
    if seconds <= 0:
        return "0:00"
    minutes, secs = divmod(seconds, 60)
    if minutes >= 60:
        hours, minutes = divmod(minutes, 60)
        return f"{hours}h {minutes}m"
    return f"{minutes}m {secs:02d}s"


def get_monitoring_narrative_hours(incident_id: int | None) -> int:
    """Read ``monitor_hours`` from the latest completed ``prompt_offline_scan`` payload."""
    if not incident_id:
        return 36
    import db

    # Walk actions newest-first — the most recent offline scan defines the window.
    for action in reversed(db.get_incident_actions_list(incident_id)):
        if action.get("action_key") != "prompt_offline_scan":
            continue
        raw = action.get("payload_json")
        if not raw:
            return 36
        try:
            payload = json.loads(raw)
            return int(payload.get("monitor_hours", 36))
        except (json.JSONDecodeError, TypeError, ValueError):
            return 36
    return 36


def get_blocked_actions(incident: dict | None, *, incident_id: int | None = None) -> dict[str, str]:
    """Return action keys blocked right now mapped to human-readable reasons."""
    blocked: dict[str, str] = {}
    if not incident:
        return blocked

    if is_monitoring_active(incident):
        hours = get_monitoring_narrative_hours(incident_id or incident.get("incident_id"))
        remaining = format_monitoring_remaining(incident)
        reason = (
            f"Enhanced monitoring in progress ({hours}h watch window; "
            f"demo unlock in {remaining})"
        )
        for key in MONITORING_BLOCKED_ACTIONS:
            blocked[key] = reason
    return blocked


def monitoring_gate_until_iso() -> str:
    """Return ``monitor_until`` timestamp using compressed prototype minutes."""
    from datetime import timedelta

    minutes = get_prototype_monitor_minutes()
    return (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
