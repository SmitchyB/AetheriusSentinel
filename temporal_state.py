"""Temporal gating helpers for monitoring windows and async action waits.

This module is the **time-based gatekeeper** for the incident response playbook.
It does not run timers or background jobs itself; instead it answers questions
the UI and ``incident_scenarios`` ask on every render:

- Is an enhanced monitoring window still active for this incident?
- How much demo-time remains before monitoring-gated actions unlock?
- Which action keys should be blocked right now, and why?
- What ISO timestamp should we write to ``incidents.monitor_until`` when the user
  schedules ``prompt_offline_scan``?

**Prototype compression:** Real IR workflows might wait 24–48 hours. The demo
compresses that wait to a few minutes via ``PROTOTYPE_MONITOR_MINUTES`` so
reviewers can see the full lifecycle without leaving the app open overnight.

**Relationship to other modules:**

- ``action_catalog.py`` defines which actions exist; this module defines which
  subset is *temporarily* unavailable during monitoring.
- ``incident_scenarios.execute_incident_action`` sets ``monitor_until`` when
  ``prompt_offline_scan`` runs, using ``monitoring_gate_until_iso()``.
- ``incident_scenarios._process_expired_monitoring`` clears the gate and emits
  an ``UPDATE_TYPE_MONITORING_COMPLETE`` alert when ``is_monitoring_active``
  returns False.
- ``incident_scenarios.can_execute_action`` and ``get_blocked_actions`` consult
  this module before allowing trust / false-positive / documentation shortcuts.

**Update type constants** (also used when inserting ``incident_updates`` rows):

- ``UPDATE_TYPE_MONITORING_COMPLETE`` — watch window ended; user may proceed.
- ``UPDATE_TYPE_ASYNC_ACTION_COMPLETE`` — reserved for future async action flows.
- ``UPDATE_TYPE_INVESTIGATION_REFRESH`` — reserved for re-scan / refresh flows.
- ``UPDATE_TYPE_STATUS_CHANGE`` — reserved for status-driven notifications.
"""

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
    """Return compressed demo wait before monitoring-gated steps unlock.

    Reads ``PROTOTYPE_MONITOR_MINUTES`` from the environment (default ``3``).
    Values below 1 are clamped to 1 so the gate always has a positive duration.
    Used by ``monitoring_gate_until_iso()`` when persisting ``monitor_until``.
    """
    raw = os.getenv("PROTOTYPE_MONITOR_MINUTES", "3")
    try:
        return max(1, int(raw))
    except ValueError:
        return 3


def actions_blocked_during_monitoring() -> frozenset[str]:
    """Return the canonical frozenset of action keys blocked during active monitoring.

    Thin wrapper around ``MONITORING_BLOCKED_ACTIONS`` so callers do not import
    the constant directly — keeps the blocked set swappable for tests later.
    """
    return MONITORING_BLOCKED_ACTIONS


def parse_monitor_until(incident: dict | None) -> datetime | None:
    """Parse ``incident['monitor_until']`` into a naive local ``datetime``.

    Accepts SQLite-style ``YYYY-MM-DD HH:MM:SS``, ISO ``YYYY-MM-DDTHH:MM:SS``,
    or anything ``datetime.fromisoformat`` understands. Returns ``None`` when
    the incident is missing, the field is empty, or parsing fails — callers
    treat ``None`` as "no monitoring gate active".
    """
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
    """Return True while ``monitor_until`` is set and still in the future.

    This is the primary gate check used by ``get_playbook_phase`` (→ ``monitoring``
    phase), ``can_execute_action`` (blocks most user actions), and chat copy
    formatters that show waiting-state messages.
    """
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
    """Human-readable countdown for UI and chat (e.g. ``2m 05s`` or ``1h 3m``).

    Shown alongside the *narrative* watch length from ``get_monitoring_narrative_hours``
    so users understand both "we are watching for 36h" and "demo unlock in 2m".
    """
    seconds = monitoring_remaining_seconds(incident)
    if seconds <= 0:
        return "0:00"
    minutes, secs = divmod(seconds, 60)
    if minutes >= 60:
        hours, minutes = divmod(minutes, 60)
        return f"{hours}h {minutes}m"
    return f"{minutes}m {secs:02d}s"


def get_monitoring_narrative_hours(incident_id: int | None) -> int:
    """Read ``monitor_hours`` from the latest completed ``prompt_offline_scan`` payload.

    The *story* told to the user references this value (often 36h). It is
    independent of ``PROTOTYPE_MONITOR_MINUTES``, which only controls when
    buttons unlock in the prototype. Falls back to ``36`` when no scan action
    exists or the payload cannot be parsed.
    """
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
    """Return action keys blocked right now mapped to human-readable reasons.

    When monitoring is active, every key in ``MONITORING_BLOCKED_ACTIONS`` is
    blocked with a message that includes both narrative hours and demo remaining
    time. ``incident_scenarios.can_execute_action`` consults this dict first.
    Returns an empty dict when no temporal gates apply.
    """
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
    """Return ``monitor_until`` timestamp using compressed prototype minutes.

    Called from ``execute_incident_action`` when the user runs
    ``prompt_offline_scan``. Format matches SQLite seed convention:
    ``YYYY-MM-DD HH:MM:SS`` (naive local time).
    """
    from datetime import timedelta

    minutes = get_prototype_monitor_minutes()
    return (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
