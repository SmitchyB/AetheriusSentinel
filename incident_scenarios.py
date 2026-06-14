"""Incident scenarios, playbook flow, and action execution.

This module is the core playbook/scenario engine for the Aetherius Sentinel
Streamlit prototype. It owns:

- Static incident scenario definitions (titles, severities, narrative copy)
- Scan-to-incident mapping and rotation logic
- Streamlit session-state initialization for active incidents
- Playbook phase computation (awaiting ack → containment → eradication → post-incident)
- Gating rules for which response actions may run in each phase
- Acknowledge and execute flows that persist actions to SQLite via ``db``
- Chat UX helpers (open thread, prior-session bootstrap, action buttons)
- Scan trigger that creates DB incidents and seeds the chat narrative
- Plain-language and expert-mode narrative formatters for scan results

Downstream consumers: ``app.py``, ``sentinel_actions.py``, expert/standard UI pages.
Action metadata and templates live in ``action_catalog.py``.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta

import streamlit as st

import db
from action_catalog import (
    ACTIONS,
    CONTAINMENT_KEYS,
    ERADICATION_KEYS,
    POST_INCIDENT_KEYS,
    build_recommended_playbook,
    format_action_result,
    format_plain_action_result,
    get_action,
    get_draft_payload,
    get_scenario_step_prompt,
    normalize_action_key,
    playbook_recommendation_text,
    recommended_steps_in_category,
    scenario_key_for_title,
)

# ---------------------------------------------------------------------------
# INCIDENTS — static scenario catalog keyed by internal scenario id
# ---------------------------------------------------------------------------
# Each entry supplies default UI copy when a DB row is hydrated via
# ``build_active_incident_from_db``. DB fields (status, device_name, etc.)
# override these defaults at runtime.
INCIDENTS = {
    "exfiltration": {
        "title": "Exfiltration",
        "subtitle": "Data Theft",
        "severity": "Critical",
        "source": "Brett's Workstation",
        "source_mac": "A4:83:E7:12:9F:3C",
        "indicator": "185.199.108.153",
        "description": (
            "Large outbound data transfer detected from a trusted workstation to an "
            "unknown external endpoint. Traffic pattern matches staged exfiltration."
        ),
    },
    "low_risk_anomaly": {
        "title": "Low-Risk Anomaly",
        "subtitle": "Unknown Device",
        "severity": "Low",
        "source": "Guest-IoT-7A2F",
        "indicator": "192.168.1.44",
        "description": (
            "An unrecognized device joined the network and is probing local services "
            "at low frequency. No confirmed malicious behavior yet."
        ),
    },
    "brute_force": {
        "title": "Brute Force",
        "subtitle": "Targeted Attack",
        "severity": "High",
        "source": "Front Door Smart Lock",
        "indicator": "203.0.113.88",
        "description": (
            "Repeated failed authentication attempts detected against a smart lock from "
            "a known hostile subnet. Lockout threshold nearly reached."
        ),
    },
    "lateral_scanning": {
        "title": "Lateral Scanning",
        "subtitle": "Internal Worm",
        "severity": "High",
        "source": "Living Room Roku",
        "source_mac": "B8:27:EB:4D:61:A2",
        "indicator": "192.168.1.15",
        "description": (
            "Internal host is scanning adjacent subnets on multiple ports, consistent "
            "with worm-like lateral movement behavior."
        ),
    },
    "ransomware_beacon": {
        "title": "Ransomware Staging",
        "subtitle": "Encryption Prep",
        "severity": "Critical",
        "source": "Brett's Workstation",
        "source_mac": "AA:BB:CC:DD:EE:FF",
        "indicator": "45.33.32.156",
        "description": (
            "Encrypted outbound bursts and shadow-copy deletion activity detected on a "
            "trusted workstation. Pattern matches pre-encryption ransomware staging."
        ),
    },
    "command_and_control": {
        "title": "Command and Control",
        "subtitle": "C2 Beacon",
        "severity": "Critical",
        "source": "Main Home Gateway",
        "source_mac": "00:1A:2B:3C:4D:5E",
        "indicator": "198.18.0.77",
        "description": (
            "Recurring DNS and HTTPS beacons from the home gateway to a known command-and-control "
            "infrastructure. Sustained callback interval suggests active remote control."
        ),
    },
}

# ---------------------------------------------------------------------------
# Scan pool — maps scan button keys to rotatable scenario subsets
# ---------------------------------------------------------------------------
# ``ai_threat_sweep`` and ``active_connections`` each draw from a different
# pool so repeated scans feel varied without exposing every scenario at once.
SCAN_INCIDENT_POOL = {
    "ai_threat_sweep": ["exfiltration", "low_risk_anomaly", "ransomware_beacon"],
    "active_connections": ["brute_force", "lateral_scanning", "command_and_control"],
}

# Human-readable labels for scan buttons in the UI.
SCAN_LABELS = {
    "ai_threat_sweep": "Run AI Threat Sweep",
    "active_connections": "Scan Active Connections",
}

# CSS severity token names used by dashboard badges.
SEVERITY_COLORS = {
    "Critical": "critical",
    "High": "high",
    "Low": "low",
}

# Links each scenario key to a ``devices.device_id`` row for realistic DB seeding.
SCENARIO_DEVICE_MAP = {
    "exfiltration": 2,
    "low_risk_anomaly": 6,
    "brute_force": 4,
    "lateral_scanning": 3,
    "ransomware_beacon": 2,
    "command_and_control": 1,
}

# Chat-only actions shown before playbook bootstrap on returning incidents.
PRIOR_SESSION_ACTIONS = {"summarize_past_sessions", "where_we_left_off"}

# Synthetic action key for the acknowledge step (not in ACTIONS catalog).
ACKNOWLEDGE_ACTION = "acknowledge_alert"

# Incident statuses that mean the response playbook is finished.
TERMINAL_STATUSES = {"Mitigated", "False Positive", "Trusted"}

# Statuses where the incident is still actionable (not closed).
OPEN_STATUSES = {"Active", "Investigating"}


def is_terminal_status(status: str) -> bool:
    """Return True when ``status`` is a closed/resolved terminal state."""
    return status in TERMINAL_STATUSES


def is_incident_open(incident: dict) -> bool:
    """Return True when the incident is still in an open workflow status."""
    return incident.get("status", "Active") in OPEN_STATUSES


def can_show_start_investigation(incident: dict) -> bool:
    """Show only for fresh alerts that have not entered investigation yet."""
    return incident.get("status") == "Active"


def can_show_open_analyst_chat(incident: dict) -> bool:
    """Analyst chat is available while the incident is still open (not closed)."""
    return is_incident_open(incident) and not is_terminal_status(incident.get("status", ""))


def can_start_new_incident_conversation(incident: dict) -> bool:
    """Standard dashboard — new Sentinel threads only for open incidents."""
    return is_incident_open(incident) and not is_terminal_status(incident.get("status", ""))


def can_show_acknowledge(incident_id: int, incident: dict) -> bool:
    """Acknowledge button visible only for unacknowledged open incidents."""
    return is_incident_open(incident) and not db.is_incident_acknowledged(incident_id)


# ---------------------------------------------------------------------------
# State init — Streamlit session keys for incident/playbook UX
# ---------------------------------------------------------------------------
def init_incident_state():
    """Ensure all incident-related session keys exist with safe defaults."""
    if "active_incident" not in st.session_state:
        st.session_state.active_incident = None
    if "scan_rotation" not in st.session_state:
        # Round-robin index per scan type when random mode is off.
        st.session_state.scan_rotation = {
            "ai_threat_sweep": 0,
            "active_connections": 0,
        }
    if "scan_mode_random" not in st.session_state:
        st.session_state.scan_mode_random = True
    if "awaiting_playbook_bootstrap" not in st.session_state:
        # True while user picks summarize vs. resume on a returning incident.
        st.session_state.awaiting_playbook_bootstrap = False
    if "playbook_phase" not in st.session_state:
        st.session_state.playbook_phase = "awaiting_ack"
    if "recommended_action_keys" not in st.session_state:
        st.session_state.recommended_action_keys = []
    if "recommended_action_incident_id" not in st.session_state:
        st.session_state.recommended_action_incident_id = None


def is_expert_mode() -> bool:
    """Return True when the expert dashboard mode flag is set."""
    return bool(st.session_state.get("expert_mode"))


def build_active_incident_from_db(db_row: dict) -> dict:
    """Merge a SQLite incident row with static scenario metadata from INCIDENTS."""
    scenario_key = scenario_key_for_title(db_row["title"])
    incident = INCIDENTS[scenario_key].copy()
    incident["key"] = scenario_key
    incident["incident_id"] = db_row["incident_id"]
    incident["title"] = db_row["title"]
    incident["severity"] = db_row["severity"]
    incident["status"] = db_row["status"]
    incident["device_name"] = db_row["device_name"]
    incident["device_type"] = db_row.get("device_type")
    incident["internal_ip"] = db_row.get("internal_ip")
    incident["owner_name"] = db_row.get("owner_name")
    incident["source"] = db_row["device_name"]
    incident["acknowledged_at"] = db_row.get("acknowledged_at")
    incident["monitor_until"] = db_row.get("monitor_until")
    incident["authority_recommended"] = bool(db_row.get("authority_recommended"))
    if db_row.get("mac_address"):
        incident["source_mac"] = db_row["mac_address"]
    indicator = db_row.get("primary_indicator") or db_row.get("internal_ip")
    if indicator:
        incident["indicator"] = indicator
    return incident


def get_active_incident():
    """Return the in-memory active incident dict, or None."""
    return st.session_state.get("active_incident")


def clear_active_incident():
    """Reset active incident and playbook session keys."""
    st.session_state.active_incident = None
    st.session_state.playbook_phase = "awaiting_ack"
    st.session_state.recommended_action_keys = []
    st.session_state.recommended_action_incident_id = None


def _load_recommended_action_keys_from_db(incident_id: int) -> list[str]:
    """Read the active playbook action list from SQLite."""
    rec = db.get_active_playbook_recommendation(incident_id)
    if rec and rec.get("playbook_actions_json"):
        try:
            return json.loads(rec["playbook_actions_json"])
        except json.JSONDecodeError:
            pass
    return []


def get_recommended_action_keys(incident_id: int | None = None) -> list[str]:
    """Resolve recommended playbook steps from incident-scoped cache or DB."""
    incident_id = incident_id or st.session_state.get("active_incident_id")
    cached_id = st.session_state.get("recommended_action_incident_id")
    cached_keys = st.session_state.get("recommended_action_keys")
    if incident_id and cached_id == incident_id and cached_keys is not None:
        return list(cached_keys)
    if incident_id:
        return _load_recommended_action_keys_from_db(incident_id)
    return list(cached_keys) if cached_keys else []


def sync_recommended_actions_from_db(incident_id: int):
    """Refresh session cache of recommended action keys from the database."""
    keys = _load_recommended_action_keys_from_db(incident_id)
    st.session_state.recommended_action_keys = keys
    st.session_state.recommended_action_incident_id = incident_id


def _incident_completed_action_keys(incident_id: int | None) -> set[str]:
    return db.get_incident_action_keys_completed(incident_id) if incident_id else set()


def is_playbook_complete(incident: dict) -> bool:
    """Return True when every recommended playbook step has been completed."""
    incident_id = incident.get("incident_id")
    recommended = get_recommended_action_keys(incident_id)
    if not recommended:
        return False
    completed = _incident_completed_action_keys(incident_id)
    return all(k in completed for k in recommended)


def get_next_recommended_step(
    incident: dict,
    *,
    require_executable: bool = False,
) -> str | None:
    """Return the next incomplete playbook step, optionally gated by can_execute_action."""
    incident_id = incident.get("incident_id")
    recommended = get_recommended_action_keys(incident_id)
    completed = _incident_completed_action_keys(incident_id)
    for key in recommended:
        if key in completed:
            continue
        if require_executable and not can_execute_action(key, incident):
            continue
        return key
    return None


def get_next_executable_recommended_step(incident: dict) -> str | None:
    """Return the next recommended step the user is allowed to run right now."""
    return get_next_recommended_step(incident, require_executable=True)


def _scenario_key_for_incident(incident: dict) -> str:
    return incident.get("key") or scenario_key_for_title(incident.get("title", ""))


# ---------------------------------------------------------------------------
# Playbook phase — derive current response stage from DB + session state
# ---------------------------------------------------------------------------
def get_playbook_phase(incident: dict | None = None) -> str:
    """Return the current playbook phase string for gating UI and actions.

    Phase progression follows the incident's recommended playbook order:
        closed → awaiting_ack → containment → eradication → post_incident → closed

    Returns one of: ``closed``, ``awaiting_ack``, ``containment``,
    ``eradication``, ``post_incident``.
    """
    incident = incident or get_active_incident()
    if not incident:
        return "closed"

    incident_id = incident.get("incident_id")
    status = incident.get("status", "Active")

    if status in TERMINAL_STATUSES:
        return "closed"

    if incident_id and not db.is_incident_acknowledged(incident_id):
        return "awaiting_ack"

    recommended = get_recommended_action_keys(incident_id)
    if not recommended:
        return "closed"

    completed = _incident_completed_action_keys(incident_id)
    rec_containment = recommended_steps_in_category(recommended, CONTAINMENT_KEYS)
    rec_eradication = recommended_steps_in_category(recommended, ERADICATION_KEYS)
    rec_post = recommended_steps_in_category(recommended, POST_INCIDENT_KEYS)

    if any(k not in completed for k in rec_containment):
        return "containment"
    if any(k not in completed for k in rec_eradication):
        return "eradication"
    if any(k not in completed for k in rec_post):
        return "post_incident"

    if all(k in completed for k in recommended):
        return "closed"

    if incident.get("authority_recommended") or incident_id and _db_authority_recommended(incident_id):
        if not any(k in completed for k in POST_INCIDENT_KEYS):
            return "post_incident"

    return "closed"


def _db_authority_recommended(incident_id: int) -> bool:
    """Re-fetch authority_recommended from DB (session copy may be stale)."""
    row = db.get_incident_by_id(incident_id)
    return bool(row and row.get("authority_recommended"))


def can_execute_action(action_key: str, incident: dict) -> bool:
    """Return True if ``action_key`` is allowed for ``incident`` right now.

    Gating rules:
    - Already-completed actions are never re-run.
    - Terminal incidents only allow post_incident category actions.
    - Investigation actions are never user-triggered (auto-run on create).
    - Category must match the current playbook phase derived from recommendations.
    - Expert palette: any action in the active phase category; recommended steps
      in later categories remain blocked until their phase begins.
    """
    action_key = normalize_action_key(action_key)
    action = get_action(action_key)
    if not action:
        return False

    incident_id = incident.get("incident_id")
    status = incident.get("status", "Active")

    if incident_id and action_key in db.get_incident_action_keys_completed(incident_id):
        return False

    if is_terminal_status(status):
        return action["category"] == "post_incident"

    phase = get_playbook_phase(incident)
    category = action["category"]

    if phase == "awaiting_ack":
        return False
    if phase == "closed":
        if category == "post_incident" and (
            incident.get("authority_recommended")
            or (incident_id and _db_authority_recommended(incident_id))
        ):
            return True
        return False
    if category == "investigation":
        return False

    if phase == "containment":
        return category == "containment"
    if phase == "eradication":
        return category in ("containment", "eradication")
    if phase == "post_incident":
        return category in ("containment", "eradication", "post_incident")

    return False


# ---------------------------------------------------------------------------
# Acknowledge / execute actions — persist playbook steps to the database
# ---------------------------------------------------------------------------
def acknowledge_incident_flow(incident_id: int) -> bool:
    """Acknowledge alert, generate playbook if missing, refresh session state."""
    incident_row = db.get_incident_by_id(incident_id)
    if not incident_row:
        return False

    incident = build_active_incident_from_db(incident_row)
    if not db.is_incident_acknowledged(incident_id):
        db.acknowledge_incident(incident_id)

    # First acknowledgment creates the recommended playbook row.
    existing = db.get_active_playbook_recommendation(incident_id)
    if not existing:
        action_keys, authority = build_recommended_playbook(incident)
        text = playbook_recommendation_text(incident, action_keys)
        db.insert_playbook_recommendation(incident_id, text, action_keys)
        if authority:
            db.update_incident_status(incident_id, "Investigating", authority_recommended=1)
            db.insert_recommendation(
                incident_id,
                "Critical incident — consider notifying law enforcement after containment and resolution.",
                recommendation_type="authority_notice",
                display_order=3,
            )

    incident_row = db.get_incident_by_id(incident_id)
    st.session_state.active_incident = build_active_incident_from_db(incident_row)
    st.session_state.active_incident_id = incident_id
    sync_recommended_actions_from_db(incident_id)
    st.session_state.playbook_phase = get_playbook_phase(st.session_state.active_incident)
    st.session_state.awaiting_playbook_bootstrap = False
    return True


def execute_incident_action(
    incident_id: int,
    action_key: str,
    payload: dict | None = None,
    *,
    source: str = "expert",
) -> tuple[bool, str]:
    """Run a response action: validate, format result, persist, update status.

    Returns ``(success, message)`` where message is the human-readable result
    or an error explanation.
    """
    action_key = normalize_action_key(action_key)
    incident_row = db.get_incident_by_id(incident_id)
    if not incident_row:
        return False, "Incident not found."

    incident = build_active_incident_from_db(incident_row)
    action = get_action(action_key)
    if not action:
        return False, f"Unknown action: {action_key}"

    if not can_execute_action(action_key, incident):
        return False, f"{action['label']} is not available for this incident right now."

    if incident_id and action_key in db.get_incident_action_keys_completed(incident_id):
        return False, f"{action['label']} was already completed for this incident."

    payload = payload or get_draft_payload(action_key, incident)
    result = format_action_result(action_key, incident, payload)

    recommended = get_recommended_action_keys(incident_id)
    playbook_order = None
    is_recommended = 0
    if action_key in recommended:
        is_recommended = 1
        playbook_order = recommended.index(action_key) + 1

    db.insert_incident_action(
        incident_id,
        action_key,
        action["category"],
        result,
        payload=payload,
        is_recommended=is_recommended,
        playbook_order=playbook_order,
    )

    # Resolution actions (trust, false positive, mitigated) update incident status.
    resolution = action.get("resolution_status")
    if resolution:
        kwargs = {}
        if action_key == "prompt_offline_scan":
            # Monitoring window keeps incident in Investigating, not terminal.
            hours = int(payload.get("monitor_hours", 36))
            monitor_until = (datetime.now() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
            kwargs["monitor_until"] = monitor_until
            db.update_incident_status(incident_id, "Investigating", **kwargs)
        else:
            db.update_incident_status(incident_id, resolution, **kwargs)
    elif action_key in CONTAINMENT_KEYS and incident_row.get("status") == "Active":
        # First containment step moves Active → Investigating.
        db.update_incident_status(incident_id, "Investigating")

    updated = db.get_incident_by_id(incident_id)
    if updated and st.session_state.get("active_incident_id") == incident_id:
        st.session_state.active_incident = build_active_incident_from_db(updated)

    st.session_state.playbook_phase = get_playbook_phase(st.session_state.get("active_incident"))

    # When all recommended steps are done on a critical incident, nudge authority notice.
    completed = db.get_incident_action_keys_completed(incident_id)
    rec = recommended or []
    if rec and all(k in completed for k in rec):
        row = db.get_incident_by_id(incident_id)
        if row and row.get("authority_recommended"):
            existing_notice = [
                r for r in db.get_recommendations_for_incident(incident_id)
                if r["recommendation_type"] == "authority_notice"
            ]
            if not existing_notice:
                db.insert_recommendation(
                    incident_id,
                    "Playbook complete — post-incident documentation and authority notification recommended.",
                    recommendation_type="authority_notice",
                    display_order=4,
                )

    return True, result


# ---------------------------------------------------------------------------
# Narrative formatters — assistant copy for acknowledge, playbook, chat prompts
# ---------------------------------------------------------------------------
def format_acknowledge_prompt(incident: dict) -> str:
    """Plain-language prompt asking user to acknowledge before playbook."""
    return (
        f"**{incident['title']}** detected on **{incident.get('device_name', incident.get('source'))}** "
        f"({incident['severity']} severity).\n\n"
        "Automated investigation (fingerprint + ping sweep) has already run. "
        "Acknowledge this alert to receive your recommended response playbook."
    )


def format_playbook_brief(incident: dict, action_keys: list[str]) -> str:
    """Numbered list of recommended steps with expert labels and hints."""
    lines = [
        playbook_recommendation_text(incident, action_keys),
        "",
        "**Recommended steps:**",
    ]
    for index, key in enumerate(action_keys, start=1):
        action = get_action(key)
        if action:
            lines.append(f"{index}. **{action['label']}** — _{action['hint']}_")
    lines.append("")
    lines.append(
        "I'll unlock each step in order as we go. Use the button below when you're ready for the next one."
    )
    return "\n".join(lines)


def format_chat_action_prompt(incident: dict) -> str:
    """Short nudge text for the next chat action button row."""
    incident_id = incident.get("incident_id")
    phase = get_playbook_phase(incident)

    if phase == "closed" or is_playbook_complete(incident):
        return format_playbook_complete_message(incident)

    next_key = get_next_executable_recommended_step(incident)
    if next_key:
        scenario_key = _scenario_key_for_incident(incident)
        custom = get_scenario_step_prompt(scenario_key, next_key)
        if custom:
            return custom
        action = get_action(next_key)
        label = action.get("plain_label", action["label"]) if action else next_key
        return f"Next recommended step: I can **{label.lower()}**. Should I go ahead?"

    if phase == "post_incident":
        return "Response steps are done. Post-incident documentation actions are available if needed."

    return "Review the recommended playbook on the incident page when you're ready to continue."


def format_playbook_complete_message(incident: dict) -> str:
    """Assistant copy when all recommended playbook steps are finished."""
    status = incident.get("status", "Unknown")
    if incident.get("monitor_until"):
        return (
            f"Recommended response playbook complete. I'm monitoring **{incident.get('device_name', incident.get('source', 'the device'))}** "
            f"until **{incident['monitor_until']}**. Post-incident documentation is available on the incident page if needed."
        )
    if incident.get("authority_recommended"):
        return (
            f"Recommended response playbook complete (status: **{status}**). "
            "Consider preserving evidence and preparing materials for law enforcement on the incident page."
        )
    if is_terminal_status(status):
        return f"Response playbook complete. Incident status: **{status}**."
    return (
        f"Recommended response playbook complete (status: **{status}**). "
        "Post-incident documentation is available on the incident page if you need it."
    )


def _action_to_chat_button(action_key: str, primary: bool = False) -> dict:
    """Build a chat action button dict (key, plain label, primary/secondary type)."""
    action = get_action(action_key)
    if not action:
        return {"key": action_key, "label": action_key, "type": "secondary"}
    return {
        "key": action_key,
        "label": action.get("plain_label", action["label"]),
        "type": "primary" if primary else "secondary",
    }


def get_chat_actions_for_incident(incident: dict, *, guided: bool | None = None) -> list[dict]:
    """Return chat action buttons appropriate for the current playbook state.

    Standard mode uses guided flow (next recommended step only). Expert mode may
    request the full phase-appropriate pool via ``guided=False``.
    """
    if guided is None:
        guided = not is_expert_mode()

    incident_id = incident.get("incident_id")
    if incident_id and not db.is_incident_acknowledged(incident_id):
        if is_terminal_status(incident.get("status", "")):
            return []
        return [{"key": ACKNOWLEDGE_ACTION, "label": "Acknowledge alert", "type": "primary"}]

    if is_terminal_status(incident.get("status", "")):
        completed = _incident_completed_action_keys(incident_id)
        actions = []
        for key in POST_INCIDENT_KEYS:
            if key not in completed and can_execute_action(key, incident):
                actions.append(_action_to_chat_button(key))
        return actions[:4]

    if is_playbook_complete(incident) or get_playbook_phase(incident) == "closed":
        return []

    next_key = get_next_executable_recommended_step(incident)
    if not next_key:
        return []

    if guided:
        return [_action_to_chat_button(next_key, primary=True)]

    recommended = get_recommended_action_keys(incident_id)
    completed = _incident_completed_action_keys(incident_id)
    actions = [_action_to_chat_button(next_key, primary=True)]
    phase = get_playbook_phase(incident)
    pool: list[str] = []
    if phase == "containment":
        pool = recommended_steps_in_category(recommended, CONTAINMENT_KEYS)
    elif phase == "eradication":
        pool = recommended_steps_in_category(recommended, ERADICATION_KEYS)
    elif phase == "post_incident":
        pool = recommended_steps_in_category(recommended, POST_INCIDENT_KEYS)

    for key in pool:
        if key != next_key and key not in completed and can_execute_action(key, incident):
            actions.append(_action_to_chat_button(key))

    return actions[:4]


def _prior_session_actions() -> list:
    """Button definitions for returning-incident bootstrap (summarize vs resume)."""
    return [
        {"key": "summarize_past_sessions", "label": "Summarize past sessions", "type": "secondary"},
        {"key": "where_we_left_off", "label": "Where we left off", "type": "primary"},
    ]


def format_prior_sessions_prompt(prior_count: int) -> str:
    """Ask user how to catch up when prior chat sessions exist."""
    session_word = "session" if prior_count == 1 else "sessions"
    return (
        f"There are **{prior_count}** previous {session_word} for this incident. "
        "Would you like me to **summarize them** or tell you **where we left off**?"
    )


def format_summarize_past_sessions(incident_id: int, incident_title: str) -> str:
    """Bullet summary of each prior session's user actions."""
    sessions = db.get_sessions_for_incident(incident_id)
    if not sessions:
        return "I could not find any prior sessions to summarize."

    lines = [f"Here is a quick summary of past conversations about **{incident_title}**:\n"]
    for index, session in enumerate(sessions, start=1):
        messages = db.get_messages_for_session(session["session_id"])
        user_actions = [m["content"] for m in messages if m["role"] == "user"]
        action_summary = ", ".join(user_actions[:2]) if user_actions else "No actions taken yet"
        lines.append(f"- **Session {index}** ({session['started_at']}): {action_summary}")
    lines.append("\nAcknowledge the alert when you are ready for the response playbook.")
    return "\n".join(lines)


def format_where_we_left_off(incident_id: int, incident: dict) -> str:
    """Recap last assistant message plus next recommended playbook step."""
    sessions = db.get_sessions_for_incident(incident_id)
    if not sessions:
        return "I could not find a prior session to resume from."

    latest_session = sessions[0]
    messages = db.get_messages_for_session(latest_session["session_id"])
    last_assistant = next(
        (m["content"] for m in reversed(messages) if m["role"] == "assistant"),
        None,
    )
    status = incident.get("status", "Unknown")
    recap = last_assistant or "We had started looking at this incident."

    next_step = ""
    completed = _incident_completed_action_keys(incident_id)
    next_key = get_next_executable_recommended_step(incident)
    if next_key:
        action = get_action(next_key)
        if action:
            scenario_key = _scenario_key_for_incident(incident)
            custom = get_scenario_step_prompt(scenario_key, next_key)
            if custom:
                next_step = f"\n\n{custom}"
            else:
                next_step = (
                    f"\n\n**Next recommended step:** {action['plain_label']} — "
                    f"_{action['plain_hint']}_"
                )
    elif is_playbook_complete(incident):
        next_step = f"\n\n{format_playbook_complete_message(incident)}"

    if db.is_incident_acknowledged(incident_id):
        footer = "You can continue the response playbook when ready."
    else:
        footer = "Acknowledge the alert when you are ready to continue the response."

    return (
        f"Here is where we left off (status: **{status}**):\n\n"
        f"{recap}{next_step}\n\n"
        f"{footer}"
    )


# ---------------------------------------------------------------------------
# Chat flow — open threads, handle button actions, expert draft/deploy
# ---------------------------------------------------------------------------
def open_incident_chat(incident_id: int):
    """Start a new chat session for a DB incident."""
    from sentinel_actions import append_message

    db_row = db.get_incident_by_id(incident_id)
    if not db_row:
        return

    incident = build_active_incident_from_db(db_row)
    session_id = db.create_session_id()
    prior_count = db.count_sessions_for_incident(incident_id)

    st.session_state.active_session_id = session_id
    st.session_state.active_incident_id = incident_id
    st.session_state.active_incident = incident
    st.session_state.messages = []
    sync_recommended_actions_from_db(incident_id)
    st.session_state.playbook_phase = get_playbook_phase(incident)

    if prior_count > 0:
        # Returning incident: offer summarize/resume before playbook.
        st.session_state.awaiting_playbook_bootstrap = True
        append_message(
            "assistant",
            format_prior_sessions_prompt(prior_count),
            actions=_prior_session_actions(),
            persist=False,
        )
        return

    st.session_state.awaiting_playbook_bootstrap = False
    if db.is_incident_acknowledged(incident_id):
        action_keys = get_recommended_action_keys(incident_id)
        append_message("assistant", format_playbook_brief(incident, action_keys), persist=False)
        append_message(
            "assistant",
            format_chat_action_prompt(incident),
            actions=get_chat_actions_for_incident(incident),
            persist=False,
        )
    else:
        append_message(
            "assistant",
            format_acknowledge_prompt(incident),
            actions=[{"key": ACKNOWLEDGE_ACTION, "label": "Acknowledge alert", "type": "primary"}],
            persist=False,
        )


def handle_prior_session_action(action_key: str, message_index: int) -> bool:
    """Handle summarize/resume bootstrap; then show playbook or acknowledge."""
    from sentinel_actions import append_message, append_user_choice, consume_message_actions

    if action_key not in PRIOR_SESSION_ACTIONS:
        return False

    incident = get_active_incident()
    if not incident or not st.session_state.get("awaiting_playbook_bootstrap"):
        return False

    incident_id = incident.get("incident_id")
    if not incident_id:
        return False

    consume_message_actions(message_index)
    if action_key == "summarize_past_sessions":
        append_user_choice("Summarize past sessions")
        append_message("assistant", format_summarize_past_sessions(incident_id, incident["title"]))
    else:
        append_user_choice("Where we left off")
        append_message("assistant", format_where_we_left_off(incident_id, incident))

    st.session_state.awaiting_playbook_bootstrap = False
    if db.is_incident_acknowledged(incident_id):
        action_keys = get_recommended_action_keys(incident_id)
        append_message("assistant", format_playbook_brief(incident, action_keys), persist=False)
        append_message(
            "assistant",
            format_chat_action_prompt(incident),
            actions=get_chat_actions_for_incident(incident),
            persist=False,
        )
    else:
        append_message(
            "assistant",
            format_acknowledge_prompt(incident),
            actions=[{"key": ACKNOWLEDGE_ACTION, "label": "Acknowledge alert", "type": "primary"}],
            persist=False,
        )
    return True


def handle_acknowledge_action(message_index: int) -> bool:
    """Chat button handler for acknowledge_alert."""
    from sentinel_actions import append_message, append_user_choice, consume_message_actions

    incident = get_active_incident()
    if not incident or not incident.get("incident_id"):
        return False

    consume_message_actions(message_index)
    append_user_choice("Acknowledge alert")
    acknowledge_incident_flow(incident["incident_id"])
    incident = get_active_incident()
    action_keys = get_recommended_action_keys(incident["incident_id"])
    append_message("assistant", format_playbook_brief(incident, action_keys))
    append_message(
        "assistant",
        format_chat_action_prompt(incident),
        actions=get_chat_actions_for_incident(incident),
        persist=False,
    )
    return True


def handle_chat_action(action_key: str, message_index: int) -> bool:
    """Dispatch chat action buttons (ack, prior session, or playbook step)."""
    from sentinel_actions import append_message, append_user_choice, consume_message_actions

    if action_key == ACKNOWLEDGE_ACTION:
        return handle_acknowledge_action(message_index)

    if handle_prior_session_action(action_key, message_index):
        return True

    incident = get_active_incident()
    if not incident or not incident.get("incident_id"):
        return False

    action_key = normalize_action_key(action_key)
    action = get_action(action_key)
    if not action:
        return False

    consume_message_actions(message_index)
    append_user_choice(action.get("plain_label", action["label"]))
    success, result = execute_incident_action(incident["incident_id"], action_key, source="chat")
    if not success:
        append_message("assistant", result)
        return True

    append_message("assistant", format_plain_action_result(action_key, get_active_incident() or incident))

    updated = get_active_incident()
    if updated and is_playbook_complete(updated):
        append_message("assistant", format_playbook_complete_message(updated))
    elif updated and get_playbook_phase(updated) != "closed":
        append_message(
            "assistant",
            format_chat_action_prompt(updated),
            actions=get_chat_actions_for_incident(updated),
            persist=False,
        )
    elif updated:
        append_message("assistant", format_playbook_complete_message(updated))
    return True


def handle_expert_chat_action(action_key: str, message_index: int) -> bool:
    """Expert mode: show editable draft form instead of immediate execution."""
    from sentinel_actions import append_message, append_user_choice, consume_message_actions

    incident = get_active_incident()
    if not incident:
        return False

    consume_message_actions(message_index)
    action = get_action(action_key)
    append_user_choice(action["label"] if action else action_key)
    append_message(
        "assistant",
        f"I've drafted the **{action['label'] if action else action_key}** parameters below. "
        "Review and edit anything that needs adjusting, then run it when you're ready.",
        draft_form={"action_key": action_key},
    )
    return True


def handle_expert_deploy(action_key: str, payload: dict, draft_message_index: int | None = None) -> bool:
    """Expert mode: execute action after user confirms draft payload."""
    from sentinel_actions import append_message, append_user_choice, consume_draft_form

    incident = get_active_incident()
    if not incident or not incident.get("incident_id"):
        return False

    if draft_message_index is not None:
        consume_draft_form(draft_message_index)

    append_user_choice("Run it")
    success, result = execute_incident_action(
        incident["incident_id"],
        action_key,
        payload,
        source="expert",
    )
    if not success:
        append_message("assistant", result)
        return False

    append_message("assistant", f"Deployed: {result}")
    return True


# ---------------------------------------------------------------------------
# Scan narrative formatters — plain vs expert copy after trigger_scan
# ---------------------------------------------------------------------------
def _plain_scan_intro(scan_key: str) -> str:
    """Opening sentence for standard-mode scan results."""
    if scan_key == "ai_threat_sweep":
        return "I just finished checking your network for anything that looks suspicious."
    return "I just finished looking at what is connected to your network right now."


def _plain_incident_summary(incident: dict) -> str:
    """Scenario-specific plain-language finding paragraph."""
    summaries = {
        "exfiltration": (
            "I found a serious problem. The device called {source} has been sending a "
            "large amount of data to an outside address ({indicator})."
        ),
        "low_risk_anomaly": (
            "I found a device on your network that I do not recognize ({source} at {indicator})."
        ),
        "brute_force": (
            "Someone keeps trying to guess the password on your {source} from {indicator}."
        ),
        "lateral_scanning": (
            "Your {source} at {indicator} is trying to reach many other devices on your network."
        ),
        "ransomware_beacon": (
            "Critical alert: {source} is showing signs of ransomware staging — encrypted bursts "
            "and suspicious activity toward {indicator}."
        ),
        "command_and_control": (
            "Your {source} is repeatedly calling out to a command server at {indicator}. "
            "This looks like active remote control of your network."
        ),
    }
    template = summaries.get(incident["key"], incident.get("description", "Suspicious activity detected."))
    return template.format(source=incident["source"], indicator=incident["indicator"])


def format_scan_narrative(scan_label: str, incident: dict) -> str:
    """Full standard-mode chat message after a scan completes."""
    del scan_label
    scan_key = incident.get("scan_key", "ai_threat_sweep")
    intro = _plain_scan_intro(scan_key)
    summary = _plain_incident_summary(incident)
    return (
        f"{intro}\n\n{summary}\n\n"
        "Investigation steps are running automatically. Acknowledge the alert to get your response playbook."
    )


def _expert_scan_intro(scan_key: str) -> str:
    """Opening sentence for expert-mode scan results."""
    if scan_key == "ai_threat_sweep":
        return "AI Threat Sweep complete. Reviewed recent local logs and traffic patterns."
    return "Active connection scan complete. Mapped current device communication graph."


def format_expert_scan_narrative(scan_label: str, incident: dict) -> str:
    """Full expert-mode side-panel message after a scan completes."""
    del scan_label
    scan_key = incident.get("scan_key", "ai_threat_sweep")
    intro = _expert_scan_intro(scan_key)
    event_note = ""
    if incident.get("incident_id"):
        try:
            events = db.get_incident_events(incident["incident_id"])
            if events is not None and not events.empty:
                event_note = f"\n\n_{len(events)} telemetry events logged; primary indicator `{incident['indicator']}`._"
        except Exception:
            pass
    return (
        f"{intro}\n\n"
        f"**{incident['title']}** detected — {incident['subtitle']}. "
        f"Source: `{incident['source']}` | Indicator: `{incident['indicator']}`\n\n"
        f"{incident['description']}{event_note}\n\n"
        "Automated investigation is complete. Acknowledge the alert on the incident page to receive the playbook."
    )


def _pick_incident_key(scan_key: str) -> str:
    """Choose next scenario from pool (random or round-robin)."""
    pool = SCAN_INCIDENT_POOL[scan_key]
    if st.session_state.scan_mode_random:
        return random.choice(pool)
    index = st.session_state.scan_rotation[scan_key]
    st.session_state.scan_rotation[scan_key] = index + 1
    return pool[index % len(pool)]


# ---------------------------------------------------------------------------
# Scan trigger — create DB incident, seed session, append chat narrative
# ---------------------------------------------------------------------------
def trigger_scan(scan_key: str):
    """Run a demo scan: pick scenario, persist incident, open chat or expert panel.

    Flow:
    1. Pick scenario from SCAN_INCIDENT_POOL (random or rotation)
    2. Optionally enrich with real device row from SCENARIO_DEVICE_MAP
    3. ``create_incident_with_investigation`` seeds DB + auto investigation actions
    4. Standard mode: new chat session + acknowledge prompt
    5. Expert mode: side panel incident detail, no new chat session
    """
    from sentinel_actions import append_message

    incident_key = _pick_incident_key(scan_key)
    incident = INCIDENTS[incident_key].copy()
    incident["key"] = incident_key
    incident["scan_key"] = scan_key
    device_id = SCENARIO_DEVICE_MAP.get(incident_key, 1)

    # Best-effort: overlay scenario with actual device table fields.
    device_row = None
    try:
        devices = db.get_all_devices()
        match = devices[devices["device_id"] == device_id]
        if not match.empty:
            device_row = match.iloc[0]
    except Exception:
        pass

    db_incident_id = db.create_incident_with_investigation(
        device_id,
        incident["title"],
        incident["severity"],
        device_name=str(device_row["device_name"]) if device_row is not None else incident.get("source", "Unknown"),
        device_type=str(device_row["device_type"]) if device_row is not None else "Other",
        internal_ip=str(device_row["internal_ip"]) if device_row is not None else incident.get("indicator", "192.168.1.1"),
        mac_address=str(device_row["mac_address"]) if device_row is not None else incident.get("source_mac", "00:00:00:00:00:00"),
        scenario_key=incident_key,
        indicator=incident.get("indicator"),
    )

    incident["incident_id"] = db_incident_id
    incident["device_name"] = incident.get("source", "Unknown device")
    incident["status"] = "Active"
    st.session_state.active_incident = incident
    st.session_state.active_incident_id = db_incident_id
    st.session_state.playbook_phase = "awaiting_ack"
    st.session_state.recommended_action_keys = []
    st.session_state.recommended_action_incident_id = None

    if is_expert_mode():
        append_message("assistant", format_expert_scan_narrative(SCAN_LABELS[scan_key], incident))
        st.session_state.side_panel_open = True
        st.session_state.expert_incident_id = db_incident_id
        st.session_state.expert_view = "incident_detail"
    else:
        session_id = db.create_session_id()
        st.session_state.active_session_id = session_id
        st.session_state.messages = []
        append_message("assistant", format_scan_narrative(SCAN_LABELS[scan_key], incident))
        append_message(
            "assistant",
            format_acknowledge_prompt(incident),
            actions=[{"key": ACKNOWLEDGE_ACTION, "label": "Acknowledge alert", "type": "primary"}],
            persist=False,
        )


def sync_incident_chat():
    """No-op — chat prompts are appended explicitly after actions."""
    return


# Backward compatibility exports (legacy code may import PLAYBOOKS)
PLAYBOOKS = {}
