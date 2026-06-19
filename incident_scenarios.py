"""Incident scenarios, playbook flow, and action execution."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta

import streamlit as st

import db
import ai_service
from action_catalog import (
    ACTIONS,
    CONTAINMENT_KEYS,
    DEFAULT_MONITORING_WAITING_PROMPT,
    ERADICATION_KEYS,
    POST_INCIDENT_KEYS,
    POST_INCIDENT_CHAT_ORDER,
    STANDARD_POST_INCIDENT_CHAT_ORDER,
    SCENARIO_MONITORING_WAITING_PROMPTS,
    format_action_result,
    format_plain_action_result,
    get_action,
    get_draft_payload,
    get_scenario_step_prompt,
    normalize_action_key,
    playbook_recommendation_text,
    recommended_steps_in_category,
    scenario_key_for_title,
    simulate_investigation_summaries,
)
from temporal_state import (
    UPDATE_TYPE_MONITORING_COMPLETE,
    actions_blocked_during_monitoring,
    format_monitoring_remaining,
    get_blocked_actions,
    get_monitoring_narrative_hours,
    is_monitoring_active,
    monitoring_gate_until_iso,
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

SKIP_TO_DOCUMENTATION_ACTION = "skip_to_documentation"

# ---------------------------------------------------------------------------
# Chat-only plan revision buttons — NOT entries in action_catalog.ACTIONS
# ---------------------------------------------------------------------------
# Driven by pending_plan_update session state after AI suggests playbook changes.
APPLY_PLAN_UPDATE_ACTION = "apply_plan_update"
DECLINE_PLAN_UPDATE_ACTION = "decline_plan_update"
PLAN_UPDATE_ACTIONS = {APPLY_PLAN_UPDATE_ACTION, DECLINE_PLAN_UPDATE_ACTION}

# Resolution shortcut confirmation flow — AI verify before trust/false-alarm execute.
VERIFICATION_CONFIRM_ACTION = "verify_confirm"
VERIFICATION_CANCEL_ACTION = "verify_cancel"
VERIFICATION_ACTIONS = {VERIFICATION_CONFIRM_ACTION, VERIFICATION_CANCEL_ACTION}

# Keys requiring AI verification when taken out of recommended order (from ai_service).
RESOLUTION_SHORTCUT_KEYS = ai_service.RESOLUTION_SHORTCUT_KEYS

# ---------------------------------------------------------------------------
# Get-started gate — user must opt in before numbered plan steps appear
# ---------------------------------------------------------------------------
GET_STARTED_ACTION = "get_started"

# Legacy alias kept for any external imports.
ACKNOWLEDGE_ACTION = GET_STARTED_ACTION

# ---------------------------------------------------------------------------
# Incident status sets — drive terminal checks and open/closed UI affordances
# ---------------------------------------------------------------------------
TERMINAL_STATUSES = {"Mitigated", "False Positive", "Trusted"}
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


# ---------------------------------------------------------------------------
# State init — Streamlit session keys for incident/playbook UX
# ---------------------------------------------------------------------------
def init_incident_state():
    """Ensure all incident-related session keys exist with safe defaults."""
    if "active_incident" not in st.session_state:
        st.session_state.active_incident = None
    if "scan_rotation" not in st.session_state:
        # Round-robin index per scan type when scan_mode_random is False.
        st.session_state.scan_rotation = {
            "ai_threat_sweep": 0,
            "active_connections": 0,
        }
    if "scan_mode_random" not in st.session_state:
        st.session_state.scan_mode_random = True
    if "awaiting_get_started" not in st.session_state:
        # True between summary message and first plan reveal.
        st.session_state.awaiting_get_started = False
    if "generating_playbook_for" not in st.session_state:
        # incident_id while deferred AI playbook generation runs.
        st.session_state.generating_playbook_for = None
    if "pending_chat_bootstrap_incident_id" not in st.session_state:
        # Pairs with generating_playbook_for for process_pending_incident_chat_work.
        st.session_state.pending_chat_bootstrap_incident_id = None
    if "ai_busy" not in st.session_state:
        st.session_state.ai_busy = False
    if "scan_complete_notice" not in st.session_state:
        st.session_state.scan_complete_notice = None
    if "scan_error_notice" not in st.session_state:
        st.session_state.scan_error_notice = None
    if "pending_plan_update" not in st.session_state:
        st.session_state.pending_plan_update = None
    if "pending_action_verification" not in st.session_state:
        st.session_state.pending_action_verification = None
    if "playbook_error_notice" not in st.session_state:
        st.session_state.playbook_error_notice = None
    if "playbook_phase" not in st.session_state:
        st.session_state.playbook_phase = "awaiting_ack"
    if "recommended_action_keys" not in st.session_state:
        st.session_state.recommended_action_keys = []
    if "recommended_action_incident_id" not in st.session_state:
        # Cache invalidation: keys only valid when incident_id matches.
        st.session_state.recommended_action_incident_id = None


def is_ai_busy() -> bool:
    """Return True while a blocking AI call is in progress."""
    return bool(st.session_state.get("ai_busy"))


def is_generating_playbook(incident_id: int | None = None) -> bool:
    """Return True when playbook generation is running for an incident."""
    generating = st.session_state.get("generating_playbook_for")
    if generating is None:
        return False
    if incident_id is None:
        return True
    return generating == incident_id


def set_ai_busy(value: bool = True) -> None:
    """Set the global AI busy flag for UI gating."""
    st.session_state.ai_busy = value


def set_ai_status_message(message: str | None) -> None:
    """Set user-facing status copy shown in the chat AI banner while busy."""
    st.session_state.ai_status_message = message


def get_ai_status_message() -> str:
    """Return the active AI status line for chat banners."""
    return str(st.session_state.get("ai_status_message") or "Sentinel is thinking…")


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
    """Return the set of action keys already recorded for this incident in DB."""
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
    """Resolve scenario id from incident dict (key field or title fallback)."""
    return incident.get("key") or scenario_key_for_title(incident.get("title", ""))


def format_monitoring_waiting_message(incident: dict) -> str:
    """Template copy while an enhanced monitoring window is active."""
    incident_id = incident.get("incident_id")
    scenario_key = _scenario_key_for_incident(incident)
    device = incident.get("device_name") or incident.get("source", "the device")
    narrative_hours = get_monitoring_narrative_hours(incident_id)
    remaining = format_monitoring_remaining(incident)
    template = SCENARIO_MONITORING_WAITING_PROMPTS.get(scenario_key, DEFAULT_MONITORING_WAITING_PROMPT)
    return template.format(
        device=device,
        narrative_hours=narrative_hours,
        remaining=remaining,
    )


# ---------------------------------------------------------------------------
# Playbook phase — derive current response stage from DB + session state
# ---------------------------------------------------------------------------
def get_playbook_phase(incident: dict | None = None) -> str:
    """Return the current playbook phase string for gating UI and actions."""
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
    if incident_id and SKIP_TO_DOCUMENTATION_ACTION in completed:
        return "post_incident"

    # Monitoring gate overrides category phase until monitor_until expires.
    if is_monitoring_active(incident):
        return "monitoring"

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


def get_display_phase(incident: dict) -> str:
    """Human-readable playbook phase aligned with incident status."""
    status = incident.get("status", "Active")
    if is_terminal_status(status):
        return "Closed"
    if is_monitoring_active(incident):
        return "Monitoring"
    phase = get_playbook_phase(incident)
    if phase == "awaiting_ack":
        return "Awaiting Review"
    if phase == "closed":
        return "Closed"
    return phase.replace("_", " ").title()


def get_homeowner_phase_caption(incident: dict) -> str | None:
    """Short plain-language phase line for Standard mode chat header."""
    status = incident.get("status", "Active")
    if is_terminal_status(status):
        return "All clear — documentation available if you need it"
    if is_monitoring_active(incident):
        return "Watching for more activity"
    phase = get_playbook_phase(incident)
    captions = {
        "awaiting_ack": "Reviewing what we found",
        "containment": "Stopping the threat from spreading",
        "eradication": "Securing and cleaning up",
        "post_incident": "Wrapping up",
        "closed": "Wrapping up",
    }
    return captions.get(phase)


def _finalize_incident_if_playbook_complete(incident_id: int) -> bool:
    """Move Investigating incidents to Mitigated once the recommended playbook is done."""
    row = db.get_incident_by_id(incident_id)
    if not row:
        return False

    incident = build_active_incident_from_db(row)
    status = incident.get("status", "Active")
    if is_terminal_status(status) or not is_playbook_complete(incident):
        return False
    if incident.get("monitor_until"):
        return False

    if status in OPEN_STATUSES:
        db.update_incident_status(incident_id, "Mitigated")
        return True
    return False


def _process_expired_monitoring(incident_id: int) -> bool:
    """When a monitoring window ends, clear the gate and create an update alert."""
    row = db.get_incident_by_id(incident_id)
    if not row or not row.get("monitor_until"):
        return False

    incident = build_active_incident_from_db(row)
    if is_monitoring_active(incident):
        return False

    db.clear_monitor_until(incident_id)
    device = incident.get("device_name") or incident.get("source", "the device")
    hours = get_monitoring_narrative_hours(incident_id)
    ip = incident.get("internal_ip") or incident.get("indicator", "192.168.1.1")
    db.insert_incident_event(
        incident_id,
        ip,
        ip,
        "INTERNAL",
        "Monitoring window complete — no new anomalies observed during watch period.",
    )
    update_id = db.insert_incident_update(
        incident_id,
        UPDATE_TYPE_MONITORING_COMPLETE,
        f"Monitoring complete — {device}",
        summary_text=(
            f"Enhanced monitoring ({hours}h watch) finished for **{device}**. "
            "No new suspicious activity was detected."
        ),
        payload={"narrative_hours": hours, "trigger_action_key": "prompt_offline_scan"},
    )
    if update_id is not None:
        from sentinel_actions import bump_notifications_revision

        bump_notifications_revision()
    return True


def sync_all_monitoring_expirations() -> int:
    """Check all incidents with monitor_until and emit update alerts when expired."""
    query = "SELECT incident_id FROM incidents WHERE monitor_until IS NOT NULL;"
    with db.get_db_connection() as conn:
        rows = conn.execute(query).fetchall()
    processed = 0
    for row in rows:
        if _process_expired_monitoring(int(row["incident_id"])):
            processed += 1
    return processed


def _sync_incident_lifecycle(incident_id: int) -> dict | None:
    """Apply stale status fixes and return the latest incident row, if any."""
    _process_expired_monitoring(incident_id)
    if _finalize_incident_if_playbook_complete(incident_id):
        from sentinel_actions import bump_incidents_table_revision

        bump_incidents_table_revision()
    return db.get_incident_by_id(incident_id)


def _db_authority_recommended(incident_id: int) -> bool:
    """Re-fetch authority_recommended from DB (session copy may be stale)."""
    row = db.get_incident_by_id(incident_id)
    return bool(row and row.get("authority_recommended"))


def can_execute_action(action_key: str, incident: dict) -> bool:
    """Return True if ``action_key`` is allowed for ``incident`` right now."""
    action_key = normalize_action_key(action_key)
    action = get_action(action_key)
    if not action:
        return False

    incident_id = incident.get("incident_id")

    # Skip-to-docs is a special post_incident shortcut available mid-playbook.
    if action_key == SKIP_TO_DOCUMENTATION_ACTION:
        phase = get_playbook_phase(incident)
        if is_monitoring_active(incident):
            return False
        if phase not in ("containment", "eradication") or not incident_id:
            return False
        return action_key not in db.get_incident_action_keys_completed(incident_id)

    # Temporal gates (monitoring window) — checked before phase/category rules.
    blocked = get_blocked_actions(incident, incident_id=incident_id)
    if action_key in blocked:
        return False

    status = incident.get("status", "Active")

    if incident_id and action_key in db.get_incident_action_keys_completed(incident_id):
        return False

    if is_terminal_status(status):
        return action["category"] == "post_incident"

    phase = get_playbook_phase(incident)
    category = action["category"]

    if phase == "awaiting_ack":
        return False
    if phase == "monitoring":
        return False
    if phase == "closed":
        if category == "post_incident" and is_playbook_complete(incident):
            return True
        if category == "post_incident" and (
            incident.get("authority_recommended")
            or (incident_id and _db_authority_recommended(incident_id))
        ):
            return True
        return False
    if category == "investigation":
        return False

    # Phase → allowed categories (eradication phase still allows late containment).
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
def _cache_ai_analysis(incident_id: int, analysis_text: str) -> None:
    """Store AI analysis narrative in session for chat display."""
    if "ai_analysis_cache" not in st.session_state:
        st.session_state.ai_analysis_cache = {}
    st.session_state.ai_analysis_cache[incident_id] = analysis_text


def get_cached_ai_analysis(incident_id: int) -> str | None:
    """Return cached AI analysis for an incident, if any."""
    cache = st.session_state.get("ai_analysis_cache", {})
    return cache.get(incident_id)


def run_post_investigation_ai_analysis(incident_id: int, incident: dict | None = None) -> ai_service.AnalysisResult:
    """Run AI analysis after auto-investigation and persist playbook to DB (idempotent)."""
    existing = db.get_active_playbook_recommendation(incident_id)
    if existing:
        if incident is None:
            row = db.get_incident_by_id(incident_id)
            incident = build_active_incident_from_db(row) if row else {}
        cached = get_cached_ai_analysis(incident_id)
        keys = get_recommended_action_keys(incident_id)
        return ai_service.AnalysisResult(
            analysis=cached or existing.get("recommendation_text", ""),
            playbook_action_keys=keys,
            playbook_text=existing.get("recommendation_text", ""),
            used_ai=bool(cached),
        )

    if incident is None:
        row = db.get_incident_by_id(incident_id)
        if not row:
            return ai_service.AnalysisResult(
                analysis="Incident not found.",
                playbook_action_keys=[],
                success=False,
                error_detail="Incident not found in database.",
            )
        incident = build_active_incident_from_db(row)

    result = ai_service.analyze_incident(incident_id, incident)
    if not result.success or not result.playbook_action_keys:
        return result

    db.insert_playbook_recommendation(incident_id, result.playbook_text, result.playbook_action_keys)

    # Critical incidents may flag law-enforcement notice recommendations.
    if result.authority_recommended:
        db.update_incident_status(
            incident_id,
            incident.get("status", "Active"),
            authority_recommended=1,
        )
        existing_notices = [
            r for r in db.get_recommendations_for_incident(incident_id)
            if r["recommendation_type"] == "authority_notice"
        ]
        if not existing_notices:
            db.insert_recommendation(
                incident_id,
                "Critical incident — consider notifying law enforcement after containment and resolution.",
                recommendation_type="authority_notice",
                display_order=3,
            )

    for index, rec_text in enumerate(result.general_recommendations, start=1):
        db.insert_recommendation(
            incident_id,
            rec_text,
            recommendation_type="general",
            display_order=index,
        )

    _cache_ai_analysis(incident_id, result.analysis)
    sync_recommended_actions_from_db(incident_id)
    return result


def apply_playbook_update(incident_id: int, incident: dict, proposed_keys: list[str], summary: str) -> list[str]:
    """Persist a chat-driven playbook revision and refresh session state."""
    current = get_recommended_action_keys(incident_id)
    completed = db.get_incident_action_keys_completed(incident_id)
    filtered = ai_service.filter_remaining_playbook_keys(proposed_keys, incident_id)
    if not filtered:
        return current
    merged = ai_service.merge_playbook_update(current, completed, filtered)
    revision_note = f"{playbook_recommendation_text(incident, merged)} (Revised after chat: {summary})"

    db.deactivate_playbook_recommendations(incident_id)
    db.insert_playbook_recommendation(incident_id, revision_note, merged)
    db.insert_recommendation(
        incident_id,
        f"Response plan updated based on your question: {summary}",
        recommendation_type="general",
        display_order=5,
    )

    sync_recommended_actions_from_db(incident_id)
    updated_row = db.get_incident_by_id(incident_id)
    if updated_row:
        st.session_state.active_incident = build_active_incident_from_db(updated_row)
    st.session_state.playbook_phase = get_playbook_phase(st.session_state.get("active_incident") or incident)
    return merged


def acknowledge_incident_flow(incident_id: int) -> bool:
    """Acknowledge alert, generate playbook if missing, refresh session state."""
    incident_row = db.get_incident_by_id(incident_id)
    if not incident_row:
        return False

    incident = build_active_incident_from_db(incident_row)
    if not db.is_incident_acknowledged(incident_id):
        db.acknowledge_incident(incident_id)

    # Playbook is created by post-investigation AI.
    existing = db.get_active_playbook_recommendation(incident_id)
    if not existing:
        result = run_post_investigation_ai_analysis(incident_id, incident)
        if not result.success:
            st.session_state.playbook_error_notice = (
                result.error_detail or ai_service.format_ai_error_message("Playbook generation")
            )

    incident_row = db.get_incident_by_id(incident_id)
    st.session_state.active_incident = build_active_incident_from_db(incident_row)
    st.session_state.active_incident_id = incident_id
    sync_recommended_actions_from_db(incident_id)
    st.session_state.playbook_phase = get_playbook_phase(st.session_state.active_incident)
    st.session_state.awaiting_get_started = False
    return True


def execute_incident_action(
    incident_id: int,
    action_key: str,
    payload: dict | None = None,
    *,
    source: str = "expert",
    verification_granted: bool = False,
    prefetched_result: str | None = None,
) -> tuple[bool, str]:
    """Run a response action: validate, format result, persist, update status."""
    action_key = normalize_action_key(action_key)
    incident_row = db.get_incident_by_id(incident_id)
    if not incident_row:
        return False, "Incident not found."

    incident = build_active_incident_from_db(incident_row)
    action = get_action(action_key)
    if not action:
        return False, f"Unknown action: {action_key}"

    if incident_id and action_key in db.get_incident_action_keys_completed(incident_id):
        return False, f"{action['label']} was already completed for this incident."

    allowed = can_execute_action(action_key, incident)
    if not allowed:
        if verification_granted and action_key in RESOLUTION_SHORTCUT_KEYS:
            allowed = True
        else:
            return False, f"{action['label']} is not available for this incident right now."

    payload = payload or get_draft_payload(action_key, incident)

    if action_key == "generate_incident_report":
        if prefetched_result is not None:
            result = prefetched_result
        else:
            ai_report = ai_service.generate_incident_report(incident_id)
            result = ai_report if ai_report else format_action_result(action_key, incident, payload)
    elif action_key == SKIP_TO_DOCUMENTATION_ACTION:
        result = (
            "Skipped remaining containment and eradication steps. "
            "Post-incident documentation actions are now available."
        )
    else:
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

    # Monitoring window and resolution actions update incident status.
    if action_key == "prompt_offline_scan":
        # Starts temporal gate — see temporal_state.monitoring_gate_until_iso.
        db.update_incident_status(
            incident_id,
            "Investigating",
            monitor_until=monitoring_gate_until_iso(),
        )
    elif action.get("resolution_status"):
        db.update_incident_status(incident_id, action["resolution_status"])
    elif action_key in CONTAINMENT_KEYS and incident_row.get("status") == "Active":
        # First containment step moves Active → Investigating.
        db.update_incident_status(incident_id, "Investigating")

    _sync_incident_lifecycle(incident_id)

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
# Narrative formatters — summary, get-started gate, plan reveal, chat prompts
# ---------------------------------------------------------------------------
def format_incident_summary_message(incident_id: int, incident: dict | None = None) -> str:
    """Return saved AI analysis narrative only (no playbook steps)."""
    cached = get_cached_ai_analysis(incident_id)
    if cached:
        return cached
    rec = db.get_active_playbook_recommendation(incident_id)
    if rec and rec.get("recommendation_text"):
        return rec["recommendation_text"]
    if incident:
        return (
            f"**{incident['title']}** detected on "
            f"**{incident.get('device_name', incident.get('source'))}** "
            f"({incident['severity']} severity). Automated investigation is complete."
        )
    return "Analysis complete. Review the evidence summary above when you're ready."


def format_get_started_prompt(incident: dict) -> str:
    """Soft gate inviting the user to opt into the response plan."""
    return (
        f"I've reviewed the evidence for **{incident['title']}** on "
        f"**{incident.get('device_name', incident.get('source'))}**. "
        "Would you like to get started with the response plan?"
    )


def format_plan_reveal(incident: dict, action_keys: list[str]) -> str:
    """Numbered plan overview shown after the user clicks Get started."""
    lines = ["**Recommended response plan:**", ""]
    post_monitor_keys = actions_blocked_during_monitoring()
    for index, key in enumerate(action_keys, start=1):
        action = get_action(key)
        if action:
            label = action["label"]
            hint = action["hint"]
            footnote = ""
            if key in post_monitor_keys and "prompt_offline_scan" in action_keys:
                footnote = " _(available after monitoring window)_"
            lines.append(f"{index}. **{label}** — _{hint}_{footnote}")
    lines.append("")
    lines.append(
        "I'll unlock each step in order as we go. Use the button below when you're ready for the next one."
    )
    return "\n".join(lines)


def format_ai_analysis_message(incident_id: int) -> str:
    """Return cached AI analysis narrative or a short fallback."""
    return format_incident_summary_message(incident_id)


def format_playbook_brief(incident: dict, action_keys: list[str]) -> str:
    """Numbered list of recommended steps with expert labels and hints."""
    incident_id = incident.get("incident_id")
    cached = get_cached_ai_analysis(incident_id) if incident_id else None
    if cached:
        lines = [cached, "", "**Recommended steps:**"]
    else:
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
    phase = get_playbook_phase(incident)

    if is_monitoring_active(incident):
        return format_monitoring_waiting_message(incident)

    if phase == "closed" or is_playbook_complete(incident):
        return format_playbook_complete_message(incident)

    next_key = get_next_executable_recommended_step(incident)
    if next_key:
        incident_id = incident.get("incident_id")
        if incident_id:
            ai_text = ai_service.generate_step_guidance(
                incident_id,
                incident,
                next_key,
                playbook_phase=phase,
                expert_mode=is_expert_mode(),
            )
            if ai_text:
                return ai_text
        scenario_key = _scenario_key_for_incident(incident)
        custom = get_scenario_step_prompt(scenario_key, next_key)
        if custom:
            return custom
        action = get_action(next_key)
        label = action["label"] if action else next_key
        return f"Next recommended step: I can **{label}**. Should I go ahead?"

    if phase == "closed" or is_playbook_complete(incident):
        return format_post_incident_chat_prompt(incident)

    if phase == "post_incident":
        return format_post_incident_chat_prompt(incident)

    return "Review the recommended playbook when you're ready to continue."


def format_post_incident_chat_prompt(incident: dict) -> str:
    """Guide the user through documentation / authority handoff in chat."""
    incident_id = incident.get("incident_id")
    authority = incident.get("authority_recommended") or (
        incident_id and _db_authority_recommended(incident_id)
    )
    if authority:
        return (
            "Simulated containment steps are complete. I cannot contact law enforcement for you, "
            "but I can help you **preserve evidence**, **document what happened**, and **prepare a "
            "package for police**. Use the buttons below for each documentation step, or ask me "
            "how to proceed — for example what to save before calling authorities."
        )
    return (
        "Response steps are complete. Use the documentation buttons below to preserve records "
        "and generate a summary report, or ask me what to do next."
    )


def format_playbook_complete_message(incident: dict) -> str:
    """Assistant copy when all recommended playbook steps are finished."""
    status = incident.get("status", "Unknown")
    phase_label = get_display_phase(incident)
    if incident.get("monitor_until"):
        return (
            f"Recommended response playbook complete (status: **{status}**, phase: **{phase_label}**). "
            f"I'm monitoring **{incident.get('device_name', incident.get('source', 'the device'))}** "
            f"until **{incident['monitor_until']}**. "
            f"{format_post_incident_chat_prompt(incident)}"
        )
    if incident.get("authority_recommended") or (
        incident.get("incident_id") and _db_authority_recommended(incident["incident_id"])
    ):
        return (
            f"Recommended response playbook complete — incident **{phase_label.lower()}** "
            f"(status: **{status}**). "
            f"{format_post_incident_chat_prompt(incident)}"
        )
    if is_terminal_status(status):
        return f"Response playbook complete. Incident **{phase_label.lower()}** — status: **{status}**."
    return (
        f"Recommended response playbook complete — incident **{phase_label.lower()}** "
        f"(status: **{status}**). "
        f"{format_post_incident_chat_prompt(incident)}"
    )


def _action_to_chat_button(action_key: str, primary: bool = False) -> dict:
    """Build a chat action button dict (key, label, primary/secondary type)."""
    action = get_action(action_key)
    if not action:
        return {"key": action_key, "label": action_key, "type": "secondary"}
    return {
        "key": action_key,
        "label": action["label"],
        "type": "primary" if primary else "secondary",
    }


def _post_incident_chat_actions(incident: dict) -> list[dict]:
    """Return documentation action buttons available after playbook completion."""
    incident_id = incident.get("incident_id")
    if not incident_id:
        return []

    completed = _incident_completed_action_keys(incident_id)
    actions: list[dict] = []
    order = (
        POST_INCIDENT_CHAT_ORDER
        if is_expert_mode()
        else STANDARD_POST_INCIDENT_CHAT_ORDER
    )
    for index, key in enumerate(order):
        if key in completed or key not in POST_INCIDENT_KEYS:
            continue
        if not can_execute_action(key, incident):
            continue
        actions.append(_action_to_chat_button(key, primary=index == 0))
    return actions


def get_chat_actions_for_incident(incident: dict, *, guided: bool | None = None) -> list[dict]:
    """Return chat action buttons appropriate for the current playbook state."""
    if guided is None:
        guided = not is_expert_mode()

    incident_id = incident.get("incident_id")
    if incident_id and not db.is_incident_acknowledged(incident_id):
        if is_terminal_status(incident.get("status", "")):
            return []
        return [{"key": GET_STARTED_ACTION, "label": "Get started", "type": "primary"}]

    if is_terminal_status(incident.get("status", "")):
        return _post_incident_chat_actions(incident)

    if is_playbook_complete(incident):
        return _post_incident_chat_actions(incident)

    if is_monitoring_active(incident) or get_playbook_phase(incident) == "monitoring":
        return []

    phase = get_playbook_phase(incident)
    if phase in ("closed", "post_incident"):
        doc_actions = _post_incident_chat_actions(incident)
        if doc_actions:
            return doc_actions
        if phase == "closed":
            return []

    next_key = get_next_executable_recommended_step(incident)
    if not next_key:
        return []

    if guided:
        actions = [_action_to_chat_button(next_key, primary=True)]
        completed = _incident_completed_action_keys(incident_id)
        phase = get_playbook_phase(incident)
        if (
            phase in ("containment", "eradication")
            and SKIP_TO_DOCUMENTATION_ACTION not in completed
            and can_execute_action(SKIP_TO_DOCUMENTATION_ACTION, incident)
        ):
            actions.append(_action_to_chat_button(SKIP_TO_DOCUMENTATION_ACTION, primary=False))
        return actions

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


def clear_sticky_pending_states() -> None:
    """Clear plan-update and verification UI state."""
    st.session_state.pending_plan_update = None
    st.session_state.pending_action_verification = None


def requires_resolution_verification(action_key: str, incident: dict) -> bool:
    """Return True when trust/false-alarm/skip needs AI confirmation before execute."""
    action_key = normalize_action_key(action_key)
    if action_key not in RESOLUTION_SHORTCUT_KEYS:
        return False

    incident_id = incident.get("incident_id")
    next_key = get_next_executable_recommended_step(incident)
    if next_key == action_key:
        return False

    scenario_key = _scenario_key_for_incident(incident)
    severity = incident.get("severity", "Low")
    if severity in ("High", "Critical"):
        return True
    if scenario_key != "low_risk_anomaly":
        return True

    blocked = get_blocked_actions(incident, incident_id=incident_id)
    if action_key in blocked:
        return True

    if action_key == "trust_device" and incident_id:
        recommended = get_recommended_action_keys(incident_id)
        completed = _incident_completed_action_keys(incident_id)
        remaining_contain = [
            k for k in recommended
            if k in CONTAINMENT_KEYS and k not in completed
        ]
        if remaining_contain:
            return True

    return action_key != next_key


def get_resolution_shortcuts(incident: dict) -> list[dict]:
    """Trust, false alarm, and skip-docs shortcuts for the sticky bar."""
    incident_id = incident.get("incident_id")
    if not incident_id or not db.is_incident_acknowledged(incident_id):
        return []
    if is_terminal_status(incident.get("status", "")):
        return []

    completed = _incident_completed_action_keys(incident_id)
    shortcuts: list[dict] = []
    phase = get_playbook_phase(incident)

    for key in ("trust_device", "mark_false_positive"):
        if key in completed:
            continue
        action = get_action(key)
        if not action:
            continue
        shortcuts.append(_action_to_chat_button(key, primary=False))

    if (
        SKIP_TO_DOCUMENTATION_ACTION not in completed
        and phase in ("containment", "eradication")
        and not is_monitoring_active(incident)
    ):
        shortcuts.append(_action_to_chat_button(SKIP_TO_DOCUMENTATION_ACTION, primary=False))

    return shortcuts


def get_sticky_primary_action(incident: dict) -> dict | None:
    """Next recommended playbook step for the sticky bar primary button."""
    incident_id = incident.get("incident_id")
    if not incident_id:
        return None

    if not db.is_incident_acknowledged(incident_id):
        if is_terminal_status(incident.get("status", "")):
            return None
        return _get_started_action_button()

    if is_terminal_status(incident.get("status", "")) or is_playbook_complete(incident):
        docs = _post_incident_chat_actions(incident)
        return docs[0] if docs else None

    if is_monitoring_active(incident) or get_playbook_phase(incident) == "monitoring":
        return None

    next_key = get_next_executable_recommended_step(incident)
    if not next_key:
        docs = _post_incident_chat_actions(incident)
        return docs[0] if docs else None

    return _action_to_chat_button(next_key, primary=True)


def get_sticky_bar_state(incident: dict | None) -> dict:
    """Compute sticky action bar mode and button definitions."""
    if st.session_state.get("pending_action_verification"):
        return {
            "mode": "verification",
            "verification": st.session_state.pending_action_verification,
        }

    if st.session_state.get("pending_plan_update"):
        return {
            "mode": "plan_update",
            "plan_update": st.session_state.pending_plan_update,
            "actions": [
                {"key": APPLY_PLAN_UPDATE_ACTION, "label": "Yes, update the plan", "type": "primary"},
                {"key": DECLINE_PLAN_UPDATE_ACTION, "label": "No, keep current plan", "type": "secondary"},
            ],
        }

    if not incident:
        return {"mode": "idle"}

    if st.session_state.get("awaiting_get_started") and incident.get("incident_id"):
        if not db.is_incident_acknowledged(incident["incident_id"]):
            return {
                "mode": "get_started",
                "primary": _get_started_action_button(),
                "shortcuts": [],
            }

    primary = get_sticky_primary_action(incident)
    shortcuts = get_resolution_shortcuts(incident)
    post_docs = []
    if is_playbook_complete(incident) or get_playbook_phase(incident) in ("post_incident", "closed"):
        post_docs = _post_incident_chat_actions(incident)

    mode = "monitoring" if is_monitoring_active(incident) else "normal"
    return {
        "mode": mode,
        "primary": primary,
        "shortcuts": shortcuts,
        "post_incident_actions": post_docs,
    }


def _append_action_result_message(action_key: str, result_text: str) -> None:
    """Append assistant chat after a playbook action executes."""
    from sentinel_actions import append_message

    updated = get_active_incident()
    if not updated:
        append_message("assistant", result_text)
        return

    if action_key == "prompt_offline_scan" and is_monitoring_active(updated):
        append_message(
            "assistant",
            f"{result_text}\n\n{format_monitoring_waiting_message(updated)}",
        )
        return
    if is_playbook_complete(updated):
        _append_post_playbook_message(updated, prefix=result_text)
    elif get_playbook_phase(updated) in ("closed", "post_incident"):
        append_message(
            "assistant",
            f"{result_text}\n\n{format_post_incident_chat_prompt(updated)}",
        )
    elif get_playbook_phase(updated) != "closed":
        append_message("assistant", result_text)
        _append_next_step_message(updated)
        return
    else:
        append_message("assistant", result_text)


def handle_sticky_action(action_key: str) -> bool:
    """Dispatch sticky action bar button clicks."""
    from sentinel_actions import append_message, append_user_choice

    action_key = normalize_action_key(action_key)

    if action_key == VERIFICATION_CANCEL_ACTION:
        st.session_state.pending_action_verification = None
        return True

    if action_key == VERIFICATION_CONFIRM_ACTION:
        pending = st.session_state.get("pending_action_verification") or {}
        target_key = pending.get("action_key")
        st.session_state.pending_action_verification = None
        if not target_key:
            return False
        incident = get_active_incident()
        if not incident or not incident.get("incident_id"):
            return False
        action = get_action(target_key)
        if not action:
            return False
        append_user_choice(pending.get("confirm_label", action["label"]))
        success, result = execute_incident_action(
            incident["incident_id"],
            target_key,
            source="chat",
            verification_granted=True,
        )
        if not success:
            append_message("assistant", result)
            return True
        result_text = format_plain_action_result(target_key, get_active_incident() or incident)
        _append_action_result_message(target_key, result_text)
        return True

    if action_key in PLAN_UPDATE_ACTIONS:
        return handle_plan_update_action(action_key)

    if action_key == GET_STARTED_ACTION:
        incident = get_active_incident()
        if not incident or not incident.get("incident_id"):
            return False
        append_user_choice("Get started")
        st.session_state.awaiting_get_started = False
        _engage_incident_plan(incident["incident_id"], incident)
        return True

    incident = get_active_incident()
    if not incident or not incident.get("incident_id"):
        return False

    action = get_action(action_key)
    if not action:
        return False

    if action_key in RESOLUTION_SHORTCUT_KEYS and requires_resolution_verification(action_key, incident):
        from sentinel_actions import append_evidence_message

        append_evidence_message(
            incident_id=int(incident["incident_id"]),
            request_label=f"Resolution check: {action['label']}",
            request_kind="chat",
        )
        st.session_state.pending_chat_ai = {
            "kind": "verify_resolution",
            "incident_id": incident["incident_id"],
            "action_key": action_key,
        }
        st.rerun()
        return True

    append_user_choice(action["label"])

    if action_key == "generate_incident_report":
        from sentinel_actions import append_evidence_message

        append_evidence_message(
            incident_id=int(incident["incident_id"]),
            request_label="Incident report",
            request_kind="incident_report",
        )
        st.session_state.pending_chat_ai = {
            "kind": "incident_report",
            "incident_id": incident["incident_id"],
            "source": "chat",
        }
        st.rerun()
        return True

    from sentinel_actions import append_evidence_message

    append_evidence_message(
        incident_id=int(incident["incident_id"]),
        request_label=f"Action context: {action['label']}",
        request_kind="chat",
    )
    st.session_state.pending_chat_ai = {
        "kind": "execute_action",
        "incident_id": incident["incident_id"],
        "action_key": action_key,
        "source": "chat",
    }
    st.rerun()
    return True


def _get_started_action_button() -> dict:
    """Chat button definition for the get-started gate."""
    return {"key": GET_STARTED_ACTION, "label": "Get started", "type": "primary"}


def _action_display_label(action: dict, *, expert_mode: bool) -> str:
    """Return expert label for an action (standard and expert modes use the same names)."""
    _ = expert_mode
    return action["label"]


def format_progress_status(
    incident_id: int,
    incident: dict,
    *,
    expert_mode: bool | None = None,
) -> str:
    """DB-grounded status recap: phase, completed steps, and what is next."""
    if expert_mode is None:
        expert_mode = is_expert_mode()

    phase = get_playbook_phase(incident)
    status = incident.get("status", "Unknown")
    phase_label = get_display_phase(incident)
    recommended = get_recommended_action_keys(incident_id)
    completed_keys = _incident_completed_action_keys(incident_id)
    next_key = get_next_executable_recommended_step(incident)

    lines = [
        f"**Status:** {status} | **Phase:** {phase_label}",
    ]

    if incident_id and not db.is_incident_acknowledged(incident_id):
        lines.append("")
        lines.append(
            "Automated investigation is done, but we have not started the response plan yet."
        )
        lines.append("Click **Get started** when you want to walk through the recommended steps.")
        return "\n".join(lines)

    if is_monitoring_active(incident):
        hours = get_monitoring_narrative_hours(incident_id)
        remaining = format_monitoring_remaining(incident)
        lines.append("")
        lines.append(
            f"**Monitoring:** {hours}h enhanced watch in progress. "
            f"Demo unlock in **{remaining}**. I'll alert you when the window completes."
        )

    if recommended:
        lines.append("")
        lines.append("**Response plan progress:**")
        for index, key in enumerate(recommended, start=1):
            action = get_action(key)
            if not action:
                continue
            label = _action_display_label(action, expert_mode=expert_mode)
            if key in completed_keys:
                marker = "✓"
            elif is_monitoring_active(incident) and key in actions_blocked_during_monitoring():
                marker = "◇"
            elif key == next_key:
                marker = "→"
            else:
                marker = "○"
            lines.append(f"{marker} {index}. {label}")

    if is_monitoring_active(incident) and not is_playbook_complete(incident):
        lines.append("")
        lines.append("_◇ = unlocks after monitoring window_")
    elif next_key and not is_playbook_complete(incident):
        action = get_action(next_key)
        if action:
            label = _action_display_label(action, expert_mode=expert_mode)
            hint = action["hint"]
            lines.append("")
            lines.append(f"**Up next:** {label} — _{hint}_")
    elif is_playbook_complete(incident):
        lines.append("")
        lines.append(format_playbook_complete_message(incident))

    return "\n".join(lines)


def build_progress_chat_response(
    incident_id: int,
    incident: dict,
    *,
    expert_mode: bool | None = None,
) -> tuple[str, list[dict] | None]:
    """Answer where-we-are / next-step questions from DB state and return action buttons."""
    if expert_mode is None:
        expert_mode = is_expert_mode()

    sync_recommended_actions_from_db(incident_id)
    incident_row = _sync_incident_lifecycle(incident_id) or db.get_incident_by_id(incident_id)
    if incident_row:
        incident = build_active_incident_from_db(incident_row)
        st.session_state.active_incident = incident
    st.session_state.playbook_phase = get_playbook_phase(incident)

    status_block = format_progress_status(incident_id, incident, expert_mode=expert_mode)

    if incident_id and not db.is_incident_acknowledged(incident_id):
        st.session_state.awaiting_get_started = True
        ai_brief = ai_service.generate_resume_briefing(
            incident_id,
            incident,
            playbook_phase=get_playbook_phase(incident),
            next_key=get_next_executable_recommended_step(incident),
            playbook_complete=is_playbook_complete(incident),
            expert_mode=expert_mode,
        )
        narrative = ai_brief or format_where_we_left_off(incident_id, incident)
        return f"{status_block}\n\n{narrative}", [_get_started_action_button()]

    st.session_state.awaiting_get_started = False
    actions = get_chat_actions_for_incident(incident)

    if is_monitoring_active(incident):
        waiting = format_monitoring_waiting_message(incident)
        return f"{status_block}\n\n{waiting}", None

    if is_playbook_complete(incident) or get_playbook_phase(incident) in ("closed", "post_incident"):
        ai_brief = ai_service.generate_resume_briefing(
            incident_id,
            incident,
            playbook_phase=get_playbook_phase(incident),
            next_key=get_next_executable_recommended_step(incident),
            playbook_complete=True,
            expert_mode=expert_mode,
        )
        narrative = ai_brief or format_post_incident_chat_prompt(incident)
        return f"{status_block}\n\n{narrative}", actions or None

    guidance = _step_guidance_with_spinner(incident)
    footer = (
        "Use the action button below when you're ready to take the next step."
        if not expert_mode
        else "Execute the next response action using the button below."
    )
    return f"{status_block}\n\n{guidance}\n\n{footer}", actions or None


def format_returning_incident_resume(incident_id: int, incident: dict) -> str:
    """Single resume message for returning incidents (AI or template fallback)."""
    next_key = get_next_executable_recommended_step(incident)
    ai_brief = ai_service.generate_resume_briefing(
        incident_id,
        incident,
        playbook_phase=get_playbook_phase(incident),
        next_key=next_key,
        playbook_complete=is_playbook_complete(incident),
        expert_mode=is_expert_mode(),
    )
    if ai_brief:
        return ai_brief
    return format_where_we_left_off(incident_id, incident)


def format_where_we_left_off(incident_id: int, incident: dict) -> str:
    """Template fallback recap for returning users when AI is unavailable."""
    session_id = db.get_incident_chat_session_id(incident_id)
    if not session_id:
        return "Welcome back. Let's pick up where we left off on this incident."

    messages = db.get_messages_for_session(session_id)
    last_assistant = next(
        (m["content"] for m in reversed(messages) if m["role"] == "assistant"),
        None,
    )
    status = incident.get("status", "Unknown")
    recap = last_assistant or "We had started looking at this incident."

    next_step = ""
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
                    f"\n\n**Next recommended step:** {action['label']} — "
                    f"_{action['hint']}_"
                )
    elif is_playbook_complete(incident):
        next_step = f"\n\n{format_playbook_complete_message(incident)}"

    if db.is_incident_acknowledged(incident_id):
        if is_playbook_complete(incident):
            footer = "Use the documentation buttons below or ask me what to do next."
        else:
            footer = "You can continue the response plan when ready."
    else:
        footer = "Click **Get started** when you're ready to continue the response plan."

    return (
        f"Welcome back — here is where we left off (status: **{status}**):\n\n"
        f"{recap}{next_step}\n\n"
        f"{footer}"
    )


def _append_summary_with_get_started(incident_id: int, incident: dict) -> None:
    """One combined summary + get-started gate message."""
    from sentinel_actions import append_evidence_message, append_message

    append_evidence_message(
        incident_id=incident_id,
        request_label="Initial incident analysis",
        request_kind="initial_analysis",
    )
    append_message(
        "assistant",
        f"{format_incident_summary_message(incident_id, incident)}\n\n"
        f"{format_get_started_prompt(incident)}",
    )
    st.session_state.awaiting_get_started = True


def _queue_step_guidance_if_needed(incident: dict) -> bool:
    """Phase 1 for next-step AI guidance: evidence message, then deferred LLM."""
    incident_id = incident.get("incident_id")
    if not incident_id or is_monitoring_active(incident):
        return False
    next_key = get_next_executable_recommended_step(incident)
    if not next_key or not ai_service.is_available():
        return False

    from sentinel_actions import append_evidence_message

    action = get_action(next_key)
    label = action["label"] if action else next_key
    append_evidence_message(
        incident_id=int(incident_id),
        request_label=f"Next step guidance: {label}",
        request_kind="step_guidance",
        next_action_key=next_key,
    )
    st.session_state.pending_chat_ai = {
        "kind": "step_guidance",
        "incident_id": int(incident_id),
        "next_action_key": next_key,
        "playbook_phase": get_playbook_phase(incident),
        "expert_mode": is_expert_mode(),
    }
    st.rerun()
    return True


def _step_guidance_with_spinner(incident: dict) -> str:
    """Generate next-step guidance, showing a spinner when AI is called."""
    if is_ai_busy():
        return format_chat_action_prompt(incident)
    if _queue_step_guidance_if_needed(incident):
        return ""
    return format_chat_action_prompt(incident)


def _append_post_playbook_message(incident: dict, prefix: str = "") -> None:
    """One assistant turn after playbook completion — guidance plus doc buttons."""
    from sentinel_actions import append_message

    body = format_playbook_complete_message(incident)
    if prefix:
        body = f"{prefix}\n\n{body}"
    append_message(
        "assistant",
        body,
    )


def _append_next_step_message(incident: dict) -> None:
    """One assistant turn: step guidance plus action buttons."""
    from sentinel_actions import append_message

    if _queue_step_guidance_if_needed(incident):
        return
    prompt = format_chat_action_prompt(incident)
    append_message(
        "assistant",
        prompt,
    )


def _append_incident_chat_bootstrap(incident_id: int, incident: dict) -> None:
    """Seed the chat thread with one appropriate opening message (first visit only)."""
    from sentinel_actions import append_message

    if db.is_incident_acknowledged(incident_id):
        st.session_state.awaiting_get_started = False
        action_keys = get_recommended_action_keys(incident_id)
        append_message(
            "assistant",
            format_plan_reveal(incident, action_keys),
        )
        _append_next_step_message(incident)
    else:
        _append_summary_with_get_started(incident_id, incident)


def ensure_playbook_chat_actions() -> None:
    """No-op — playbook actions render in the sticky action bar."""
    return


def ensure_post_playbook_chat_actions() -> None:
    """Backward-compatible alias — keeps documentation buttons visible after playbook completion."""
    ensure_playbook_chat_actions()


def process_pending_chat_ai() -> bool:
    """Run deferred LLM work after evidence was shown in chat (two-phase AI flow)."""
    pending = st.session_state.get("pending_chat_ai")
    if not pending:
        return False

    from sentinel_actions import append_message

    kind = pending.get("kind")
    incident_id = pending.get("incident_id")
    expert_mode = bool(pending.get("expert_mode", st.session_state.get("expert_mode")))

    set_ai_busy(True)
    try:
        if kind == "answer_chat":
            set_ai_status_message("Sentinel is thinking…")
            incident = get_active_incident() if incident_id else None
            history = st.session_state.get("messages", [])
            result = ai_service.answer_chat(
                pending.get("user_message", ""),
                incident_id,
                history,
                chat_scope=pending.get("chat_scope", "incident"),
                expert_mode=expert_mode,
                playbook_phase=pending.get("phase", "closed"),
                awaiting_get_started=bool(pending.get("awaiting_get_started")),
                incident=incident,
            )
            append_message("assistant", result.reply)
            if (
                pending.get("chat_scope") == "incident"
                and result.suggest_plan_update
                and result.proposed_playbook_keys
                and incident_id
                and incident
                and db.is_incident_acknowledged(incident_id)
            ):
                st.session_state.pending_plan_update = {
                    "proposed_keys": result.proposed_playbook_keys,
                    "summary": result.plan_update_summary,
                }
                append_message(
                    "assistant",
                    result.plan_update_question,
                    persist=False,
                )

        elif kind == "step_guidance" and incident_id:
            set_ai_status_message("Sentinel is preparing your next step…")
            incident_row = db.get_incident_by_id(incident_id)
            incident = build_active_incident_from_db(incident_row) if incident_row else {}
            next_key = pending.get("next_action_key")
            phase = pending.get("playbook_phase", get_playbook_phase(incident))
            ai_text = ai_service.generate_step_guidance(
                incident_id,
                incident,
                next_key,
                playbook_phase=phase,
                expert_mode=expert_mode,
            )
            prompt = ai_text or format_chat_action_prompt(incident)
            append_message("assistant", prompt)

        elif kind == "incident_report" and incident_id:
            set_ai_status_message("Sentinel is generating your incident report…")
            ai_report = ai_service.generate_incident_report(incident_id)
            incident_row = db.get_incident_by_id(incident_id)
            if not incident_row:
                append_message("assistant", "Incident not found.")
            else:
                incident = build_active_incident_from_db(incident_row)
                payload = get_draft_payload("generate_incident_report", incident)
                success, result_text = execute_incident_action(
                    incident_id,
                    "generate_incident_report",
                    payload=payload,
                    source=pending.get("source", "chat"),
                    prefetched_result=ai_report,
                )
                if not success:
                    append_message("assistant", result_text)
                else:
                    _append_action_result_message("generate_incident_report", result_text)

        elif kind == "execute_action" and incident_id:
            set_ai_status_message("Sentinel is thinking…")
            action_key = pending.get("action_key", "")
            success, result = execute_incident_action(
                incident_id,
                action_key,
                source=pending.get("source", "chat"),
            )
            if not success:
                append_message("assistant", result)
            else:
                incident_row = db.get_incident_by_id(incident_id)
                incident = (
                    build_active_incident_from_db(incident_row)
                    if incident_row
                    else (get_active_incident() or {})
                )
                result_text = format_plain_action_result(action_key, incident)
                _append_action_result_message(action_key, result_text)

        elif kind == "verify_resolution" and incident_id:
            set_ai_status_message("Sentinel is reviewing this choice…")
            action_key = pending.get("action_key", "")
            verification = ai_service.verify_resolution_action(incident_id, action_key)
            st.session_state.pending_action_verification = {
                "action_key": action_key,
                "warning": verification.warning,
                "checklist": verification.checklist,
                "confirm_label": verification.confirm_label,
                "error_detail": verification.error_detail,
            }
    finally:
        set_ai_busy(False)
        set_ai_status_message(None)

    st.session_state.pending_chat_ai = None
    return True


def process_pending_incident_chat_work() -> bool:
    """Finish deferred playbook generation and bootstrap chat messages."""
    incident_id = st.session_state.get("pending_chat_bootstrap_incident_id")
    if not incident_id or not is_generating_playbook(incident_id):
        return False

    db_row = db.get_incident_by_id(incident_id)
    if not db_row:
        st.session_state.generating_playbook_for = None
        st.session_state.pending_chat_bootstrap_incident_id = None
        return False

    incident = build_active_incident_from_db(db_row)
    set_ai_status_message("Sentinel is analyzing incident evidence…")
    set_ai_busy(True)
    try:
        run_post_investigation_ai_analysis(incident_id, incident)
    finally:
        set_ai_busy(False)
        set_ai_status_message(None)

    session_id = db.get_incident_chat_session_id(incident_id)
    if session_id and not db.session_has_messages(session_id):
        _append_incident_chat_bootstrap(incident_id, incident)

    st.session_state.generating_playbook_for = None
    st.session_state.pending_chat_bootstrap_incident_id = None
    return True


# ---------------------------------------------------------------------------
# Chat flow — open threads, handle button actions, expert draft/deploy
# ---------------------------------------------------------------------------
def resume_incident_chat(incident_id: int, *, skip_bootstrap: bool = False) -> None:
    """Resume or create the canonical investigation chat for a DB incident."""
    import chat_sessions

    db_row = _sync_incident_lifecycle(incident_id) or db.get_incident_by_id(incident_id)
    if not db_row:
        return

    session_id = db.get_or_create_incident_chat_session(incident_id)
    chat_sessions.load_chat_session(session_id)
    st.session_state.expert_drawer_history_expanded = False

    sync_recommended_actions_from_db(incident_id)
    incident = get_active_incident() or build_active_incident_from_db(db_row)
    st.session_state.playbook_phase = get_playbook_phase(incident)
    st.session_state.awaiting_get_started = not db.is_incident_acknowledged(incident_id)

    if skip_bootstrap or db.session_has_messages(session_id):
        return

    if not db.get_active_playbook_recommendation(incident_id):
        st.session_state.generating_playbook_for = incident_id
        st.session_state.pending_chat_bootstrap_incident_id = incident_id
        return

    _append_incident_chat_bootstrap(incident_id, incident)


def open_incident_chat(incident_id: int) -> None:
    """Open the canonical investigation chat for a DB incident (alias for resume)."""
    resume_incident_chat(incident_id)


def _engage_incident_plan(incident_id: int, incident: dict) -> dict:
    """Mark engagement and append plan reveal + first step messages."""
    from sentinel_actions import append_message

    if not db.is_incident_acknowledged(incident_id):
        db.acknowledge_incident(incident_id)

    existing = db.get_active_playbook_recommendation(incident_id)
    if not existing:
        set_ai_busy(True)
        try:
            with st.spinner("Sentinel is building your response plan..."):
                run_post_investigation_ai_analysis(incident_id, incident)
        finally:
            set_ai_busy(False)

    incident_row = db.get_incident_by_id(incident_id)
    if incident_row:
        st.session_state.active_incident = build_active_incident_from_db(incident_row)
    sync_recommended_actions_from_db(incident_id)
    st.session_state.playbook_phase = get_playbook_phase(st.session_state.active_incident)
    st.session_state.awaiting_get_started = False

    incident = get_active_incident() or incident
    action_keys = get_recommended_action_keys(incident_id)
    append_message("assistant", format_plan_reveal(incident, action_keys))
    _append_next_step_message(incident)
    return incident


def handle_get_started_action(message_index: int) -> bool:
    """Chat button handler — user opts into the pre-saved response plan."""
    from sentinel_actions import append_user_choice, consume_message_actions

    incident = get_active_incident()
    if not incident or not incident.get("incident_id"):
        return False

    consume_message_actions(message_index)
    append_user_choice("Get started")
    _engage_incident_plan(incident["incident_id"], incident)
    return True


def handle_plan_update_action(action_key: str) -> bool:
    """Apply or decline an AI-offered playbook revision from sticky bar or chat."""
    from sentinel_actions import append_message, append_user_choice

    if action_key not in PLAN_UPDATE_ACTIONS:
        return False

    incident = get_active_incident()
    if not incident or not incident.get("incident_id"):
        return False

    plan_update = st.session_state.get("pending_plan_update")
    if not plan_update:
        return False

    incident_id = incident["incident_id"]
    st.session_state.pending_plan_update = None

    if action_key == DECLINE_PLAN_UPDATE_ACTION:
        append_user_choice("No, keep current plan")
        updated = get_active_incident() or incident
        if db.is_incident_acknowledged(incident_id) and not is_playbook_complete(updated):
            prompt = _step_guidance_with_spinner(updated)
            append_message(
                "assistant",
                "No problem — we'll keep the current response plan.\n\n"
                f"{prompt}",
            )
        else:
            append_message(
                "assistant",
                "No problem — we'll keep the current response plan.",
            )
        return True

    append_user_choice("Yes, update the plan")
    summary = plan_update.get("summary", "Updated based on your question.")
    proposed = plan_update.get("proposed_keys", [])
    apply_playbook_update(incident_id, incident, proposed, summary)
    updated = get_active_incident() or incident
    action_keys = get_recommended_action_keys(incident_id)

    append_message(
        "assistant",
        f"Done. I updated your response plan: _{summary}_\n\n"
        f"{format_plan_reveal(updated, action_keys)}",
    )
    if not is_playbook_complete(updated) and get_playbook_phase(updated) != "closed":
        _append_next_step_message(updated)
    return True


def handle_chat_action(action_key: str, message_index: int) -> bool:
    """Legacy inline chat buttons — delegates to sticky handler."""
    _ = message_index
    return handle_sticky_action(action_key)


def handle_expert_chat_action(action_key: str, message_index: int) -> bool:
    """Expert mode: show editable draft form for playbook steps; sticky for plan/update."""
    from sentinel_actions import append_message, append_user_choice, consume_message_actions

    if action_key in PLAN_UPDATE_ACTIONS or action_key == GET_STARTED_ACTION:
        return handle_sticky_action(action_key)

    if action_key in VERIFICATION_ACTIONS:
        return handle_sticky_action(action_key)

    if action_key in RESOLUTION_SHORTCUT_KEYS:
        return handle_sticky_action(action_key)

    incident = get_active_incident()
    if not incident:
        return False

    consume_message_actions(message_index)
    action = get_action(action_key)
    if not action:
        return False

    append_user_choice(action["label"])
    append_message(
        "assistant",
        f"I've drafted the **{action['label']}** parameters below. "
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
        "Investigation steps ran automatically. Sentinel is analyzing the evidence next."
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
        "Automated investigation is complete. Open **Sentinel Chat** from the incident page when you're ready to review the summary."
    )


def _pick_incident_key(scan_key: str) -> str:
    """Choose next scenario from pool (random or round-robin)."""
    pool = SCAN_INCIDENT_POOL[scan_key]
    if st.session_state.scan_mode_random:
        return random.choice(pool)
    index = st.session_state.scan_rotation[scan_key]
    st.session_state.scan_rotation[scan_key] = index + 1
    return pool[index % len(pool)]


def run_incident_recheck(incident_id: int, update_id: int) -> ai_service.UpdateAnalysisResult:
    """Re-run simulated investigation after an incident update alert is opened."""
    update_row = db.get_incident_update_by_id(update_id)
    if not update_row:
        return ai_service.UpdateAnalysisResult(
            summary="Incident update not found.",
            success=False,
            error_detail="Update record not found.",
        )

    db.acknowledge_incident_update(update_id)

    row = db.get_incident_by_id(incident_id)
    if not row:
        return ai_service.UpdateAnalysisResult(
            summary=update_row.get("summary_text", "Incident update received."),
            success=False,
            error_detail="Incident not found in database.",
        )

    incident = build_active_incident_from_db(row)
    fp_summary, sweep_summary = simulate_investigation_summaries(incident)
    db.insert_incident_action(
        incident_id,
        "fingerprint_device",
        "investigation",
        f"Re-check: {fp_summary}",
        is_automated=1,
    )
    db.insert_incident_action(
        incident_id,
        "ping_sweep",
        "investigation",
        f"Re-check: {sweep_summary}",
        is_automated=1,
    )
    hours = get_monitoring_narrative_hours(incident_id)
    review_payload = get_draft_payload("monitoring_review", incident)
    review_payload["window_hours"] = hours
    db.insert_incident_action(
        incident_id,
        "monitoring_review",
        "investigation",
        format_action_result("monitoring_review", incident, review_payload),
        payload=review_payload,
        is_automated=1,
    )

    return ai_service.analyze_incident_update(incident_id, update_row)


def open_incident_update(incident_id: int, update_id: int) -> None:
    """Open chat for a pending incident update — re-scan, summarize, offer next steps."""
    from sentinel_actions import append_evidence_message, append_message, bump_notifications_revision

    clear_sticky_pending_states()
    update_row = db.get_incident_update_by_id(update_id)
    resume_incident_chat(incident_id, skip_bootstrap=True)

    incident = get_active_incident()
    if not incident:
        db_row = db.get_incident_by_id(incident_id)
        if not db_row:
            return
        incident = build_active_incident_from_db(db_row)

    set_ai_busy(True)
    try:
        with st.spinner("Sentinel is re-checking your network and analyzing the update..."):
            result = run_incident_recheck(incident_id, update_id)
    finally:
        set_ai_busy(False)

    device = incident.get("device_name") or incident.get("source", "the device")
    updated_row = db.get_incident_by_id(incident_id)
    if updated_row:
        incident = build_active_incident_from_db(updated_row)
        st.session_state.active_incident = incident
        st.session_state.playbook_phase = get_playbook_phase(incident)

    update_title = (update_row or {}).get("title", "Incident update")
    update_summary = (update_row or {}).get("summary_text", "")

    opener_parts = [
        f"**{update_title}** ({device})",
        update_summary,
    ]
    if result.success and result.summary:
        opener_parts.append(result.summary)
    elif result.error_detail:
        opener_parts.append(f"_{ai_service.format_ai_error_message('Update analysis')}_\n\n{result.error_detail}")

    next_key = get_next_executable_recommended_step(incident)
    if result.next_step_narrative:
        opener_parts.append(result.next_step_narrative)
    elif next_key:
        opener_parts.append(format_chat_action_prompt(incident))
    else:
        opener_parts.append("Review the action bar below for your next step.")

    opener_parts.append("I re-checked your network context for this device.")
    opener = "\n\n".join(part for part in opener_parts if part)

    append_evidence_message(
        incident_id=incident_id,
        request_label="Incident update re-check",
        request_kind="update_recheck",
        update_row=update_row,
    )
    append_message("assistant", opener, persist=True)

    if result.suggest_plan_update and result.playbook_action_keys and result.plan_update_summary:
        st.session_state.pending_plan_update = {
            "proposed_keys": result.playbook_action_keys,
            "summary": result.plan_update_summary,
        }
        append_message(
            "assistant",
            f"**Should I update your response plan?** {result.plan_update_summary}",
            persist=True,
        )

    bump_notifications_revision()


# ---------------------------------------------------------------------------
# Scan trigger — create DB incident, seed session, append chat narrative
# ---------------------------------------------------------------------------
def trigger_scan(scan_key: str):
    """Run a demo scan: pick scenario, persist incident, pre-generate AI plan."""
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
    incident["device_name"] = str(device_row["device_name"]) if device_row is not None else incident.get("source", "Unknown device")
    incident["status"] = "Active"
    st.session_state.active_incident = incident
    st.session_state.active_incident_id = db_incident_id
    st.session_state.playbook_phase = "awaiting_ack"
    st.session_state.recommended_action_keys = []
    st.session_state.recommended_action_incident_id = None
    st.session_state.awaiting_get_started = False

    set_ai_busy(True)
    try:
        with st.spinner("Sentinel is analyzing incident evidence..."):
            result = run_post_investigation_ai_analysis(db_incident_id, incident)
    finally:
        set_ai_busy(False)

    from sentinel_actions import bump_incidents_table_revision

    bump_incidents_table_revision()

    if not result.success:
        st.session_state.scan_error_notice = (
            f"Alert created: **{incident['title']}** — but Sentinel could not build an AI response plan.\n\n"
            f"{result.error_detail or ai_service.format_ai_error_message()}"
        )
        st.session_state.scan_complete_notice = None
    else:
        st.session_state.scan_complete_notice = (
            f"Alert created: **{incident['title']}** — open it from **Alerts** to review."
        )
        st.session_state.scan_error_notice = None

    if is_expert_mode():
        st.session_state.expert_incident_id = db_incident_id
        st.session_state.expert_view = "incident_detail"
    else:
        st.session_state.active_session_id = None
        st.session_state.active_incident_id = None
        st.session_state.active_incident = None
        st.session_state.messages = []


def sync_incident_chat():
    """No-op — chat prompts are appended explicitly after actions."""
    return


# Backward compatibility exports (legacy code may import PLAYBOOKS)
# Static per-scenario playbooks were removed in favor of AI-generated recommendations.
PLAYBOOKS = {}
