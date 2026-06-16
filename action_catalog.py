"""Central registry of incident response actions and playbook generation.

**Catalog architecture (read this first):**

Every response step in the prototype is identified by a stable string key
(e.g. ``isolate_device``). Metadata for that key lives in ``ACTIONS``. The
playbook engine in ``incident_scenarios`` never hard-codes labels or categories;
it always looks up keys here.

::

    action_key  →  ACTIONS[key]  →  category, labels, hints, expert_params
                 ↘  SCENARIO_STEP_PROMPTS[scenario][key]  →  chat nudge copy
                 ↘  get_draft_payload(key, incident)      →  expert form defaults
                 ↘  format_action_result(key, ...)       →  simulated outcome text

**Category lifecycle (IR phases):**

1. ``investigation`` — auto-run on incident create (fingerprint, ping sweep);
   never offered as user buttons.
2. ``containment`` — stop spread (isolate, block, sever, etc.).
3. ``eradication`` — remove threat or resolve benign cases (trust, wipe, patch).
4. ``post_incident`` — documentation and authority handoff (reports, forensics).

``incident_scenarios.get_playbook_phase`` derives the active phase by checking
which category still has incomplete *recommended* steps. Derived sets
(``CONTAINMENT_KEYS``, etc.) are built from ``ACTIONS`` at import time.

**Playbook content vs. catalog content:**

- ``ACTIONS`` defines *what can exist*.
- AI analysis (``ai_service.analyze_incident``) chooses an ordered subset of
  keys per incident and persists it to ``playbook_recommendations``.
- ``SCENARIO_STEP_PROMPTS`` supplies fallback chat copy when AI step guidance
  is unavailable — keyed by scenario id, not DB title.
- ``DB_INCIDENT_SCENARIO_MAP`` bridges seeded DB titles → scenario ids.

**Simulation only:** ``format_action_result`` and friends return plausible
strings; no packets are sent, no hosts are isolated. Expert ``expert_params``
exist purely to populate Streamlit forms.

**Consumers:** ``incident_scenarios.py``, expert UI forms, ``db.py`` (action
keys in ``incident_actions``), ``temporal_state.py`` (blocked key subset).
"""

from __future__ import annotations

import json
from typing import Any

# Valid action categories; tuple order mirrors typical IR lifecycle for docs/UI.
# incident_scenarios phase strings align with containment → eradication → post_incident.
ACTION_CATEGORIES = ("investigation", "containment", "eradication", "post_incident")

# ---------------------------------------------------------------------------
# ACTIONS — master registry keyed by stable action id
# ---------------------------------------------------------------------------
# Each entry defines:
#   category          — investigation | containment | eradication | post_incident
#   label / plain_label — expert vs standard UI strings
#   hint / plain_hint — short descriptions for tooltips and chat
#   expert_params     — form field names shown in expert draft UI
#   resolution_status — if set, executing this action closes the incident
ACTIONS: dict[str, dict[str, Any]] = {
    "fingerprint_device": {
        "category": "investigation",
        "label": "Fingerprint Device",
        "plain_label": "Identify the device",
        "hint": "Gather OS, ports, and services metadata",
        "plain_hint": "Learn exactly what this device is and what it is running",
        "description": "Gathering technical metadata from a specific endpoint.",
        "expert_params": ["target_ip", "target_mac"],
        "resolution_status": None,
    },
    "ping_sweep": {
        "category": "investigation",
        "label": "Ping Sweep",
        "plain_label": "Map nearby devices",
        "hint": "Identify active hosts on the subnet",
        "plain_hint": "See what else is on the network around this device",
        "description": "Sending ICMP echo requests across a target subnet to identify active hosts.",
        "expert_params": ["subnet", "timeout_seconds"],
        "resolution_status": None,
    },
    "monitoring_review": {
        "category": "investigation",
        "label": "Monitoring Review",
        "plain_label": "Review watch-window telemetry",
        "hint": "Analyze telemetry collected during the monitoring window",
        "plain_hint": "Check what happened on this device during the watch period",
        "description": "Reviewing telemetry and events collected during an enhanced monitoring window.",
        "expert_params": ["device_name", "window_hours"],
        "resolution_status": None,
    },
    "sever_connection": {
        "category": "containment",
        "label": "Sever Connection",
        "plain_label": "Stop the connection",
        "hint": "Terminate active sessions to the threat",
        "plain_hint": "Stop the connection that is sending or receiving dangerous traffic",
        "description": "Forcibly terminating active network sessions to and from the compromised device.",
        "expert_params": ["target_ip", "protocol", "reset_packets"],
        "resolution_status": None,
    },
    "isolate_device": {
        "category": "containment",
        "label": "Isolate Device",
        "plain_label": "Take the device offline",
        "hint": "Quarantine the host",
        "plain_hint": "Take that device off the network so it cannot spread",
        "description": "Placing the endpoint in a restricted quarantine state.",
        "expert_params": ["target_mac", "allow_management"],
        "resolution_status": None,
    },
    "perm_block": {
        "category": "containment",
        "label": "Perm Block",
        "plain_label": "Block that outside address",
        "hint": "Blacklist malicious indicator",
        "plain_hint": "Block that address so it cannot connect again",
        "description": "Permanently adding malicious indicators to deny lists.",
        "expert_params": ["target_ip", "direction", "action", "timeout"],
        "resolution_status": None,
    },
    "port_lockdown": {
        "category": "containment",
        "label": "Port Lockdown",
        "plain_label": "Close the open door",
        "hint": "Restrict traffic on specific ports",
        "plain_hint": "Close the way the attacker is getting in",
        "description": "Restricting traffic on specific network ports.",
        "expert_params": ["target_ip", "port", "protocol"],
        "resolution_status": None,
    },
    "throttle_connection": {
        "category": "containment",
        "label": "Throttle Connection",
        "plain_label": "Slow the connection",
        "hint": "Limit bandwidth to slow exfiltration",
        "plain_hint": "Slow down suspicious traffic without fully disconnecting",
        "description": "Severely limiting network bandwidth available to a specific device.",
        "expert_params": ["target_ip", "max_kbps", "duration_hours"],
        "resolution_status": None,
    },
    "dns_sinkhole": {
        "category": "containment",
        "label": "DNS Sinkhole",
        "plain_label": "Block malicious domains",
        "hint": "Reroute malicious DNS to a dead-end",
        "plain_hint": "Stop malware from reaching its command servers",
        "description": "Rerouting DNS requests for known malicious domains to an internal sinkhole.",
        "expert_params": ["domain", "sinkhole_ip"],
        "resolution_status": None,
    },
    "trust_device": {
        "category": "eradication",
        "label": "Trust Device",
        "plain_label": "Trust it for now",
        "hint": "Reverse containment and whitelist behavior",
        "plain_hint": "Mark this device as okay and return it to normal use",
        "description": "Reversing containment actions and whitelisting standard behaviors.",
        "expert_params": ["device_name", "snooze_hours"],
        "resolution_status": "Trusted",
    },
    "prompt_offline_scan": {
        "category": "eradication",
        "label": "Prompt Offline Scan",
        "plain_label": "Schedule a deep scan",
        "hint": "Force deep scan and 24–48h monitoring",
        "plain_hint": "Watch this device closely for the next day or two",
        "description": "Scheduling intensive monitoring and offline scan of the device.",
        "expert_params": ["device_name", "monitor_hours"],
        "resolution_status": None,
    },
    "require_credential_rotation": {
        "category": "eradication",
        "label": "Require Credential Rotation",
        "plain_label": "Reset passwords",
        "hint": "Force password resets and revoke sessions",
        "plain_hint": "Change passwords so stolen credentials no longer work",
        "description": "Forcing password resets and revoking active session tokens.",
        "expert_params": ["affected_users", "revoke_sessions"],
        "resolution_status": "Mitigated",
    },
    "mark_false_positive": {
        "category": "eradication",
        "label": "Mark False Positive",
        "plain_label": "Mark as false alarm",
        "hint": "Tag alert as benign",
        "plain_hint": "This was normal activity, not a real threat",
        "description": "Tagging the alert as benign and tuning detection rules.",
        "expert_params": ["reason", "suppress_hours"],
        "resolution_status": "False Positive",
    },
    "reimage_wipe_device": {
        "category": "eradication",
        "label": "Reimage/Wipe Device",
        "plain_label": "Wipe and reinstall",
        "hint": "Erase and reinstall from clean baseline",
        "plain_hint": "Completely wipe the device and reinstall from scratch",
        "description": "Completely erasing the hard drive and reinstalling the OS.",
        "expert_params": ["target_mac", "backup_required"],
        "resolution_status": "Mitigated",
    },
    "patch_remediate": {
        "category": "eradication",
        "label": "Patch/Remediate Vulnerability",
        "plain_label": "Fix the vulnerability",
        "hint": "Apply updates to close the attack vector",
        "plain_hint": "Install updates so the same attack cannot work again",
        "description": "Applying software updates or configuration changes to fix the exploit.",
        "expert_params": ["cve_id", "patch_notes"],
        "resolution_status": "Mitigated",
    },
    "generate_incident_report": {
        "category": "post_incident",
        "label": "Generate Incident Report",
        "plain_label": "Save a summary report",
        "hint": "Document timeline, scope, and root cause",
        "plain_hint": "Write up what happened and what we did",
        "description": "Creating a formalized incident document.",
        "expert_params": ["title", "include_timeline", "notes"],
        "resolution_status": None,
    },
    "freeze_incident_state": {
        "category": "post_incident",
        "label": "Freeze Incident State",
        "plain_label": "Preserve evidence",
        "hint": "Lock snapshots and log retention",
        "plain_hint": "Lock everything in place for legal or audit purposes",
        "description": "Taking snapshots and locking log retention for chain of custody.",
        "expert_params": ["retention_days", "include_memory_dump"],
        "resolution_status": None,
    },
    "export_raw_forensics": {
        "category": "post_incident",
        "label": "Export Raw Forensics",
        "plain_label": "Export forensic data",
        "hint": "Extract logs, dumps, and traffic captures",
        "plain_hint": "Download the raw technical evidence",
        "description": "Extracting unprocessed logs, memory dumps, and traffic captures.",
        "expert_params": ["format", "include_network_captures"],
        "resolution_status": None,
    },
    "export_police_packet": {
        "category": "post_incident",
        "label": "Export Police Packet",
        "plain_label": "Prepare police report package",
        "hint": "Bundle report, forensics, and talking points",
        "plain_hint": "Get everything ready to share with law enforcement",
        "description": "Bundling incident report and forensic evidence for law enforcement.",
        "expert_params": ["agency_contact", "include_talking_points"],
        "resolution_status": None,
    },
    "skip_to_documentation": {
        "category": "post_incident",
        "label": "Skip to Documentation",
        "plain_label": "Skip to documentation",
        "hint": "Skip remaining containment/eradication and document the incident",
        "plain_hint": "Skip the rest of the response steps and move to writing the report",
        "description": "User chose to skip remaining response steps and proceed to documentation.",
        "expert_params": [],
        "resolution_status": None,
    },
}

# ---------------------------------------------------------------------------
# ACTION_ALIASES — legacy UI / demo keys → canonical ACTIONS keys
# ---------------------------------------------------------------------------
# normalize_action_key() is called at every execution boundary so old saved
# data and RESPONSE_RESPONSES keys still resolve.
ACTION_ALIASES = {
    "permanent_block": "perm_block",
    "trust_snooze": "trust_device",
    "incident_report": "generate_incident_report",
}

# ---------------------------------------------------------------------------
# DB_INCIDENT_SCENARIO_MAP — seed/scan titles → incident_scenarios.INCIDENTS keys
# ---------------------------------------------------------------------------
# Used by scenario_key_for_title() when hydrating DB rows. Unknown titles fall
# back to low_risk_anomaly so the app never crashes on a missing mapping.
DB_INCIDENT_SCENARIO_MAP = {
    "Command and Control Traffic": "command_and_control",
    "Repeated Unauthorized Login Attempts": "brute_force",
    "Suspicious Outbound Traffic Surge": "exfiltration",
    "Unrecognized Device Activity": "low_risk_anomaly",
    "Ransomware Staging Detected": "ransomware_beacon",
    "Internal Lateral Movement": "lateral_scanning",
}

# ---------------------------------------------------------------------------
# SCENARIO_STEP_PROMPTS — per-scenario chat nudges before each playbook step
# ---------------------------------------------------------------------------
# Nested dict: scenario_key → action_key → assistant message string.
# incident_scenarios.format_chat_action_prompt prefers AI-generated guidance;
# these templates are the offline fallback. Not every action needs an entry.
SCENARIO_STEP_PROMPTS: dict[str, dict[str, str]] = {
    "exfiltration": {
        "sever_connection": "First, stop the active data transfer to the outside address.",
        "isolate_device": "Connection stopped. Next, take the workstation offline to prevent further spread.",
        "perm_block": "Device isolated. Block the exfil endpoint permanently.",
        "prompt_offline_scan": "Block in place. Schedule enhanced monitoring before reconnecting.",
        "generate_incident_report": (
            "Monitoring completed with no new threats. "
            "Generate the incident report to close out response."
        ),
    },
    "brute_force": {
        "port_lockdown": "Close the open door the attacker is using to reach your smart lock.",
        "perm_block": "Port lockdown is in place. Next, block the outside address permanently.",
        "require_credential_rotation": "Outside address blocked. Reset passwords so stolen credentials no longer work.",
    },
    "lateral_scanning": {
        "isolate_device": "First, take the scanning device offline so it cannot reach other hosts.",
        "perm_block": "Device isolated. Block the scanner's address permanently.",
        "prompt_offline_scan": "Block in place. Schedule a deep scan and monitoring window before reconnecting.",
        "generate_incident_report": (
            "Monitoring completed with no new threats. "
            "Generate the incident report to document response."
        ),
    },
    "low_risk_anomaly": {
        "prompt_offline_scan": "This looks low risk for now. I recommend watching the device closely for a day or two.",
        "trust_device": (
            "Monitoring completed with no new alerts. "
            "If you're comfortable, mark the device as trusted."
        ),
    },
    "ransomware_beacon": {
        "sever_connection": "First, sever the outbound staging connection immediately.",
        "isolate_device": "Connection severed. Quarantine the workstation before encryption spreads.",
        "dns_sinkhole": "Device isolated. Block command-and-control domains at DNS.",
        "reimage_wipe_device": "C2 blocked. Wipe and reinstall the workstation from a clean baseline.",
        "generate_incident_report": "Device remediated. Generate the incident report for records and authority review.",
    },
    "command_and_control": {
        "dns_sinkhole": "First, sinkhole the malicious domains the gateway is calling out to.",
        "perm_block": "DNS sinkhole active. Block the outside command server address permanently.",
        "isolate_device": "C2 address blocked. Quarantine the gateway to stop further callbacks.",
        "patch_remediate": "Gateway isolated. Patch the vulnerability that allowed remote control.",
        "generate_incident_report": "Patch applied. Generate the incident report to document response and evidence.",
    },
}

# ---------------------------------------------------------------------------
# Monitoring waiting copy — shown while temporal_state.is_monitoring_active
# ---------------------------------------------------------------------------
# Placeholders: {device}, {narrative_hours}, {remaining}. Scenario-specific
# tone where defined; DEFAULT_MONITORING_WAITING_PROMPT covers the rest.
SCENARIO_MONITORING_WAITING_PROMPTS: dict[str, str] = {
    "low_risk_anomaly": (
        "Enhanced monitoring is running on **{device}** ({narrative_hours}h watch). "
        "I'll alert you in **Alerts** when the window completes so we can decide whether to trust the device. "
        "Demo unlock in **{remaining}** — no action needed right now."
    ),
    "exfiltration": (
        "**{device}** is under enhanced monitoring ({narrative_hours}h watch) before we close this case. "
        "I'll notify you when the window ends. Demo unlock in **{remaining}**."
    ),
    "lateral_scanning": (
        "Deep scan and monitoring are active for **{device}** ({narrative_hours}h watch). "
        "I'll alert you when we can proceed to documentation. Demo unlock in **{remaining}**."
    ),
}
DEFAULT_MONITORING_WAITING_PROMPT = (
    "Enhanced monitoring is running on **{device}** ({narrative_hours}h watch). "
    "I'll alert you when the window completes. Demo unlock in **{remaining}**."
)

# ---------------------------------------------------------------------------
# Derived category sets — rebuilt from ACTIONS whenever this module loads
# ---------------------------------------------------------------------------
# incident_scenarios uses these for get_playbook_phase, can_execute_action,
# and recommended_steps_in_category filtering (preserves playbook order).
CONTAINMENT_KEYS = {k for k, v in ACTIONS.items() if v["category"] == "containment"}
ERADICATION_KEYS = {k for k, v in ACTIONS.items() if v["category"] == "eradication"}
POST_INCIDENT_KEYS = {k for k, v in ACTIONS.items() if v["category"] == "post_incident"}

# Chat button order after the *recommended* playbook is complete (documentation).
# Expert mode exposes forensics/freeze; standard mode shows a shorter subset.
POST_INCIDENT_CHAT_ORDER = (
    "freeze_incident_state",
    "export_raw_forensics",
    "generate_incident_report",
    "export_police_packet",
)
STANDARD_POST_INCIDENT_CHAT_ORDER = (
    "generate_incident_report",
    "export_police_packet",
)
# Investigation keys — auto-run only; blocked from user-triggered execution.
INVESTIGATION_KEYS = {k for k, v in ACTIONS.items() if v["category"] == "investigation"}
# Resolution keys — executing one sets incident status via resolution_status field.
RESOLUTION_KEYS = {k for k, v in ACTIONS.items() if v.get("resolution_status")}


def _c2_domain_for_scenario(scenario_key: str | None) -> str:
    """Return a plausible malicious domain for DNS sinkhole draft payloads.

    Scenario-specific domains make expert forms feel grounded. Unknown scenarios
    get a generic placeholder — still valid for the simulated sinkhole result.
    """
    domains = {
        "command_and_control": "update-cdn.evilcorp.net",
        "ransomware_beacon": "paygate-locker.onion.link",
    }
    return domains.get(scenario_key or "", "malware-c2.example")


def normalize_action_key(action_key: str) -> str:
    """Resolve legacy alias to canonical ACTIONS key.

    Always call this at execution boundaries — chat buttons, sticky bar, DB
    lookups, and expert deploy may still emit pre-refactor key names.
    """
    return ACTION_ALIASES.get(action_key, action_key)


def get_action(action_key: str) -> dict[str, Any] | None:
    """Look up action metadata by key (aliases supported).

    Returns None for unknown keys — callers should treat that as "not runnable".
    """
    return ACTIONS.get(normalize_action_key(action_key))


def get_actions_by_category(category: str) -> list[tuple[str, dict[str, Any]]]:
    """Return all (key, metadata) pairs for a given category.

    Used by expert palette UIs to list containment/eradication tools. Order
    follows insertion order in ACTIONS (stable in Python 3.7+).
    """
    return [(k, v) for k, v in ACTIONS.items() if v["category"] == category]


def scenario_key_for_title(title: str) -> str:
    """Map a DB incident title to a scenario key; default to low_risk_anomaly.

    Scan-created incidents use titles from INCIDENTS; seeded rows use longer
    titles from seed.py — both paths must resolve to the same scenario id.
    """
    return DB_INCIDENT_SCENARIO_MAP.get(title, "low_risk_anomaly")


def playbook_recommendation_text(incident: dict, action_keys: list[str]) -> str:
    """One-line summary: incident title plus arrow-separated action labels.

    Persisted to playbook_recommendations.recommendation_text and shown in
    expert incident detail before the user opens chat.
    """
    labels = [get_action(k)["label"] for k in action_keys if get_action(k)]
    joined = " → ".join(labels)
    return f"Recommended response for **{incident.get('title', 'this incident')}**: {joined}."


def get_scenario_step_prompt(scenario_key: str, action_key: str) -> str | None:
    """Return scenario-specific chat copy for the next playbook step, if defined.

    None means incident_scenarios should fall back to generic "Next step: …" copy
    or AI-generated guidance from ai_service.generate_step_guidance.
    """
    action_key = normalize_action_key(action_key)
    return SCENARIO_STEP_PROMPTS.get(scenario_key, {}).get(action_key)


def recommended_steps_in_category(recommended: list[str], category_keys: set[str]) -> list[str]:
    """Filter a playbook order list to one IR category, preserving order.

    Critical for phase detection: containment phase = first incomplete key in
    recommended ∩ CONTAINMENT_KEYS, not "any containment action in ACTIONS".
    """
    return [k for k in recommended if k in category_keys]


def get_draft_payload(action_key: str, incident: dict) -> dict:
    """Build default expert-form parameter values from incident context.

    Pulls indicator, source device, MAC, and IP from the incident dict so
    draft forms are pre-filled with realistic demo values. execute_incident_action
    uses the same defaults when payload is omitted (chat / sticky bar path).
    """
    action_key = normalize_action_key(action_key)
    indicator = incident.get("indicator") or incident.get("primary_indicator") or incident.get("internal_ip", "")
    source = incident.get("source") or incident.get("device_name", "Unknown")
    mac = incident.get("source_mac") or incident.get("mac_address", "00:00:00:00:00:00")
    ip = incident.get("internal_ip") or indicator

    payloads: dict[str, dict] = {
        "perm_block": {
            "target_ip": indicator,
            "direction": "Both",
            "action": "DROP",
            "timeout": 0,
        },
        "isolate_device": {"target_mac": mac, "allow_management": True},
        "sever_connection": {"target_ip": indicator, "protocol": "TCP", "reset_packets": True},
        "port_lockdown": {
            "target_ip": ip or indicator,
            "port": 22 if incident.get("key") == "brute_force" else 443,
            "protocol": "TCP",
        },
        "throttle_connection": {"target_ip": ip, "max_kbps": 64, "duration_hours": 4},
        "dns_sinkhole": {
            "domain": _c2_domain_for_scenario(incident.get("key")),
            "sinkhole_ip": "127.0.0.1",
        },
        "trust_device": {"device_name": source, "snooze_hours": 24},
        "prompt_offline_scan": {"device_name": source, "monitor_hours": 36},
        "require_credential_rotation": {"affected_users": incident.get("owner_name", "Admin"), "revoke_sessions": True},
        "mark_false_positive": {"reason": "Legitimate business activity", "suppress_hours": 72},
        "reimage_wipe_device": {"target_mac": mac, "backup_required": True},
        "patch_remediate": {"cve_id": "CVE-2026-0001", "patch_notes": "Apply latest security update"},
        "generate_incident_report": {
            "title": f"{incident.get('title', 'Incident')} — Response Summary",
            "include_timeline": True,
            "notes": incident.get("description", ""),
        },
        "freeze_incident_state": {"retention_days": 90, "include_memory_dump": True},
        "export_raw_forensics": {"format": "ZIP", "include_network_captures": True},
        "export_police_packet": {"agency_contact": "Local cyber crimes unit", "include_talking_points": True},
        "fingerprint_device": {"target_ip": ip, "target_mac": mac},
        "ping_sweep": {"subnet": "192.168.1.0/24", "timeout_seconds": 2},
        "monitoring_review": {
            "device_name": source,
            "window_hours": 36,
        },
    }
    return payloads.get(action_key, {})


# ---------------------------------------------------------------------------
# Formatters — simulated action result strings for chat and expert UI
# ---------------------------------------------------------------------------
def format_action_result(action_key: str, incident: dict, payload: dict | None = None) -> str:
    """Return expert-style result text after an action executes (prototype simulation).

    Each branch formats a distinct sentence so chat and expert deploy feedback
    feel action-specific. Unknown keys degrade to "{label} completed for {source}."
    """
    action_key = normalize_action_key(action_key)
    payload = payload or {}
    action = get_action(action_key)
    if not action:
        return f"Action {action_key} completed."

    source = incident.get("source") or incident.get("device_name", "the device")
    indicator = incident.get("indicator") or incident.get("primary_indicator", "unknown")

    if action_key == "fingerprint_device":
        return (
            f"Fingerprint complete for **{source}** — "
            f"OS/services cataloged; open ports and running services recorded."
        )
    if action_key == "ping_sweep":
        subnet = payload.get("subnet", "192.168.1.0/24")
        return f"Ping sweep complete on `{subnet}` — active hosts mapped for blast-radius analysis."
    if action_key == "monitoring_review":
        hours = payload.get("window_hours", 36)
        return (
            f"Monitoring review complete for **{source}** — "
            f"{hours}h watch-window telemetry shows no new suspicious activity."
        )
    if action_key == "sever_connection":
        return f"Severed active sessions to `{payload.get('target_ip', indicator)}`."
    if action_key == "isolate_device":
        mgmt = "management ports retained" if payload.get("allow_management", True) else "full isolation"
        return f"Quarantined **{source}** ({mgmt})."
    if action_key == "perm_block":
        return f"Permanent block applied for `{payload.get('target_ip', indicator)}`."
    if action_key == "port_lockdown":
        return f"Closed {payload.get('protocol', 'TCP')} port {payload.get('port', 443)} on `{payload.get('target_ip', ip_fallback(incident))}`."
    if action_key == "throttle_connection":
        return f"Throttled **{source}** to {payload.get('max_kbps', 64)} kbps for {payload.get('duration_hours', 4)}h."
    if action_key == "dns_sinkhole":
        return f"DNS sinkhole active for `{payload.get('domain', 'malware-c2.example')}`."
    if action_key == "trust_device":
        return f"**{source}** marked trusted; containment reversed."
    if action_key == "prompt_offline_scan":
        hours = payload.get("monitor_hours", 36)
        return f"Enhanced monitoring scheduled for **{source}** ({hours}h window)."
    if action_key == "require_credential_rotation":
        return f"Credential rotation enforced for `{payload.get('affected_users', 'affected users')}`."
    if action_key == "mark_false_positive":
        return f"Alert marked false positive: _{payload.get('reason', 'benign activity')}_."
    if action_key == "reimage_wipe_device":
        return f"Reimage initiated for **{source}** from clean baseline."
    if action_key == "patch_remediate":
        return f"Patch `{payload.get('cve_id', 'CVE')}` scheduled for **{source}**."
    if action_key == "generate_incident_report":
        return f"Incident report **{payload.get('title', incident.get('title', 'Report'))}** generated."
    if action_key == "freeze_incident_state":
        return f"Incident state frozen — evidence retained for {payload.get('retention_days', 90)} days."
    if action_key == "export_raw_forensics":
        return "Raw forensic bundle prepared (logs, memory metadata, network captures)."
    if action_key == "export_police_packet":
        return (
            "Police packet prepared.\n\n"
            "**What to tell authorities:** Report unauthorized access/data exfiltration involving "
            f"**{source}** and indicator `{indicator}`. Provide the exported forensic bundle and incident timeline."
        )
    return f"{action['label']} completed for **{source}**."


def format_plain_action_result(action_key: str, incident: dict) -> str:
    """Standard-mode chat wrapper: prefixes with 'Done.' and notes status changes.

    Resolution actions (trust, false positive, wipe, etc.) append the new
    incident status so homeowners see closure in plain language.
    """
    action_key = normalize_action_key(action_key)
    payload = get_draft_payload(action_key, incident)
    text = format_action_result(action_key, incident, payload)
    if action_key in RESOLUTION_KEYS:
        status = get_action(action_key)["resolution_status"]
        return f"Done. {text} Incident status updated to **{status}**."
    return f"Done. {text}"


def ip_fallback(incident: dict) -> str:
    """Best-effort IP string when payload omits target_ip.

    Prefers internal_ip (LAN) over external indicator — matches how containment
    actions usually target the compromised host, not the remote C2 IP.
    """
    return incident.get("internal_ip") or incident.get("indicator") or "0.0.0.0"


# ---------------------------------------------------------------------------
# simulate_investigation_summaries — auto-run investigation copy on incident create
# ---------------------------------------------------------------------------
def simulate_investigation_summaries(incident: dict) -> tuple[str, str]:
    """Return (fingerprint_summary, ping_sweep_summary) for DB seeding.

    Called when ``db.create_incident_with_investigation`` auto-records
    fingerprint_device and ping_sweep actions.
    """
    device = incident.get("device_name") or incident.get("source", "Unknown device")
    ip = incident.get("internal_ip") or incident.get("indicator", "N/A")
    mac = incident.get("mac_address") or incident.get("source_mac", "N/A")
    dtype = incident.get("device_type", "Unknown")
    fp = (
        f"Fingerprint: {device} — {dtype}, {ip}, MAC {mac}; "
        "open ports and services cataloged."
    )
    sweep = (
        f"Ping sweep: active hosts mapped on 192.168.1.0/24; "
        f"blast radius centered on {ip}."
    )
    return fp, sweep


def actions_to_json(action_keys: list[str]) -> str:
    """Serialize playbook action key list for SQLite storage.

    Stored in playbook_recommendations.playbook_actions_json as a JSON array
    of strings preserving AI/user-defined step order.
    """
    return json.dumps(action_keys)
