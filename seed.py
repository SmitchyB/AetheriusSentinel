"""
Database seed script for Aetherius Sentinel local development.

Purpose
-------
Creates ``data/project.db`` from ``schema.sql`` and populates it with a realistic
home-network demo dataset. This is the **single entry point** for resetting local
SQLite state during development; the Dash app reads from the same tables defined
in ``schema.sql``.

What gets seeded (maps 1:1 to schema tables)
--------------------------------------------
1. ``devices``           — six home-network hosts (gateway, workstation, IoT, etc.)
2. ``incidents``         — six incidents at different lifecycle stages and severities
3. ``incident_events``   — per-scenario network telemetry (via ``scenario_telemetry``)
4. ``indicators``        — IOC rows (IP/host metadata per scenario)
5. ``incident_indicators`` — junction linking each incident to exactly one indicator
6. ``recommendations``   — AI playbooks, authority notices, and general tips
7. ``incident_actions``  — auto investigation + user playbook steps (via ``seed_narrative``)
8. ``chat_messages``     — general and incident-scoped chat transcripts
9. ``incident_updates``  — pending alert for incident 6 (monitoring complete demo)

Cross-module dependencies
-------------------------
- ``scenario_telemetry`` — event templates and IOC metadata for each ``scenario_key``
- ``seed_narrative``      — ``insert_investigation_actions``, ``seed_chat_session``
- ``action_catalog``       — (indirectly via seed_narrative) action labels and result text

Scenario keys used here (must match ``scenario_telemetry.SCENARIO_*`` and
``incident_scenarios`` runtime definitions):
  command_and_control | brute_force | exfiltration | low_risk_anomaly |
  ransomware_beacon | lateral_scanning

Run directly::

    python seed.py

Idempotency note: each run drops and recreates tables via ``schema.sql`` executemany,
so re-running overwrites ``data/project.db`` entirely.
"""

import json
import sqlite3
from pathlib import Path

from scenario_telemetry import get_scenario_events_with_timestamps, get_scenario_indicator
from seed_narrative import insert_investigation_actions, seed_chat_session

# ---------------------------------------------------------------------------
# Path constants — relative to project root (script must be run from repo root).
# ---------------------------------------------------------------------------

# Target SQLite file; parent ``data/`` is created if missing.
DATABASE_PATH = Path("data/project.db")

# DDL source; ``initialize_database`` reads this verbatim and executes it.
# Table order in schema.sql respects FK dependencies (children dropped first).
SCHEMA_PATH = Path("schema.sql")

# ---------------------------------------------------------------------------
# DEVICES — demo device registry
# ---------------------------------------------------------------------------
# Keys are ``device_id`` integers that become PRIMARY KEY values in
# ``devices.device_id`` (schema.sql). Incidents reference these via
# ``incidents.device_id`` FOREIGN KEY.
#
# Field mapping to ``devices`` columns:
#   device_name  -> devices.device_name
#   device_type  -> devices.device_type  (must satisfy CHECK constraint)
#   internal_ip  -> devices.internal_ip
#   mac_address  -> devices.mac_address  (UNIQUE NOT NULL)
#   owner_name   -> devices.owner_name
#
# These dicts are also merged into ``incident_ctx`` for action_catalog formatters
# and chat scripts in ``seed_narrative`` (needs source, source_mac, indicator, key).

DEVICES = {
    # device_id=1 — Primary gateway; anchor host for C2 scenario (incident_id=1).
    1: {
        "device_name": "Main Home Gateway",
        "device_type": "Gateway",  # schema CHECK: Gateway is allowed
        "internal_ip": "192.168.1.1",
        "mac_address": "00:1A:2B:3C:4D:5E",
        "owner_name": "Admin",
    },
    # device_id=2 — Primary workstation; shared by exfiltration (inc 3) and
    # ransomware_beacon (inc 5) to show one host in multiple incident timelines.
    2: {
        "device_name": "Brett's Workstation",
        "device_type": "Workstation",
        "internal_ip": "192.168.1.10",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "owner_name": "Brett Smitch",
    },
    # device_id=3 — Media device; lateral_scanning scenario (incident_id=6).
    3: {
        "device_name": "Living Room Roku",
        "device_type": "Media",
        "internal_ip": "192.168.1.15",
        "mac_address": "11:22:33:44:55:66",
        "owner_name": "Shared",
    },
    # device_id=4 — IoT smart lock; brute_force scenario (incident_id=2).
    4: {
        "device_name": "Front Door Smart Lock",
        "device_type": "IoT",
        "internal_ip": "192.168.1.20",
        "mac_address": "77:88:99:AA:BB:CC",
        "owner_name": "Admin",
    },
    # device_id=5 — Console; present for network realism, not tied to a seeded incident.
    5: {
        "device_name": "PlayStation 5",
        "device_type": "Console",
        "internal_ip": "192.168.1.25",
        "mac_address": "DD:EE:FF:00:11:22",
        "owner_name": "Brett Smitch",
    },
    # device_id=6 — Unrecognized guest IoT; low_risk_anomaly scenario (incident_id=4).
    6: {
        "device_name": "Guest-IoT-7A2F",
        "device_type": "IoT",
        "internal_ip": "192.168.1.44",
        "mac_address": "FE:DC:BA:98:76:54",
        "owner_name": "Guest",
    },
}

# ---------------------------------------------------------------------------
# SCENARIO_INDICATORS — primary IOC per scenario_key
# ---------------------------------------------------------------------------
# Values become ``indicators.indicator_value`` after enrichment via
# ``get_scenario_indicator()`` (type, threat_actor_group, confidence_score).
# Keys must match ``scenario_telemetry.SCENARIO_EVENT_TEMPLATES`` and are
# passed to telemetry IP substitution logic (external attacker IPs / C2 hosts).
#
# Seeded 1:1 with incidents via ``incident_indicators`` (incident N -> indicator N).

SCENARIO_INDICATORS = {
    "command_and_control": "198.18.0.77",   # incident 1 — C2 endpoint (RFC 5737 test range)
    "brute_force": "203.0.113.88",            # incident 2 — attacker source IP
    "exfiltration": "185.199.108.153",        # incident 3 — exfil destination
    "low_risk_anomaly": "192.168.1.44",      # incident 4 — unknown host (same as device 6)
    "ransomware_beacon": "45.33.32.156",      # incident 5 — ransomware C2
    "lateral_scanning": "198.51.100.45",      # incident 6 — external callback to Roku
}


def _incident_ctx(device_id: int, scenario_key: str) -> dict:
    """
    Build the incident context dict consumed by ``seed_narrative`` and ``action_catalog``.

    Merges ``DEVICES[device_id]`` with scenario-specific fields that runtime code
    also expects when formatting action results and chat copy.

    Parameters
    ----------
    device_id:
        FK into ``devices.device_id`` for the incident being scripted.
    scenario_key:
        One of the keys in ``SCENARIO_INDICATORS`` / ``scenario_telemetry``.

    Returns
    -------
    dict
        Device fields plus ``source``, ``source_mac``, ``indicator``, and ``key``.
        ``source`` duplicates ``device_name`` for legacy formatter keys in action_catalog.
    """
    device = DEVICES[device_id]
    return {
        **device,
        "source": device["device_name"],
        "source_mac": device["mac_address"],
        "indicator": SCENARIO_INDICATORS[scenario_key],
        "key": scenario_key,
    }


def _insert_events(
    conn: sqlite3.Connection,
    event_id: int,
    incident_id: int,
    scenario_key: str,
    device_id: int,
    created_at: str,
) -> int:
    """
    Bulk-insert ``incident_events`` rows for one incident from scenario templates.

    Delegates event content and relative timestamps to
    ``scenario_telemetry.get_scenario_events_with_timestamps``, which rewrites
    placeholder IPs in templates to the actual ``device_ip`` and ``indicator``.

  Schema target: ``incident_events`` (
        event_id PK, incident_id FK, timestamp, source_ip, destination_ip,
        protocol, payload_summary
    )

    Parameters
    ----------
    conn:
        Open SQLite connection with ``PRAGMA foreign_keys = ON``.
    event_id:
        Next available ``event_id`` (caller maintains global counter across incidents).
    incident_id:
        Parent incident FK.
    scenario_key:
        Selects template list in ``scenario_telemetry.SCENARIO_EVENT_TEMPLATES``.
    device_id:
        Used only to look up ``internal_ip`` for IP substitution in templates.
    created_at:
        Incident ``created_at`` string; anchors all template offset minutes.

    Returns
    -------
    int
        Next unused ``event_id`` after this batch (no gaps — monotonic increment).
    """
    device_ip = DEVICES[device_id]["internal_ip"]
    indicator = SCENARIO_INDICATORS[scenario_key]
    # Each row: (timestamp, source_ip, destination_ip, protocol, payload_summary)
    events = get_scenario_events_with_timestamps(scenario_key, device_ip, indicator, created_at)
    for ts, src, dst, proto, summary in events:
        conn.execute(
            """
            INSERT INTO incident_events (event_id, incident_id, timestamp, source_ip, destination_ip, protocol, payload_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, incident_id, ts, src, dst, proto, summary),
        )
        event_id += 1
    return event_id


def initialize_database() -> None:
    """
    Create the project database, apply schema DDL, and insert all demo rows.

    Execution model
    ---------------
    - Opens ``DATABASE_PATH``, enables foreign keys, runs full ``schema.sql``.
    - All INSERTs occur inside one connection context; single ``commit()`` at end.
    - On failure before commit, transaction rolls back (atomic seed).

    Insert order respects FK graph in schema.sql:
      devices -> incidents -> incident_events, indicators, incident_indicators,
      recommendations -> chat_messages / incident_actions / incident_updates
    """

    DATABASE_PATH.parent.mkdir(exist_ok=True)

    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")
        schema_sql = SCHEMA_PATH.read_text()
        conn.executescript(schema_sql)

        # ===================================================================
        # Step 1: devices
        # ===================================================================
        # Parent table for incidents. Six rows; device_id 5 is filler (no incident).
        conn.executemany(
            """
            INSERT INTO devices (device_id, mac_address, device_name, device_type, internal_ip, owner_name)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (device_id, data["mac_address"], data["device_name"], data["device_type"], data["internal_ip"], data["owner_name"])
                for device_id, data in DEVICES.items()
            ],
        )

        # ===================================================================
        # Step 2: incidents
        # ===================================================================
        # Six incidents demonstrating varied ``status``, ``severity``, and lifecycle:
        #   - acknowledged_at set => user has seen the alert
        #   - authority_recommended => maps to scenario_telemetry.scenario_authority_recommended logic
        #   - chat_session_id updated later in Step 6 after sessions are created
        #   - monitor_until left NULL here; incident 6 uses incident_updates instead
        conn.executemany(
            """
            INSERT INTO incidents (
                incident_id, device_id, title, severity, status, created_at,
                acknowledged_at, monitor_until, authority_recommended
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                # inc 1: C2 on gateway — Investigating, authority flag on
                (1, 1, "Command and Control Traffic", "Critical", "Investigating",
                 "2026-06-10 01:00:00", "2026-06-10 01:05:00", None, 1),
                # inc 2: brute force on smart lock — Active, acknowledged
                (2, 4, "Repeated Unauthorized Login Attempts", "High", "Active",
                 "2026-06-10 08:45:00", "2026-06-10 08:46:00", None, 1),
                # inc 3: exfiltration — Mitigated (full playbook done in chat)
                (3, 2, "Suspicious Outbound Traffic Surge", "Critical", "Mitigated",
                 "2026-05-27 23:10:00", "2026-05-27 23:12:00", None, 1),
                # inc 4: low risk — Active, never acknowledged, no authority push
                (4, 6, "Unrecognized Device Activity", "Low", "Active",
                 "2026-06-09 14:30:00", None, None, 0),
                # inc 5: ransomware — Active, fresh (investigation only, no chat)
                (5, 2, "Ransomware Staging Detected", "Critical", "Active",
                 "2026-06-11 06:00:00", None, None, 1),
                # inc 6: lateral scan — Investigating, pending monitoring_complete update
                (6, 3, "Internal Lateral Movement", "High", "Investigating",
                 "2026-06-10 22:00:00", "2026-06-10 22:05:00", None, 0),
            ],
        )

        # ===================================================================
        # Step 3: incident_events (scenario telemetry)
        # ===================================================================
        # Tuple: (incident_id, scenario_key, device_id, created_at anchor)
        # ``created_at`` must match the incident row above — offsets are relative to it.
        event_id = 1  # global PK counter across all incidents
        incident_scenarios = [
            (1, "command_and_control", 1, "2026-06-10 01:00:00"),
            (2, "brute_force", 4, "2026-06-10 08:45:00"),
            (3, "exfiltration", 2, "2026-05-27 23:10:00"),
            (4, "low_risk_anomaly", 6, "2026-06-09 14:30:00"),
            (5, "ransomware_beacon", 2, "2026-06-11 06:00:00"),
            (6, "lateral_scanning", 3, "2026-06-10 22:00:00"),
        ]
        for incident_id, scenario_key, device_id, created_at in incident_scenarios:
            event_id = _insert_events(conn, event_id, incident_id, scenario_key, device_id, created_at)

        # ===================================================================
        # Step 4: indicators + incident_indicators (IOC junction)
        # ===================================================================
        # One indicator row per scenario; junction is strictly 1:1 for demo clarity.
        # ``get_scenario_indicator`` fills indicator_type, threat_actor_group, confidence_score.
        indicator_rows = []
        for idx, (scenario_key, value) in enumerate(SCENARIO_INDICATORS.items(), start=1):
            meta = get_scenario_indicator(scenario_key, value)
            indicator_rows.append((
                idx,  # indicator_id — matches incident_id in junction below
                meta["indicator_value"],
                meta["indicator_type"],
                meta["threat_actor_group"],
                meta["confidence_score"],
            ))
        conn.executemany(
            """
            INSERT INTO indicators (indicator_id, indicator_value, indicator_type, threat_actor_group, confidence_score)
            VALUES (?, ?, ?, ?, ?)
            """,
            indicator_rows,
        )
        # PK (incident_id, indicator_id) — each incident linked to its scenario IOC
        conn.executemany(
            "INSERT INTO incident_indicators (incident_id, indicator_id) VALUES (?, ?)",
            [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)],
        )

        # ===================================================================
        # Step 5: recommendations
        # ===================================================================
        # Types (schema CHECK): general | playbook | authority_notice
        # playbook rows include ``playbook_actions_json`` — array of action_key strings
        # that match ``action_catalog`` keys used in chat scripts below.
        # display_order controls UI sort; is_active=1 keeps rows visible in expert panel.
        conn.executemany(
            """
            INSERT INTO recommendations (
                recommendation_id, incident_id, recommendation_text, is_ai_generated,
                recommendation_type, playbook_actions_json, display_order, is_active, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                # --- Incident 1 (C2) ---
                (1, 1,
                 "Critical C2 traffic on gateway. Sinkhole DNS, block C2 IP, isolate gateway, patch firmware.",
                 1, "playbook",
                 json.dumps(["dns_sinkhole", "perm_block", "isolate_device", "patch_remediate", "generate_incident_report"]),
                 0, 1, "2026-06-10 01:05:00"),
                (2, 1,
                 "Active command-and-control on home gateway. Consider notifying authorities and preserve evidence.",
                 1, "authority_notice", None, 3, 1, "2026-06-10 01:10:00"),
                # --- Incident 2 (brute force) ---
                (3, 2,
                 "Recommended response: port lockdown, permanent block of attacker IP, then credential rotation.",
                 1, "playbook",
                 json.dumps(["port_lockdown", "perm_block", "require_credential_rotation"]),
                 0, 1, "2026-06-10 08:46:00"),
                (4, 2,
                 "Smart lock under active brute force. Disable external access and rotate credentials.",
                 1, "general", None, 1, 1, "2026-06-10 08:46:00"),
                # --- Incident 3 (exfiltration — mitigated) ---
                (5, 3,
                 "Recommended response: sever active connection, isolate workstation, block exfil endpoint, offline scan.",
                 1, "playbook",
                 json.dumps([
                     "sever_connection", "isolate_device", "perm_block",
                     "prompt_offline_scan", "generate_incident_report",
                 ]),
                 0, 1, "2026-05-27 23:12:00"),
                (6, 3,
                 "Critical data exfiltration detected. Consider notifying law enforcement and preserve evidence.",
                 1, "authority_notice", None, 3, 1, "2026-05-28 00:00:00"),
                (7, 3,
                 "Workstation isolated from network. Run full offline malware scan before reconnecting.",
                 0, "general", None, 2, 1, "2026-05-27 23:30:00"),
                # --- Incident 4 (low risk) ---
                (8, 4,
                 "Monitor unrecognized device for 24h before escalating. No confirmed malicious behavior yet.",
                 1, "general", None, 1, 1, "2026-06-09 14:35:00"),
                (9, 4,
                 "Recommended response: monitor with offline scan window, then trust or escalate.",
                 1, "playbook",
                 json.dumps(["prompt_offline_scan", "trust_device"]),
                 0, 1, "2026-06-09 14:35:00"),
                # --- Incident 6 (lateral scanning) — no recs for incident 5 (fresh) ---
                (10, 6,
                 "Recommended response: isolate, block scanner IP, enhanced monitoring, then incident report.",
                 1, "playbook",
                 json.dumps([
                     "isolate_device", "perm_block", "prompt_offline_scan",
                     "generate_incident_report",
                 ]),
                 0, 1, "2026-06-10 22:05:00"),
            ],
        )

        # ===================================================================
        # Step 6: incident_actions + chat_messages + incident_updates
        # ===================================================================
        # Global ID cursors — must stay monotonic across all inserts in this step.
        # action_id -> incident_actions.action_id (PK)
        # message_id -> chat_messages.message_id (PK)
        action_id = 1
        message_id = 1

        # --- General chat sessions (incident_id NULL per schema FK optional) ---
        # Two standalone threads for dashboard chat drawer when no incident selected.
        conn.executemany(
            """
            INSERT INTO chat_messages (message_id, session_id, incident_id, role, content, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (message_id, "sess-general-001", None, "assistant",
                 "Hi, I am Sentinel. Ask me anything about your home network.", "2026-06-09 10:00:00"),
                (message_id + 1, "sess-general-001", None, "user",
                 "Is everything okay on my network?", "2026-06-09 10:01:00"),
                (message_id + 2, "sess-general-001", None, "assistant",
                 "Everything looks stable right now. Run a scan if you want a fresh check.", "2026-06-09 10:01:30"),
            ],
        )
        message_id += 3

        conn.executemany(
            """
            INSERT INTO chat_messages (message_id, session_id, incident_id, role, content, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (message_id, "sess-general-002", None, "user",
                 "What does Sentinel monitor on my network?", "2026-06-09 11:00:00"),
                (message_id + 1, "sess-general-002", None, "assistant",
                 "I watch device connections, login attempts, and unusual outbound traffic. "
                 "Select an incident or run a scan when you want a deeper check.", "2026-06-09 11:00:30"),
            ],
        )
        message_id += 2

        # --- Incident 1: command_and_control — mid-playbook chat ---
        # Investigation actions at T+30s; chat starts later at session_start.
        ctx1 = _incident_ctx(1, "command_and_control")
        action_id = insert_investigation_actions(
            conn, action_id=action_id, incident_id=1, incident_ctx=ctx1, created_at="2026-06-10 01:00:30",
        )
        message_id, action_id = seed_chat_session(
            conn,
            message_id=message_id,
            action_id=action_id,
            incident_id=1,
            incident_ctx=ctx1,
            scenario_key="command_and_control",
            session_id="sess-inc1-001",
            session_start="2026-06-10 01:15:00",
            script=[
                ("assistant",
                 "Your Main Home Gateway at 192.168.1.1 is repeatedly calling out to a command server "
                 "at 198.18.0.77. This looks like active remote control of your network."),
                ("action", "dns_sinkhole"),  # creates incident_actions + user/assistant msgs
                ("assistant", "Next step is blocking the outside command server address permanently."),
                ("action", "perm_block"),
            ],
        )

        # --- Incident 2: brute_force — containment steps done in chat ---
        ctx2 = _incident_ctx(4, "brute_force")
        action_id = insert_investigation_actions(
            conn, action_id=action_id, incident_id=2, incident_ctx=ctx2, created_at="2026-06-10 08:45:30",
        )
        message_id, action_id = seed_chat_session(
            conn,
            message_id=message_id,
            action_id=action_id,
            incident_id=2,
            incident_ctx=ctx2,
            scenario_key="brute_force",
            session_id="sess-inc2-001",
            session_start="2026-06-10 09:00:00",
            script=[
                ("assistant",
                 "Someone keeps trying to guess the password on your Front Door Smart Lock from 203.0.113.88."),
                ("action", "port_lockdown"),
                ("assistant", "Next step is blocking the outside address."),
                ("action", "perm_block"),
            ],
        )

        # --- Incident 3: exfiltration — full playbook (longest chat script) ---
        ctx3 = _incident_ctx(2, "exfiltration")
        action_id = insert_investigation_actions(
            conn, action_id=action_id, incident_id=3, incident_ctx=ctx3, created_at="2026-05-27 23:10:30",
        )
        message_id, action_id = seed_chat_session(
            conn,
            message_id=message_id,
            action_id=action_id,
            incident_id=3,
            incident_ctx=ctx3,
            scenario_key="exfiltration",
            session_id="sess-inc3-001",
            session_start="2026-05-27 23:15:00",
            script=[
                ("assistant",
                 "Brett's Workstation was sending a large amount of data to an outside address (185.199.108.153)."),
                ("action", "sever_connection"),
                ("assistant", "Connection stopped. Next, take the workstation offline to prevent further spread."),
                ("action", "isolate_device"),
                ("assistant", "Device isolated. Block the exfil endpoint permanently."),
                ("action", "perm_block"),
                ("assistant", "Block in place. Schedule enhanced monitoring before reconnecting."),
                ("action", "prompt_offline_scan"),
                ("assistant",
                 "Monitoring scheduled. Generate the incident report to close out response."),
                ("action", "generate_incident_report"),
            ],
        )

        # --- Incident 4: low_risk_anomaly — assistant-only, no playbook actions yet ---
        ctx4 = _incident_ctx(6, "low_risk_anomaly")
        action_id = insert_investigation_actions(
            conn, action_id=action_id, incident_id=4, incident_ctx=ctx4, created_at="2026-06-09 14:30:30",
        )
        # Manual single message (not using seed_chat_session — demonstrates early-stage incident)
        conn.execute(
            """
            INSERT INTO chat_messages (message_id, session_id, incident_id, role, content, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                message_id, "sess-inc4-001", 4, "assistant",
                "I found a device on your network that I do not recognize (Guest-IoT-7A2F at 192.168.1.44). "
                "It is probing local services at low frequency. No confirmed malicious behavior yet.",
                "2026-06-10 15:00:00",
            ),
        )
        message_id += 1

        # --- Incident 5: ransomware_beacon — investigation only, no chat transcript ---
        ctx5 = _incident_ctx(2, "ransomware_beacon")
        action_id = insert_investigation_actions(
            conn, action_id=action_id, incident_id=5, incident_ctx=ctx5, created_at="2026-06-11 06:00:30",
        )

        # --- Incident 6: lateral_scanning — monitoring waiting state in chat ---
        ctx6 = _incident_ctx(3, "lateral_scanning")
        action_id = insert_investigation_actions(
            conn, action_id=action_id, incident_id=6, incident_ctx=ctx6, created_at="2026-06-10 22:00:30",
        )
        message_id, action_id = seed_chat_session(
            conn,
            message_id=message_id,
            action_id=action_id,
            incident_id=6,
            incident_ctx=ctx6,
            scenario_key="lateral_scanning",
            session_id="sess-inc6-001",
            session_start="2026-06-10 22:15:00",
            script=[
                ("assistant",
                 "Your Living Room Roku at 192.168.1.15 is trying to reach many other devices on your network."),
                ("action", "isolate_device"),
                ("assistant", "Device isolated. Block the scanner's address permanently."),
                ("action", "perm_block"),
                ("assistant",
                 "Block in place. Schedule a deep scan and monitoring window before reconnecting."),
                ("action", "prompt_offline_scan"),
                ("assistant",
                 "Enhanced monitoring is running on **Living Room Roku** (36h watch). "
                 "I'll alert you in **Alerts** when the window completes so we can proceed to documentation. "
                 "No action needed right now."),
            ],
        )

        # Extra incident_events row + incident_updates for incident 6 demo:
        # Simulates monitoring window completion -> pending alert in expert notifications.
        # acknowledged_at NULL => still pending in UI (idx_incident_updates_pending).
        conn.execute(
            """
            INSERT INTO incident_events (
                event_id, incident_id, timestamp, source_ip, destination_ip, protocol, payload_summary
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                6,
                "2026-06-10 22:20:00",
                "192.168.1.15",
                "192.168.1.15",
                "INTERNAL",  # not a real IANA protocol — narrative marker for UI
                "Monitoring window complete — no new anomalies observed during watch period.",
            ),
        )
        event_id += 1

        conn.executemany(
            """
            INSERT INTO incident_updates (
                update_id, incident_id, update_type, title, summary_text, payload_json,
                created_at, acknowledged_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1,
                    6,
                    "monitoring_complete",  # consumed by expert_notifications / incident UI
                    "Monitoring complete — Living Room Roku",
                    (
                        "Enhanced monitoring (36h watch) finished for **Living Room Roku**. "
                        "No new suspicious activity was detected."
                    ),
                    json.dumps({
                        "narrative_hours": 36,
                        "trigger_action_key": "prompt_offline_scan",  # ties back to last playbook step
                    }),
                    "2026-06-10 22:20:00",
                    None,  # pending — user has not acknowledged yet
                ),
            ],
        )

        # Link incidents to their primary chat session (incidents.chat_session_id column).
        # Incident 5 intentionally omitted — no chat session seeded.
        for incident_id, session_id in (
            (1, "sess-inc1-001"),
            (2, "sess-inc2-001"),
            (3, "sess-inc3-001"),
            (4, "sess-inc4-001"),
            (6, "sess-inc6-001"),
        ):
            conn.execute(
                "UPDATE incidents SET chat_session_id = ? WHERE incident_id = ?;",
                (session_id, incident_id),
            )

        conn.commit()


if __name__ == "__main__":
    # CLI entry: wipe/recreate db and print confirmation paths.
    initialize_database()
    print(f"Database successfully created at: {DATABASE_PATH}")
    print("Aetherius Sentinel local data seeded.")
