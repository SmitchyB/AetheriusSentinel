"""
Database seed script for Aetherius Sentinel local development.

Creates ``data/project.db`` from ``schema.sql`` and populates it with a realistic
home-network demo: six devices, six incidents at different lifecycle stages,
scenario-specific telemetry, IOCs, AI recommendations, response actions, and
chat transcripts that stay in sync with ``incident_actions``.

Run directly: ``python seed.py``
"""

import json
import sqlite3
from pathlib import Path

from scenario_telemetry import get_scenario_events_with_timestamps, get_scenario_indicator
from seed_narrative import insert_investigation_actions, seed_chat_session

# Paths relative to project root (run from repo root).
DATABASE_PATH = Path("data/project.db")
SCHEMA_PATH = Path("schema.sql")

# --- Demo device registry ---
# Keys are device_id values that match incidents and seed narratives.
# Each entry supplies network identity fields used when building incident_ctx
# dicts for action_catalog formatters and chat scripts.

DEVICES = {
    # Primary gateway — anchor for C2 scenario (incident 1).
    1: {
        "device_name": "Main Home Gateway",
        "device_type": "Gateway",
        "internal_ip": "192.168.1.1",
        "mac_address": "00:1A:2B:3C:4D:5E",
        "owner_name": "Admin",
    },
    # Primary workstation — exfiltration and ransomware scenarios (incidents 3, 5).
    2: {
        "device_name": "Brett's Workstation",
        "device_type": "Workstation",
        "internal_ip": "192.168.1.10",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "owner_name": "Brett Smitch",
    },
    # Media device — lateral scanning scenario (incident 6).
    3: {
        "device_name": "Living Room Roku",
        "device_type": "Media",
        "internal_ip": "192.168.1.15",
        "mac_address": "11:22:33:44:55:66",
        "owner_name": "Shared",
    },
    # IoT smart lock — brute force scenario (incident 2).
    4: {
        "device_name": "Front Door Smart Lock",
        "device_type": "IoT",
        "internal_ip": "192.168.1.20",
        "mac_address": "77:88:99:AA:BB:CC",
        "owner_name": "Admin",
    },
    5: {
        "device_name": "PlayStation 5",
        "device_type": "Console",
        "internal_ip": "192.168.1.25",
        "mac_address": "DD:EE:FF:00:11:22",
        "owner_name": "Brett Smitch",
    },
    # Unrecognized guest IoT — low_risk_anomaly scenario (incident 4).
    6: {
        "device_name": "Guest-IoT-7A2F",
        "device_type": "IoT",
        "internal_ip": "192.168.1.44",
        "mac_address": "FE:DC:BA:98:76:54",
        "owner_name": "Guest",
    },
}

# Maps each scenario_key to the primary IOC IP/host used in events and indicators.
SCENARIO_INDICATORS = {
    "command_and_control": "198.18.0.77",
    "brute_force": "203.0.113.88",
    "exfiltration": "185.199.108.153",
    "low_risk_anomaly": "192.168.1.44",
    "ransomware_beacon": "45.33.32.156",
    "lateral_scanning": "198.51.100.45",
}


def _incident_ctx(device_id: int, scenario_key: str) -> dict:
    """Merge device fields with scenario indicator for action_catalog / chat helpers."""
    device = DEVICES[device_id]
    return {
        **device,
        "source": device["device_name"],
        "source_mac": device["mac_address"],
        "indicator": SCENARIO_INDICATORS[scenario_key],
        "key": scenario_key,
    }


def _insert_events(conn: sqlite3.Connection, event_id: int, incident_id: int, scenario_key: str, device_id: int, created_at: str) -> int:
    """
    Bulk-insert scenario telemetry rows for one incident.

    Returns the next unused event_id so callers can chain inserts without gaps.
    """
    device_ip = DEVICES[device_id]["internal_ip"]
    indicator = SCENARIO_INDICATORS[scenario_key]
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
    Create the project db, run the schema, and insert sample data.

    All inserts happen in one transaction; commit at the end rolls everything
    forward atomically or leaves an empty db on failure.
    """

    DATABASE_PATH.parent.mkdir(exist_ok=True)

    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")
        schema_sql = SCHEMA_PATH.read_text()
        conn.executescript(schema_sql)

        # --- Step 1: Devices ---
        # Seed the six demo hosts that incidents reference by device_id.
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

        # --- Step 2: Incidents ---
        # Six incidents at varied lifecycle stages (Active, Investigating, Mitigated).
        conn.executemany(
            """
            INSERT INTO incidents (
                incident_id, device_id, title, severity, status, created_at,
                acknowledged_at, monitor_until, authority_recommended
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 1, "Command and Control Traffic", "Critical", "Investigating",
                 "2026-06-10 01:00:00", "2026-06-10 01:05:00", None, 1),
                (2, 4, "Repeated Unauthorized Login Attempts", "High", "Active",
                 "2026-06-10 08:45:00", "2026-06-10 08:46:00", None, 1),
                (3, 2, "Suspicious Outbound Traffic Surge", "Critical", "Mitigated",
                 "2026-05-27 23:10:00", "2026-05-27 23:12:00", None, 1),
                (4, 6, "Unrecognized Device Activity", "Low", "Active",
                 "2026-06-09 14:30:00", None, None, 0),
                (5, 2, "Ransomware Staging Detected", "Critical", "Active",
                 "2026-06-11 06:00:00", None, None, 1),
                (6, 3, "Internal Lateral Movement", "High", "Investigating",
                 "2026-06-10 22:00:00", "2026-06-10 22:05:00", None, 0),
            ],
        )

        # --- Step 3: Incident events ---
        # Rich per-scenario telemetry; timestamps anchored to each incident's created_at.
        event_id = 1
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

        # --- Step 4: Indicators ---
        # One IOC per scenario, linked 1:1 to incidents via incident_indicators.
        indicator_rows = []
        for idx, (scenario_key, value) in enumerate(SCENARIO_INDICATORS.items(), start=1):
            meta = get_scenario_indicator(scenario_key, value)
            indicator_rows.append((
                idx,
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
        conn.executemany(
            "INSERT INTO incident_indicators (incident_id, indicator_id) VALUES (?, ?)",
            [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)],
        )

        # --- Step 5: Recommendations ---
        # Playbooks for acknowledged incidents plus authority notices and general tips.
        conn.executemany(
            """
            INSERT INTO recommendations (
                recommendation_id, incident_id, recommendation_text, is_ai_generated,
                recommendation_type, playbook_actions_json, display_order, is_active, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 1,
                 "Critical C2 traffic on gateway. Sinkhole DNS, block C2 IP, isolate gateway, patch firmware.",
                 1, "playbook",
                 json.dumps(["dns_sinkhole", "perm_block", "isolate_device", "patch_remediate", "generate_incident_report"]),
                 0, 1, "2026-06-10 01:05:00"),
                (2, 1,
                 "Active command-and-control on home gateway. Consider notifying authorities and preserve evidence.",
                 1, "authority_notice", None, 3, 1, "2026-06-10 01:10:00"),
                (3, 2,
                 "Recommended response: port lockdown, permanent block of attacker IP, then credential rotation.",
                 1, "playbook",
                 json.dumps(["port_lockdown", "perm_block", "require_credential_rotation"]),
                 0, 1, "2026-06-10 08:46:00"),
                (4, 2,
                 "Smart lock under active brute force. Disable external access and rotate credentials.",
                 1, "general", None, 1, 1, "2026-06-10 08:46:00"),
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
                (8, 4,
                 "Monitor unrecognized device for 24h before escalating. No confirmed malicious behavior yet.",
                 1, "general", None, 1, 1, "2026-06-09 14:35:00"),
                (9, 4,
                 "Recommended response: monitor with offline scan window, then trust or escalate.",
                 1, "playbook",
                 json.dumps(["prompt_offline_scan", "trust_device"]),
                 0, 1, "2026-06-09 14:35:00"),
                (10, 6,
                 "Recommended response: isolate compromised media device, block scanner IP, schedule offline scan.",
                 1, "playbook",
                 json.dumps(["isolate_device", "perm_block", "prompt_offline_scan"]),
                 0, 1, "2026-06-10 22:05:00"),
            ],
        )

        # --- Step 6: Incident actions + chat ---
        # Auto investigation rows plus user-driven playbook steps mirrored in chat.
        action_id = 1
        message_id = 1

        # General welcome session (no incident context).
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

        # Incident 1 — command_and_control, mid-playbook (2 sessions).
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
                ("action", "dns_sinkhole"),
            ],
        )
        message_id, action_id = seed_chat_session(
            conn,
            message_id=message_id,
            action_id=action_id,
            incident_id=1,
            incident_ctx=ctx1,
            scenario_key="command_and_control",
            session_id="sess-inc1-002",
            session_start="2026-06-10 02:30:00",
            script=[
                ("assistant", "Next step is blocking the outside command server address permanently."),
                ("action", "perm_block"),
            ],
        )

        # Incident 2 — brute_force, containment done (2 sessions).
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
            ],
        )
        message_id, action_id = seed_chat_session(
            conn,
            message_id=message_id,
            action_id=action_id,
            incident_id=2,
            incident_ctx=ctx2,
            scenario_key="brute_force",
            session_id="sess-inc2-002",
            session_start="2026-06-10 11:00:00",
            script=[
                ("assistant", "Next step is blocking the outside address."),
                ("action", "perm_block"),
            ],
        )

        # Incident 3 — exfiltration, full playbook complete (1 long session).
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
                ("assistant", "Monitoring scheduled. Generate the incident report to close out response."),
                ("action", "generate_incident_report"),
            ],
        )

        # Incident 4 — low_risk_anomaly, early stage (assistant-only, no response actions yet).
        ctx4 = _incident_ctx(6, "low_risk_anomaly")
        action_id = insert_investigation_actions(
            conn, action_id=action_id, incident_id=4, incident_ctx=ctx4, created_at="2026-06-09 14:30:30",
        )
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

        # Incident 5 — ransomware_beacon, fresh (investigation only, no chat yet).
        ctx5 = _incident_ctx(2, "ransomware_beacon")
        action_id = insert_investigation_actions(
            conn, action_id=action_id, incident_id=5, incident_ctx=ctx5, created_at="2026-06-11 06:00:30",
        )

        # Incident 6 — lateral_scanning, partial playbook (1 session).
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
            ],
        )

        conn.commit()


if __name__ == "__main__":
    initialize_database()
    print(f"Database successfully created at: {DATABASE_PATH}")
    print("Aetherius Sentinel local data seeded.")
