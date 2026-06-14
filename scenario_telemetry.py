"""
Scenario-specific incident event and indicator templates for seed and runtime.

Each ``scenario_key`` (e.g. ``command_and_control``) defines a scripted sequence
of network events and IOC metadata. Templates use placeholder IPs that helper
functions rewrite to the actual device IP and indicator value at insert time.

Consumed by ``seed.py`` (historical timestamps) and ``db.create_incident_with_investigation``
(live incident creation without explicit timestamps).
"""

from __future__ import annotations

from typing import Any

# --- Event templates ---
# Each event tuple: (timestamp_offset_minutes, source_ip, destination_ip, protocol, payload_summary)
# offset is relative to incident created_at when materialized via get_scenario_events_with_timestamps.
# Placeholder IPs (192.168.1.x) are swapped for real device/indicator values per scenario.

SCENARIO_EVENT_TEMPLATES: dict[str, list[tuple[int, str, str, str, str]]] = {
    "command_and_control": [
        (0, "192.168.1.1", "8.8.8.8", "DNS", "DNS query for update-cdn.evilcorp.net (NXDOMAIN sinkhole candidate)"),
        (1, "192.168.1.1", "198.18.0.77", "HTTPS", "TLS beacon POST /api/v2/checkin — 412 bytes outbound"),
        (5, "192.168.1.1", "198.18.0.77", "HTTPS", "Sustained callback interval ~90s — C2 heartbeat pattern"),
        (12, "192.168.1.1", "198.18.0.77", "HTTPS", "Encrypted payload burst 2.1KB — possible tasking download"),
        (18, "192.168.1.1", "192.168.1.10", "TCP", "Gateway initiated SMB probe to workstation (lateral staging)"),
        (25, "192.168.1.1", "198.18.0.77", "HTTPS", "Beacon resumed after brief silence — persistence indicator"),
        (40, "192.168.1.1", "198.18.0.77", "HTTPS", "DNS-over-HTTPS fallback attempt to 198.18.0.77:443"),
        (55, "192.168.1.1", "192.168.1.15", "TCP", "Internal port scan relay via compromised gateway"),
    ],
    "brute_force": [
        (0, "203.0.113.88", "192.168.1.20", "TCP", "Failed authentication attempt — Invalid Creds"),
        (1, "203.0.113.88", "192.168.1.20", "TCP", "Failed authentication attempt — Invalid Creds"),
        (2, "203.0.113.88", "192.168.1.20", "TCP", "Failed authentication attempt — Lockout Triggered"),
        (30, "203.0.113.88", "192.168.1.20", "TCP", "Brute force resumed after cooldown"),
        (45, "203.0.113.88", "192.168.1.20", "TCP", "Credential stuffing pattern detected — 47 attempts/min"),
        (60, "203.0.113.88", "192.168.1.20", "TCP", "Dictionary attack using common IoT default passwords"),
    ],
    "exfiltration": [
        (0, "192.168.1.10", "185.199.108.153", "UDP", "Large outbound payload anomaly (500MB)"),
        (2, "192.168.1.10", "185.199.108.153", "UDP", "Continuous data stream detected — sustained exfil"),
        (8, "192.168.1.10", "185.199.108.153", "UDP", "Archive staging: .zip chunks outbound on high port"),
        (15, "192.168.1.10", "185.199.108.153", "TCP", "Fallback HTTPS tunnel opened after UDP throttle"),
        (30, "192.168.1.10", "185.199.108.153", "UDP", "Exfil volume spike — 1.2GB in 10-minute window"),
        (45, "192.168.1.10", "185.199.108.153", "UDP", "Connection persistence — keepalive every 30s"),
        (60, "192.168.1.10", "185.199.108.153", "UDP", "Post-mitigation residual probe blocked"),
    ],
    "low_risk_anomaly": [
        (0, "192.168.1.44", "192.168.1.1", "UDP", "Unknown host DHCP lease observed"),
        (15, "192.168.1.44", "192.168.1.15", "TCP", "Low-frequency service discovery scan"),
        (45, "192.168.1.44", "192.168.1.10", "TCP", "SMB port probe from guest segment"),
        (90, "192.168.1.44", "192.168.1.1", "ICMP", "Periodic ping sweep of gateway"),
    ],
    "ransomware_beacon": [
        (0, "192.168.1.10", "45.33.32.156", "HTTPS", "Encrypted beacon to 45.33.32.156 — 890 bytes"),
        (3, "192.168.1.10", "127.0.0.1", "LOCAL", "vssadmin delete shadows /all detected — shadow copy wipe"),
        (5, "192.168.1.10", "45.33.32.156", "HTTPS", "Ransomware staging key exchange — RSA public key upload"),
        (10, "192.168.1.10", "192.168.1.1", "TCP", "Mass file rename activity — .locked extension pattern"),
        (12, "192.168.1.10", "45.33.32.156", "HTTPS", "Pre-encryption callback — victim ID transmitted"),
        (20, "192.168.1.10", "192.168.1.15", "TCP", "Lateral spread attempt via SMB to media device"),
        (25, "192.168.1.10", "45.33.32.156", "HTTPS", "Encrypted outbound burst 4.7MB — staging complete"),
        (30, "192.168.1.10", "127.0.0.1", "LOCAL", "bcdedit recoveryenabled no — boot recovery disabled"),
    ],
    "lateral_scanning": [
        (0, "192.168.1.15", "192.168.1.1", "TCP", "SYN packet to port 22 (SSH)"),
        (0, "192.168.1.15", "192.168.1.10", "TCP", "SYN packet to port 445 (SMB)"),
        (1, "192.168.1.15", "192.168.1.20", "TCP", "SYN packet to port 80 (HTTP)"),
        (2, "192.168.1.15", "192.168.1.25", "TCP", "SYN packet to port 443 (HTTPS)"),
        (5, "192.168.1.15", "192.168.1.0/24", "TCP", "Sequential port sweep across subnet — worm behavior"),
        (15, "198.51.100.45", "192.168.1.15", "TCP", "External callback to compromised media device"),
        (30, "192.168.1.15", "192.168.1.10", "TCP", "Repeated SMB auth failures — lateral movement attempt"),
    ],
}

# --- Indicator metadata templates ---
# indicator_value comes from the caller; these dicts supply type, actor, and confidence.

SCENARIO_INDICATOR_TEMPLATES: dict[str, dict[str, Any]] = {
    "command_and_control": {
        "indicator_type": "C2 Endpoint",
        "threat_actor_group": "SilverHydra APT",
        "confidence_score": 92,
    },
    "brute_force": {
        "indicator_type": "Known Bad Subnet",
        "threat_actor_group": "Mirai Botnet Variant",
        "confidence_score": 95,
    },
    "exfiltration": {
        "indicator_type": "Suspicious Endpoint",
        "threat_actor_group": "Data Exfiltration Node",
        "confidence_score": 88,
    },
    "low_risk_anomaly": {
        "indicator_type": "Unknown Host",
        "threat_actor_group": "Unclassified",
        "confidence_score": 40,
    },
    "ransomware_beacon": {
        "indicator_type": "Ransomware C2",
        "threat_actor_group": "LockBit Affiliate",
        "confidence_score": 94,
    },
    "lateral_scanning": {
        "indicator_type": "Malicious IP",
        "threat_actor_group": "Unknown Scanner",
        "confidence_score": 85,
    },
}


def get_scenario_events(
    scenario_key: str,
    device_ip: str,
    indicator: str,
) -> list[tuple[str, str, str, str, str]]:
    """
    Return incident event rows as (source_ip, destination_ip, protocol, payload_summary).

    Timestamps are omitted — caller supplies explicit timestamps or uses datetime('now').
    Delegates to the timestamped helper and strips the time column for runtime inserts.
    """
    rows = get_scenario_events_with_timestamps(
        scenario_key, device_ip, indicator, "2026-01-01 00:00:00",
    )
    return [(src, dst, proto, summary) for _ts, src, dst, proto, summary in rows]


def get_scenario_events_with_timestamps(
    scenario_key: str,
    device_ip: str,
    indicator: str,
    base_timestamp: str,
) -> list[tuple[str, str, str, str, str]]:
    """
    Return events with absolute timestamps for seed data.

    Rewrites template placeholder IPs per scenario so the same templates work
    across different seeded devices and IOC values.
    """
    from datetime import datetime, timedelta

    templates = SCENARIO_EVENT_TEMPLATES.get(scenario_key, [])
    base = datetime.strptime(base_timestamp, "%Y-%m-%d %H:%M:%S")
    events: list[tuple[str, str, str, str, str]] = []
    for offset, src, dst, proto, summary in templates:
        ts = (base + timedelta(minutes=offset)).strftime("%Y-%m-%d %H:%M:%S")
        src_resolved = src
        dst_resolved = dst
        # Per-scenario IP substitution rules — only touch known placeholder octets.
        if scenario_key == "command_and_control":
            src_resolved = device_ip if src == "192.168.1.1" else src
            dst_resolved = indicator if dst == "198.18.0.77" else dst
        elif scenario_key == "exfiltration":
            src_resolved = device_ip if src == "192.168.1.10" else src
            dst_resolved = indicator if "185.199.108.153" in dst else dst
        elif scenario_key == "ransomware_beacon":
            src_resolved = device_ip if src == "192.168.1.10" else src
            dst_resolved = indicator if dst == "45.33.32.156" else dst
        elif scenario_key == "lateral_scanning":
            src_resolved = device_ip if src == "192.168.1.15" else src
        elif scenario_key == "low_risk_anomaly":
            src_resolved = indicator if src == "192.168.1.44" else src
        elif scenario_key == "brute_force":
            dst_resolved = device_ip if dst == "192.168.1.20" else dst
        events.append((ts, src_resolved, dst_resolved, proto, summary))
    return events


def get_scenario_indicator(scenario_key: str, indicator_value: str) -> dict[str, Any]:
    """
    Return indicator metadata for a scenario.

    Merges caller-supplied ``indicator_value`` with template fields; unknown
    scenarios fall back to generic suspicious-endpoint defaults.
    """
    template = SCENARIO_INDICATOR_TEMPLATES.get(scenario_key, {
        "indicator_type": "Suspicious Endpoint",
        "threat_actor_group": "Unknown",
        "confidence_score": 50,
    })
    return {
        "indicator_value": indicator_value,
        **template,
    }


def scenario_authority_recommended(scenario_key: str, severity: str) -> bool:
    """
    Return True when the UI should suggest notifying authorities.

    Only Critical/High severities on scenarios with clear criminal activity
    (C2, exfil, ransomware, brute force) trigger the flag.
    """
    return severity in ("Critical", "High") and scenario_key in (
        "exfiltration", "brute_force", "ransomware_beacon", "command_and_control",
    )
