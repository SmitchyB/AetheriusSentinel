import sqlite3
from pathlib import Path

DATABASE_PATH = Path("data/project.db")
SCHEMA_PATH = Path("schema.sql")

def initialize_database() -> None:
    """Create the project db, run the schema, and insert sample data."""

    # Ensure the data directory exists
    DATABASE_PATH.parent.mkdir(exist_ok=True)

    with sqlite3.connect(DATABASE_PATH) as conn:
        # Enable foreign keys for SQLite
        conn.execute("PRAGMA foreign_keys = ON;")

        # Read and execute the schema file
        schema_sql = SCHEMA_PATH.read_text()
        conn.executescript(schema_sql)

        # 1. Insert Devices (5 records)
        conn.executemany(
            """
            INSERT INTO devices (device_id, mac_address, device_name, device_type, internal_ip, owner_name)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (1, "00:1A:2B:3C:4D:5E", "Main Home Gateway", "Gateway", "192.168.1.1", "Admin"),
                (2, "AA:BB:CC:DD:EE:FF", "Brett's Workstation", "Workstation", "192.168.1.10", "Brett Smitch"),
                (3, "11:22:33:44:55:66", "Living Room Roku", "Media", "192.168.1.15", "Shared"),
                (4, "77:88:99:AA:BB:CC", "Front Door Smart Lock", "IoT", "192.168.1.20", "Admin"),
                (5, "DD:EE:FF:00:11:22", "PlayStation 5", "Console", "192.168.1.25", "Brett Smitch"),
            ],
        )

        # 2. Insert Incidents (3 records)
        conn.executemany(
            """
            INSERT INTO incidents (incident_id, device_id, title, severity, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 1, "External Port Scan Detected", "Medium", "Investigating", "2026-05-28 02:15:00"),
                (2, 4, "Repeated Unauthorized Login Attempts", "High", "Active", "2026-05-28 08:45:00"),
                (3, 2, "Suspicious Outbound Traffic Surge", "Critical", "Mitigated", "2026-05-27 23:10:00"),
            ],
        )

        # 3. Insert Incident Events (8 records - Raw Telemetry)
        conn.executemany(
            """
            INSERT INTO incident_events (event_id, incident_id, timestamp, source_ip, destination_ip, protocol, payload_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 1, "2026-05-28 02:15:01", "198.51.100.45", "192.168.1.1", "TCP", "SYN packet to port 22 (SSH)"),
                (2, 1, "2026-05-28 02:15:02", "198.51.100.45", "192.168.1.1", "TCP", "SYN packet to port 80 (HTTP)"),
                (3, 1, "2026-05-28 02:15:03", "198.51.100.45", "192.168.1.1", "TCP", "SYN packet to port 443 (HTTPS)"),
                (4, 2, "2026-05-28 08:45:10", "203.0.113.88", "192.168.1.20", "TCP", "Failed authentication attempt - Invalid Creds"),
                (5, 2, "2026-05-28 08:45:15", "203.0.113.88", "192.168.1.20", "TCP", "Failed authentication attempt - Invalid Creds"),
                (6, 2, "2026-05-28 08:45:20", "203.0.113.88", "192.168.1.20", "TCP", "Failed authentication attempt - Lockout Triggered"),
                (7, 3, "2026-05-27 23:10:05", "192.168.1.10", "185.199.108.153", "UDP", "Large outbound payload anomaly (500MB)"),
                (8, 3, "2026-05-27 23:12:00", "192.168.1.10", "185.199.108.153", "UDP", "Continuous data stream detected"),
            ],
        )

        # 4. Insert Indicators (3 records - Threat Intel)
        conn.executemany(
            """
            INSERT INTO indicators (indicator_id, indicator_value, indicator_type, threat_actor_group, confidence_score)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (1, "198.51.100.45", "Malicious IP", "Unknown Scanner", 85),
                (2, "203.0.113.88", "Known Bad Subnet", "Mirai Botnet Variant", 95),
                (3, "185.199.108.153", "Suspicious Endpoint", "Data Exfiltration Node", 70),
            ],
        )

        # 5. Insert Incident-Indicators Mapping (3 records)
        conn.executemany(
            """
            INSERT INTO incident_indicators (incident_id, indicator_id)
            VALUES (?, ?)
            """,
            [
                (1, 1), # Port scan maps to Malicious IP
                (2, 2), # Smart Lock attack maps to Mirai Variant
                (3, 3), # Outbound surge maps to Exfil Node
            ],
        )

        # 6. Insert Recommendations (3 records)
        conn.executemany(
            """
            INSERT INTO recommendations (recommendation_id, incident_id, recommendation_text, is_ai_generated, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (1, 1, "Ensure gateway firewall is set to drop external ICMP and unused port traffic.", 0, "2026-05-28 02:20:00"),
                (2, 2, "AI Alert: Smart Lock is under active brute force. Immediately disable external internet access to the lock via the router app.", 1, "2026-05-28 08:46:00"),
                (3, 3, "Workstation isolated from network. Run full offline malware scan before reconnecting.", 0, "2026-05-27 23:30:00"),
            ],
        )

        conn.commit()

if __name__ == "__main__":
    initialize_database()
    print(f"Database successfully created at: {DATABASE_PATH}")
    print("Aetherius Sentinel local data seeded.")