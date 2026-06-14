"""
Database access layer.

This is the single entry point for all SQLite reads and writes used by
the Streamlit app. 

"""

import json
import sqlite3
import uuid
import pandas as pd
from pathlib import Path

# Resolve DB path relative to project root so imports work from any cwd.
_PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = _PROJECT_ROOT / "data" / "project.db"


# --- Connection ---


def get_db_connection():
    """
    Create and return a connection to the SQLite database.

    Uses ``sqlite3.Row`` as the row factory so columns are accessible by name.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# --- Incident reads ---


def get_all_devices():
    """Retrieve all monitored devices on the network as a DataFrame."""
    query = """
        SELECT device_id, mac_address, device_name, device_type 
        FROM devices;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_incidents_by_severity(severity_level):
    """
    Retrieve incidents filtered by a specific severity level.

    Uses parameterized ``?`` placeholders to prevent SQL injection.
    Intended for prototype filtering demos and ad-hoc queries.
    """
    query = """
        SELECT incident_id, title, severity, status 
        FROM incidents 
        WHERE severity = ?;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn, params=(severity_level,))


def get_incidents_with_devices():
    """
    Retrieve incidents joined with their affected network devices.

    Returns device name and internal IP alongside each incident row.
    """
    query = """
        SELECT 
            incidents.incident_id, 
            incidents.title, 
            devices.device_name, 
            devices.internal_ip 
        FROM incidents 
        JOIN devices 
            ON incidents.device_id = devices.device_id;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_ai_incident_context(incident_id):
    """
    Retrieve the complete context for a specific incident to feed to the AI.

    Pulls the incident, the device, and compresses all raw event log summaries
    into a single pipe-delimited string via ``GROUP_CONCAT``.
    """
    query = """
        SELECT 
            incidents.incident_id, 
            incidents.title, 
            incidents.severity, 
            devices.device_name, 
            GROUP_CONCAT(incident_events.payload_summary, ' | ') AS event_logs
        FROM incidents
        JOIN devices 
            ON incidents.device_id = devices.device_id
        LEFT JOIN incident_events 
            ON incidents.incident_id = incident_events.incident_id
        WHERE incidents.incident_id = ?
        GROUP BY 
            incidents.incident_id, 
            incidents.title, 
            incidents.severity, 
            devices.device_name;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn, params=(incident_id,))


def get_device_count() -> int:
    """Return the total number of monitored devices."""
    query = "SELECT COUNT(*) AS count FROM devices;"
    with get_db_connection() as conn:
        row = conn.execute(query).fetchone()
    return int(row["count"])


def get_critical_incident_count() -> int:
    """Return incidents at Critical severity that are still open."""
    query = """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE severity = 'Critical'
          AND status IN ('Active', 'Investigating');
    """
    with get_db_connection() as conn:
        row = conn.execute(query).fetchone()
    return int(row["count"])


def get_incidents_this_month_count() -> int:
    """Return incidents created in the current calendar month."""
    query = """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now', 'localtime');
    """
    with get_db_connection() as conn:
        row = conn.execute(query).fetchone()
    return int(row["count"])


def get_system_status() -> str:
    """
    Summarize overall system health from open incident severities.

    Maps the worst open severity to a human-readable status label for the
    dashboard header (Operational → Critical).
    """
    query = """
        SELECT severity, COUNT(*) AS count
        FROM incidents
        WHERE status IN ('Active', 'Investigating')
        GROUP BY severity;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query).fetchall()

    # Numeric ranks let us pick the single worst severity across open incidents.
    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    worst = max(
        (severity_rank.get(row["severity"], 0) for row in rows),
        default=0,
    )
    # Threshold checks (not equality) so unknown severities still map sensibly.
    if worst >= severity_rank["Critical"]:
        return "Critical"
    if worst >= severity_rank["High"]:
        return "Degraded"
    if worst >= severity_rank["Medium"]:
        return "Elevated"
    if worst >= severity_rank["Low"]:
        return "Stable"
    # No open incidents at any severity.
    return "Operational"


def get_security_events_feed():
    """Return recent security telemetry joined with incident context."""
    query = """
        SELECT
            incident_events.timestamp AS "Time",
            incidents.title AS "Incident",
            incidents.severity AS "Severity",
            incident_events.source_ip AS "Source IP",
            incident_events.destination_ip AS "Destination IP",
            incident_events.protocol AS "Protocol",
            incident_events.payload_summary AS "Summary"
        FROM incident_events
        JOIN incidents
            ON incident_events.incident_id = incidents.incident_id
        ORDER BY incident_events.timestamp DESC;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_traffic_timeseries():
    """
    Aggregate incident-event activity into hourly traffic metrics.

    Traffic volume is a synthetic kb estimate derived from protocol type, not
    real byte counts — sufficient for prototype charts.
    """
    query = """
        SELECT
            printf('%02d:00', CAST(strftime('%H', timestamp) AS INTEGER)) AS Hour,
            COUNT(*) AS "Connection Requests",
            SUM(
                CASE protocol
                    WHEN 'UDP' THEN 500
                    WHEN 'TCP' THEN 120
                    ELSE 80
                END
            ) AS "Traffic Volume (kb)"
        FROM incident_events
        GROUP BY strftime('%H', timestamp)
        ORDER BY strftime('%H', timestamp);
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_incidents_list():
    """Return incidents joined with device names for the standard-mode list."""
    query = """
        SELECT
            incidents.incident_id AS "ID",
            incidents.title AS "Title",
            incidents.severity AS "Severity",
            incidents.status AS "Status",
            devices.device_name AS "Device"
        FROM incidents
        JOIN devices ON incidents.device_id = devices.device_id
        ORDER BY incidents.created_at DESC;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_incident_by_id(incident_id: int):
    """Return a single incident row with device context and top threat indicator."""
    query = """
        SELECT
            incidents.incident_id,
            incidents.device_id,
            incidents.title,
            incidents.severity,
            incidents.status,
            incidents.created_at,
            incidents.acknowledged_at,
            incidents.monitor_until,
            incidents.authority_recommended,
            devices.device_name,
            devices.device_type,
            devices.internal_ip,
            devices.mac_address,
            devices.owner_name,
            (
                SELECT indicators.indicator_value
                FROM incident_indicators
                JOIN indicators
                    ON incident_indicators.indicator_id = indicators.indicator_id
                WHERE incident_indicators.incident_id = incidents.incident_id
                ORDER BY indicators.confidence_score DESC
                LIMIT 1
            ) AS primary_indicator
        FROM incidents
        JOIN devices ON incidents.device_id = devices.device_id
        WHERE incidents.incident_id = ?;
    """
    with get_db_connection() as conn:
        row = conn.execute(query, (incident_id,)).fetchone()
    return dict(row) if row else None


def get_open_incidents() -> list[dict]:
    """Return active or investigating incidents with device and indicator context."""
    query = """
        SELECT
            incidents.incident_id,
            incidents.device_id,
            incidents.title,
            incidents.severity,
            incidents.status,
            incidents.created_at,
            devices.device_name,
            devices.internal_ip,
            devices.mac_address,
            (
                SELECT indicators.indicator_value
                FROM incident_indicators
                JOIN indicators
                    ON incident_indicators.indicator_id = indicators.indicator_id
                WHERE incident_indicators.incident_id = incidents.incident_id
                ORDER BY indicators.confidence_score DESC
                LIMIT 1
            ) AS primary_indicator
        FROM incidents
        JOIN devices ON incidents.device_id = devices.device_id
        WHERE incidents.status IN ('Active', 'Investigating')
        ORDER BY
            CASE incidents.severity
                WHEN 'Critical' THEN 4
                WHEN 'High' THEN 3
                WHEN 'Medium' THEN 2
                ELSE 1
            END DESC,
            incidents.created_at DESC;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query).fetchall()
    return [dict(row) for row in rows]


# --- Writes ---


def insert_incident(device_id: int, title: str, severity: str, status: str = "Active") -> int:
    """Insert a new incident and return its incident_id."""
    query = """
        INSERT INTO incidents (device_id, title, severity, status, created_at)
        VALUES (?, ?, ?, ?, datetime('now'));
    """
    with get_db_connection() as conn:
        cursor = conn.execute(query, (device_id, title, severity, status))
        conn.commit()
        return int(cursor.lastrowid)


# --- Chat ---


def create_session_id() -> str:
    """Generate a new UUID session identifier for a chat thread."""
    return str(uuid.uuid4())


def save_chat_message(
    session_id: str,
    role: str,
    content: str,
    incident_id: int | None = None,
) -> int:
    """
    Persist a chat message and return message_id.

    ``incident_id`` may be None for general (non-incident) conversations.
    """
    query = """
        INSERT INTO chat_messages (session_id, incident_id, role, content, created_at)
        VALUES (?, ?, ?, ?, datetime('now'));
    """
    with get_db_connection() as conn:
        cursor = conn.execute(query, (session_id, incident_id, role, content))
        conn.commit()
        return int(cursor.lastrowid)


def get_messages_for_session(session_id: str) -> list[dict]:
    """Return ordered messages for a session as role/content dicts."""
    query = """
        SELECT role, content
        FROM chat_messages
        WHERE session_id = ?
        ORDER BY message_id ASC;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query, (session_id,)).fetchall()
    return [{"role": row["role"], "content": row["content"]} for row in rows]


def count_sessions_for_incident(incident_id: int) -> int:
    """Count distinct chat sessions linked to an incident."""
    query = """
        SELECT COUNT(DISTINCT session_id) AS count
        FROM chat_messages
        WHERE incident_id = ?;
    """
    with get_db_connection() as conn:
        row = conn.execute(query, (incident_id,)).fetchone()
    return int(row["count"])


def get_sessions_for_incident(incident_id: int) -> list[dict]:
    """Return session summaries for an incident, newest first."""
    query = """
        SELECT
            session_id,
            MIN(created_at) AS started_at,
            MAX(created_at) AS last_activity,
            COUNT(*) AS message_count
        FROM chat_messages
        WHERE incident_id = ?
        GROUP BY session_id
        ORDER BY last_activity DESC;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query, (incident_id,)).fetchall()
    return [dict(row) for row in rows]


def get_session_history(limit: int = 20) -> list[dict]:
    """Return recent chat sessions with preview text and incident context."""
    query = """
        SELECT
            cm.session_id,
            cm.incident_id,
            COALESCE(i.title, 'General chat') AS incident_title,
            MAX(cm.created_at) AS last_activity,
            MIN(cm.created_at) AS started_at,
            COUNT(*) AS message_count,
            (
                SELECT content
                FROM chat_messages
                WHERE session_id = cm.session_id
                ORDER BY message_id DESC
                LIMIT 1
            ) AS last_message
        FROM chat_messages cm
        LEFT JOIN incidents i ON cm.incident_id = i.incident_id
        GROUP BY cm.session_id
        ORDER BY last_activity DESC
        LIMIT ?;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query, (limit,)).fetchall()
    return [dict(row) for row in rows]


def get_session_incident_id(session_id: str) -> int | None:
    """Return the incident_id for a session, if any."""
    query = """
        SELECT incident_id
        FROM chat_messages
        WHERE session_id = ?
        LIMIT 1;
    """
    with get_db_connection() as conn:
        row = conn.execute(query, (session_id,)).fetchone()
    if not row or row["incident_id"] is None:
        return None
    return int(row["incident_id"])


# --- Incident reads (dashboard & expert) ---


def get_connected_hardware():
    """
    Return the current inventory of connected network devices.

    Column aliases match the standard-mode hardware table headers.
    """
    query = """
        SELECT
            device_name AS "Device",
            device_type AS "Type",
            mac_address AS "MAC Address",
            internal_ip AS "IP Address",
            owner_name AS "Owner"
        FROM devices
        ORDER BY device_name;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_open_incident_count() -> int:
    """Return count of active or investigating incidents."""
    query = """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE status IN ('Active', 'Investigating');
    """
    with get_db_connection() as conn:
        row = conn.execute(query).fetchone()
    return int(row["count"])


def get_expert_incidents_list():
    """Return incidents with device context for expert-mode list."""
    query = """
        SELECT
            incidents.incident_id AS "ID",
            incidents.title AS "Title",
            incidents.severity AS "Severity",
            incidents.status AS "Status",
            devices.device_name AS "Device",
            devices.internal_ip AS "IP",
            incidents.created_at AS "Created",
            (
                SELECT COUNT(*)
                FROM incident_events
                WHERE incident_events.incident_id = incidents.incident_id
            ) AS "Events"
        FROM incidents
        JOIN devices ON incidents.device_id = devices.device_id
        ORDER BY
            CASE incidents.severity
                WHEN 'Critical' THEN 4
                WHEN 'High' THEN 3
                WHEN 'Medium' THEN 2
                ELSE 1
            END DESC,
            incidents.created_at DESC;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_incidents_filtered(severity=None, status=None):
    """
    Return incidents filtered by optional severity and status.

    Builds the WHERE clause dynamically; ``"All"`` means no filter for that axis.
    """
    query = """
        SELECT
            incidents.incident_id AS "ID",
            incidents.title AS "Title",
            incidents.severity AS "Severity",
            incidents.status AS "Status",
            devices.device_name AS "Device",
            devices.internal_ip AS "IP",
            incidents.created_at AS "Created",
            (
                SELECT COUNT(*)
                FROM incident_events
                WHERE incident_events.incident_id = incidents.incident_id
            ) AS "Events"
        FROM incidents
        JOIN devices ON incidents.device_id = devices.device_id
        WHERE 1=1
    """
    params = []
    # Append optional filters only when the UI did not choose "All".
    if severity and severity != "All":
        query += " AND incidents.severity = ?"
        params.append(severity)
    if status and status != "All":
        query += " AND incidents.status = ?"
        params.append(status)
    query += """
        ORDER BY
            CASE incidents.severity
                WHEN 'Critical' THEN 4
                WHEN 'High' THEN 3
                WHEN 'Medium' THEN 2
                ELSE 1
            END DESC,
            incidents.created_at DESC;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn, params=params)


def get_incident_events(incident_id: int):
    """Return security events for a single incident."""
    query = """
        SELECT
            incident_events.timestamp AS "Time",
            incident_events.source_ip AS "Source IP",
            incident_events.destination_ip AS "Destination IP",
            incident_events.protocol AS "Protocol",
            incident_events.payload_summary AS "Summary"
        FROM incident_events
        WHERE incident_events.incident_id = ?
        ORDER BY incident_events.timestamp DESC;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn, params=(incident_id,))


def get_incidents_by_severity_counts():
    """Return incident counts grouped by severity for charting."""
    query = """
        SELECT severity AS "Severity", COUNT(*) AS "Count"
        FROM incidents
        GROUP BY severity
        ORDER BY
            CASE severity
                WHEN 'Critical' THEN 4
                WHEN 'High' THEN 3
                WHEN 'Medium' THEN 2
                ELSE 1
            END DESC;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_event_volume_timeseries(hours: int = 48):
    """
    Return hourly event counts for the last N hours.

    Uses SQLite ``datetime('now', ?)`` with a negative offset string.
    """
    query = """
        SELECT
            strftime('%m/%d %H:00', timestamp) AS "Hour",
            COUNT(*) AS "Events"
        FROM incident_events
        WHERE timestamp >= datetime('now', ?)
        GROUP BY strftime('%Y-%m-%d %H', timestamp)
        ORDER BY strftime('%Y-%m-%d %H', timestamp);
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn, params=(f"-{hours} hours",))


def get_security_events_ticker(limit: int = 25):
    """Return compact recent security events for the overview ticker."""
    query = """
        SELECT
            incident_events.timestamp AS "Time",
            incidents.severity AS "Severity",
            incidents.title AS "Incident",
            incident_events.payload_summary AS "Summary"
        FROM incident_events
        JOIN incidents ON incident_events.incident_id = incidents.incident_id
        ORDER BY incident_events.timestamp DESC
        LIMIT ?;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn, params=(limit,))


def get_recommendations_for_incident(incident_id: int) -> list[dict]:
    """Return all recommendations for an incident, ordered for display."""
    query = """
        SELECT
            recommendation_id,
            incident_id,
            recommendation_text,
            is_ai_generated,
            recommendation_type,
            playbook_actions_json,
            display_order,
            is_active,
            created_at
        FROM recommendations
        WHERE incident_id = ? AND is_active = 1
        ORDER BY display_order ASC, created_at ASC;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query, (incident_id,)).fetchall()
    return [dict(row) for row in rows]


def get_active_playbook_recommendation(incident_id: int) -> dict | None:
    """Return the latest active playbook recommendation for an incident."""
    query = """
        SELECT
            recommendation_id,
            recommendation_text,
            playbook_actions_json,
            created_at
        FROM recommendations
        WHERE incident_id = ?
          AND recommendation_type = 'playbook'
          AND is_active = 1
        ORDER BY created_at DESC
        LIMIT 1;
    """
    with get_db_connection() as conn:
        row = conn.execute(query, (incident_id,)).fetchone()
    return dict(row) if row else None


# --- Writes (recommendations, actions, incidents) ---


def insert_recommendation(
    incident_id: int,
    recommendation_text: str,
    *,
    recommendation_type: str = "general",
    playbook_actions_json: str | None = None,
    is_ai_generated: int = 1,
    display_order: int = 0,
) -> int:
    """Insert a recommendation row and return its recommendation_id."""
    query = """
        INSERT INTO recommendations (
            incident_id, recommendation_text, is_ai_generated,
            recommendation_type, playbook_actions_json, display_order, is_active, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 1, datetime('now'));
    """
    with get_db_connection() as conn:
        cursor = conn.execute(
            query,
            (
                incident_id,
                recommendation_text,
                is_ai_generated,
                recommendation_type,
                playbook_actions_json,
                display_order,
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def insert_playbook_recommendation(
    incident_id: int,
    recommendation_text: str,
    action_keys: list[str],
) -> int:
    """Convenience wrapper that stores playbook action keys as JSON."""
    return insert_recommendation(
        incident_id,
        recommendation_text,
        recommendation_type="playbook",
        playbook_actions_json=json.dumps(action_keys),
        is_ai_generated=1,
        display_order=0,
    )


def get_incident_actions_list(incident_id: int) -> list[dict]:
    """Return actions taken on an incident, oldest first."""
    query = """
        SELECT
            action_id,
            incident_id,
            action_key,
            action_category,
            status,
            payload_json,
            result_summary,
            is_automated,
            is_recommended,
            playbook_order,
            created_at,
            completed_at
        FROM incident_actions
        WHERE incident_id = ?
        ORDER BY created_at ASC, action_id ASC;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query, (incident_id,)).fetchall()
    return [dict(row) for row in rows]


def get_incident_action_keys_completed(incident_id: int) -> set[str]:
    """Return the set of action_key values already marked completed for an incident."""
    query = """
        SELECT action_key
        FROM incident_actions
        WHERE incident_id = ? AND status = 'completed';
    """
    with get_db_connection() as conn:
        rows = conn.execute(query, (incident_id,)).fetchall()
    return {row["action_key"] for row in rows}


def insert_incident_action(
    incident_id: int,
    action_key: str,
    action_category: str,
    result_summary: str,
    *,
    payload: dict | None = None,
    is_automated: int = 0,
    is_recommended: int = 0,
    playbook_order: int | None = None,
    status: str = "completed",
) -> int:
    """Record an action taken on an incident; serializes optional payload to JSON."""
    payload_json = json.dumps(payload) if payload else None
    query = """
        INSERT INTO incident_actions (
            incident_id, action_key, action_category, status,
            payload_json, result_summary, is_automated, is_recommended,
            playbook_order, created_at, completed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'));
    """
    with get_db_connection() as conn:
        cursor = conn.execute(
            query,
            (
                incident_id,
                action_key,
                action_category,
                status,
                payload_json,
                result_summary,
                is_automated,
                is_recommended,
                playbook_order,
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def insert_incident_event(
    incident_id: int,
    source_ip: str,
    destination_ip: str,
    protocol: str,
    payload_summary: str,
) -> int:
    """Append a security telemetry event to an incident timeline."""
    query = """
        INSERT INTO incident_events (
            incident_id, timestamp, source_ip, destination_ip, protocol, payload_summary
        )
        VALUES (?, datetime('now'), ?, ?, ?, ?);
    """
    with get_db_connection() as conn:
        cursor = conn.execute(
            query,
            (incident_id, source_ip, destination_ip, protocol, payload_summary),
        )
        conn.commit()
        return int(cursor.lastrowid)


def insert_indicator_for_incident(
    incident_id: int,
    indicator_value: str,
    indicator_type: str,
    threat_actor_group: str,
    confidence_score: int,
) -> int:
    """
    Insert an indicator and link it to an incident.

    Creates both the ``indicators`` row and the ``incident_indicators`` join row
    in a single connection scope.
    """
    with get_db_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO indicators (indicator_value, indicator_type, threat_actor_group, confidence_score)
            VALUES (?, ?, ?, ?);
            """,
            (indicator_value, indicator_type, threat_actor_group, confidence_score),
        )
        indicator_id = int(cursor.lastrowid)
        # Many-to-many link table ties the IOC to this specific incident.
        conn.execute(
            "INSERT INTO incident_indicators (incident_id, indicator_id) VALUES (?, ?);",
            (incident_id, indicator_id),
        )
        conn.commit()
        return indicator_id


def update_incident_status(
    incident_id: int,
    status: str,
    *,
    monitor_until: str | None = None,
    authority_recommended: int | None = None,
) -> None:
    """Update incident status and optionally set monitor_until or authority_recommended."""
    fields = ["status = ?"]
    params: list = [status]
    # Only touch optional columns when the caller explicitly passes them.
    if monitor_until is not None:
        fields.append("monitor_until = ?")
        params.append(monitor_until)
    if authority_recommended is not None:
        fields.append("authority_recommended = ?")
        params.append(authority_recommended)
    params.append(incident_id)
    query = f"UPDATE incidents SET {', '.join(fields)} WHERE incident_id = ?;"
    with get_db_connection() as conn:
        conn.execute(query, params)
        conn.commit()


def acknowledge_incident(incident_id: int) -> None:
    """Mark an incident as acknowledged and move status to Investigating (idempotent)."""
    query = """
        UPDATE incidents
        SET acknowledged_at = datetime('now'),
            status = 'Investigating'
        WHERE incident_id = ? AND acknowledged_at IS NULL;
    """
    with get_db_connection() as conn:
        conn.execute(query, (incident_id,))
        conn.commit()


def is_incident_acknowledged(incident_id: int) -> bool:
    """Return True if acknowledged_at is set for the incident."""
    query = "SELECT acknowledged_at FROM incidents WHERE incident_id = ?;"
    with get_db_connection() as conn:
        row = conn.execute(query, (incident_id,)).fetchone()
    return bool(row and row["acknowledged_at"])


def create_incident_with_investigation(
    device_id: int,
    title: str,
    severity: str,
    *,
    device_name: str = "Unknown device",
    device_type: str = "Other",
    internal_ip: str = "192.168.1.1",
    mac_address: str = "00:00:00:00:00:00",
    scenario_key: str | None = None,
    indicator: str | None = None,
) -> int:
    """
    Insert incident and run automated investigation actions.

    This is the runtime entry point when the user or AI creates a new incident:
    it always runs fingerprint + ping_sweep, then optionally seeds scenario-specific
    events and indicators when ``scenario_key`` and ``indicator`` are provided.
    """
    # Lazy imports avoid circular dependency with action_catalog / scenario_telemetry.
    from action_catalog import simulate_investigation_summaries
    from scenario_telemetry import get_scenario_events, get_scenario_indicator, scenario_authority_recommended

    incident_id = insert_incident(device_id, title, severity, "Active")
    # Context dict mirrors what action_catalog formatters expect.
    incident_ctx = {
        "device_name": device_name,
        "device_type": device_type,
        "internal_ip": internal_ip,
        "mac_address": mac_address,
        "source": device_name,
        "key": scenario_key,
        "indicator": indicator or internal_ip,
    }
    fp_summary, sweep_summary = simulate_investigation_summaries(incident_ctx)
    # Every new incident gets the same two automated investigation steps first.
    insert_incident_action(
        incident_id,
        "fingerprint_device",
        "investigation",
        fp_summary,
        is_automated=1,
    )
    insert_incident_action(
        incident_id,
        "ping_sweep",
        "investigation",
        sweep_summary,
        is_automated=1,
    )

    if scenario_key and indicator:
        # Rich demo path: replay scripted telemetry from scenario_telemetry templates.
        for src, dst, proto, summary in get_scenario_events(scenario_key, internal_ip, indicator):
            insert_incident_event(incident_id, src, dst, proto, summary)
        meta = get_scenario_indicator(scenario_key, indicator)
        insert_indicator_for_incident(
            incident_id,
            meta["indicator_value"],
            meta["indicator_type"],
            meta["threat_actor_group"],
            meta["confidence_score"],
        )
        # Flag law-enforcement notice for high-severity scenarios that warrant it.
        if scenario_authority_recommended(scenario_key, severity):
            update_incident_status(incident_id, "Active", authority_recommended=1)
    else:
        # Minimal path: generic ICMP events when no scenario template applies.
        insert_incident_event(
            incident_id,
            internal_ip,
            "192.168.1.0/24",
            "ICMP",
            f"Auto fingerprint completed for {device_name}",
        )
        insert_incident_event(
            incident_id,
            internal_ip,
            "192.168.1.255",
            "ICMP",
            "Auto ping sweep completed on local subnet",
        )
    return incident_id


# --- Module self-test ---


if __name__ == "__main__":
    print("=== Testing Aetherius Sentinel Database Access Layer ===\n")
    print("DB_PATH:", DB_PATH)
    print("\n1. All Network Devices:")
    print(get_all_devices())
    print("-" * 50)
    print("\n2. Incidents list:")
    print(get_incidents_list())
    print("-" * 50)
    print("\n3. Session history:")
    print(get_session_history(3))
