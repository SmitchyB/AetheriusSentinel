"""Database access layer for Aetherius Sentinel."""

import json
import sqlite3
import uuid
import pandas as pd
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants — database file path
# ---------------------------------------------------------------------------
# Resolve DB path relative to project root so imports work from any cwd.
# ``data/`` may be created by seed.py on first run; path is stable across imports.
_PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = _PROJECT_ROOT / "data" / "project.db"


# ---------------------------------------------------------------------------
# Connection, schema bootstrap, and chat-session migration
# ---------------------------------------------------------------------------
# Every public read/write flows through get_db_connection(), which ensures
# the on-disk schema matches what this code expects before handing back conn.


def get_db_connection():
    """Open a SQLite connection and run idempotent schema migrations."""
    conn = sqlite3.connect(DB_PATH)
    # Row factory: named column access without manual index bookkeeping.
    conn.row_factory = sqlite3.Row
    # Idempotent migrations — safe on every connect (dev DBs may predate schema.sql).
    ensure_incident_updates_schema(conn)
    ensure_incidents_chat_session_schema(conn)
    migrate_incident_chat_sessions(conn)
    return conn

def ensure_incident_updates_schema(conn: sqlite3.Connection | None = None) -> None:
    """Create ``incident_updates`` table and indexes on legacy databases."""
    owns_conn = conn is None
    if owns_conn:
        conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_updates (
            update_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            update_type TEXT NOT NULL,
            title TEXT NOT NULL,
            summary_text TEXT,
            payload_json TEXT,
            created_at TEXT NOT NULL,
            acknowledged_at TEXT,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        );
        """
    )
    # Index for FK lookups: "all updates for incident X".
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_incident_updates_incident "
        "ON incident_updates(incident_id);"
    )
    # Composite index supports WHERE acknowledged_at IS NULL filters efficiently.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_incident_updates_pending "
        "ON incident_updates(incident_id, acknowledged_at);"
    )
    conn.commit()
    if owns_conn:
        conn.close()

def ensure_incidents_chat_session_schema(conn: sqlite3.Connection | None = None) -> None:
    """Add ``incidents.chat_session_id`` column and index on existing databases."""
    owns_conn = conn is None
    if owns_conn:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
    try:
        conn.execute("ALTER TABLE incidents ADD COLUMN chat_session_id TEXT;")
    except sqlite3.OperationalError as error:
        # Expected on databases that already ran this migration once.
        if "duplicate column name" not in str(error).lower():
            raise
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_chat_session "
        "ON incidents(chat_session_id);"
    )
    conn.commit()
    if owns_conn:
        conn.close()

def migrate_incident_chat_sessions(conn: sqlite3.Connection | None = None) -> None:
    """Merge legacy multi-session incident chats into one canonical session."""
    owns_conn = conn is None
    if owns_conn:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

    # Fast exit: skip heavy GROUP BY when no incident needs merging.
    needs_migration = conn.execute(
        """
        SELECT 1
        FROM incidents i
        WHERE EXISTS (
            SELECT 1 FROM chat_messages cm WHERE cm.incident_id = i.incident_id
        )
        AND (
            i.chat_session_id IS NULL
            OR (
                SELECT COUNT(DISTINCT session_id)
                FROM chat_messages
                WHERE incident_id = i.incident_id
            ) > 1
        )
        LIMIT 1;
        """
    ).fetchone()
    if not needs_migration:
        if owns_conn:
            conn.close()
        return

    # Enumerate every (incident, session) pair; earliest started_at wins per incident.
    rows = conn.execute(
        """
        SELECT
            incident_id,
            session_id,
            MIN(created_at) AS started_at
        FROM chat_messages
        WHERE incident_id IS NOT NULL
        GROUP BY incident_id, session_id
        ORDER BY incident_id, started_at ASC;
        """
    ).fetchall()

    # First row per incident_id in sorted order becomes canonical session UUID.
    canonical_by_incident: dict[int, str] = {}
    for row in rows:
        incident_id = int(row["incident_id"])
        if incident_id not in canonical_by_incident:
            canonical_by_incident[incident_id] = row["session_id"]

    for incident_id, canonical_session_id in canonical_by_incident.items():
        # Rewrite all messages for this incident to share one session_id.
        conn.execute(
            """
            UPDATE chat_messages
            SET session_id = ?
            WHERE incident_id = ?;
            """,
            (canonical_session_id, incident_id),
        )
        # Denormalized pointer on incidents for O(1) session lookup in UI.
        conn.execute(
            """
            UPDATE incidents
            SET chat_session_id = ?
            WHERE incident_id = ?;
            """,
            (canonical_session_id, incident_id),
        )

    conn.commit()
    if owns_conn:
        conn.close()


# ---------------------------------------------------------------------------
# Incident reads — prototypes, AI context, and dashboard aggregates
# ---------------------------------------------------------------------------
# Functions below mostly return pandas DataFrames for charts/tables or scalar
# counts for KPI badges. Parameterized queries use ? placeholders throughout.

def get_all_devices():
    """Retrieve all monitored network devices as a pandas DataFrame."""
    query = """
        SELECT device_id, mac_address, device_name, device_type, internal_ip
        FROM devices;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)

def get_incidents_by_severity(severity_level):
    """Retrieve incidents filtered by a specific severity level."""
    query = """
        SELECT incident_id, title, severity, status 
        FROM incidents 
        WHERE severity = ?;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn, params=(severity_level,))

def get_incidents_with_devices():
    """Retrieve incidents joined with their affected network devices."""
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
    """Retrieve compressed incident context for LLM prompt assembly."""
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
    """Return total number of monitored devices."""
    query = "SELECT COUNT(*) AS count FROM devices;"
    with get_db_connection() as conn:
        row = conn.execute(query).fetchone()
    return int(row["count"])

def get_critical_incident_count() -> int:
    """Count open incidents at Critical severity."""
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
    """Count incidents created in the current calendar month (local time)."""
    query = """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now', 'localtime');
    """
    with get_db_connection() as conn:
        row = conn.execute(query).fetchone()
    return int(row["count"])

def get_system_status() -> str:
    """Summarize overall system health from open incident severities."""
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
    """Aggregate incident-event activity into hourly traffic metrics."""
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
    """Return incidents joined with device names for standard-mode list."""
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
    # sqlite3.Row → plain dict for Streamlit/JSON compatibility.
    return dict(row) if row else None

def get_open_incidents() -> list[dict]:
    """Return unacknowledged Active alerts with device and indicator context."""
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
        WHERE incidents.status = 'Active'
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


# ---------------------------------------------------------------------------
# Incident writes — core INSERT paths
# ---------------------------------------------------------------------------
# Mutations commit explicitly; each function opens its own connection scope.


def insert_incident(device_id: int, title: str, severity: str, status: str = "Active") -> int:
    """Insert a new incident row and return its primary key."""
    query = """
        INSERT INTO incidents (device_id, title, severity, status, created_at)
        VALUES (?, ?, ?, ?, datetime('now'));
    """
    with get_db_connection() as conn:
        cursor = conn.execute(query, (device_id, title, severity, status))
        conn.commit()
        return int(cursor.lastrowid)


# ---------------------------------------------------------------------------
# Chat persistence — sessions, messages, and canonical incident threads
# ---------------------------------------------------------------------------
# Chat history feeds Streamlit drawers and ai_service.py prompt assembly.
# One canonical session_id per incident is stored on incidents.chat_session_id.

def create_session_id() -> str:
    """Generate a new UUID string for a chat thread."""
    return str(uuid.uuid4())

def save_chat_message(
    session_id: str,
    role: str,
    content: str,
    incident_id: int | None = None,
) -> int:
    """Persist one chat message and return its message_id."""
    query = """
        INSERT INTO chat_messages (session_id, incident_id, role, content, created_at)
        VALUES (?, ?, ?, ?, datetime('now'));
    """
    with get_db_connection() as conn:
        cursor = conn.execute(query, (session_id, incident_id, role, content))
        conn.commit()
        return int(cursor.lastrowid)

def get_messages_for_session(session_id: str) -> list[dict]:
    """Return ordered messages for one session as role/content dicts."""
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
    """Return per-session summary rows for an incident, newest activity first."""
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

def get_all_messages_for_incident(incident_id: int, *, limit: int = 40) -> list[dict]:
    """Return chat messages across all sessions for an incident, oldest first."""
    query = """
        SELECT role, content, created_at, session_id
        FROM chat_messages
        WHERE incident_id = ?
        ORDER BY created_at ASC, message_id ASC
        LIMIT ?;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query, (incident_id, limit)).fetchall()
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

def get_incident_id_for_chat_session(session_id: str) -> int | None:
    """Reverse-lookup incident_id from canonical ``incidents.chat_session_id``."""
    query = """
        SELECT incident_id
        FROM incidents
        WHERE chat_session_id = ?
        LIMIT 1;
    """
    with get_db_connection() as conn:
        row = conn.execute(query, (session_id,)).fetchone()
    if not row:
        return None
    return int(row["incident_id"])

def get_session_incident_id(session_id: str) -> int | None:
    """Resolve incident_id for a chat session using messages then canonical pointer."""
    from_messages = _get_session_incident_id_from_messages(session_id)
    if from_messages is not None:
        return from_messages
    return get_incident_id_for_chat_session(session_id)

def _get_session_incident_id_from_messages(session_id: str) -> int | None:
    """Private helper: read incident_id from first matching chat_messages row."""
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

def get_incident_chat_session_id(incident_id: int) -> str | None:
    """Return canonical chat session UUID stored on the incident row."""
    query = """
        SELECT chat_session_id
        FROM incidents
        WHERE incident_id = ?;
    """
    with get_db_connection() as conn:
        row = conn.execute(query, (incident_id,)).fetchone()
    if not row or not row["chat_session_id"]:
        return None
    return str(row["chat_session_id"])

def set_incident_chat_session_id(incident_id: int, session_id: str) -> None:
    """Persist canonical investigation chat session UUID on incident row."""
    query = """
        UPDATE incidents
        SET chat_session_id = ?
        WHERE incident_id = ?;
    """
    with get_db_connection() as conn:
        conn.execute(query, (session_id, incident_id))
        conn.commit()

def get_or_create_incident_chat_session(incident_id: int) -> str:
    """Return canonical session id for incident, creating UUID + DB row if missing."""
    existing = get_incident_chat_session_id(incident_id)
    if existing:
        return existing

    session_id = create_session_id()
    set_incident_chat_session_id(incident_id, session_id)
    return session_id

def session_has_messages(session_id: str) -> bool:
    """Return True when session_id has at least one persisted message."""
    query = """
        SELECT 1
        FROM chat_messages
        WHERE session_id = ?
        LIMIT 1;
    """
    with get_db_connection() as conn:
        row = conn.execute(query, (session_id,)).fetchone()
    return row is not None

def get_session_activity(session_id: str) -> str | None:
    """Return latest message timestamp for a session."""
    query = """
        SELECT MAX(created_at) AS last_activity
        FROM chat_messages
        WHERE session_id = ?;
    """
    with get_db_connection() as conn:
        row = conn.execute(query, (session_id,)).fetchone()
    if not row or not row["last_activity"]:
        return None
    return str(row["last_activity"])

def get_general_session_history(limit: int = 20) -> list[dict]:
    """Return recent general (non-incident) chat sessions only."""
    query = """
        SELECT
            cm.session_id,
            cm.incident_id,
            'General chat' AS incident_title,
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
        WHERE cm.incident_id IS NULL
        GROUP BY cm.session_id
        ORDER BY last_activity DESC
        LIMIT ?;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query, (limit,)).fetchall()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Incident reads — standard dashboard, expert mode, charts, and AI support
# ---------------------------------------------------------------------------
# Heavier JOINs, correlated subqueries for event counts, and filter builders.

def get_connected_hardware():
    """Return inventory of connected network devices for hardware table UI."""
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
    """Count incidents still in Active status (unacknowledged alerts)."""
    query = """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE status = 'Active';
    """
    with get_db_connection() as conn:
        row = conn.execute(query).fetchone()
    return int(row["count"])

def get_expert_incidents_list():
    """Return incidents with device context for expert-mode list view."""
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
    """Return incidents with optional severity and status filters for expert UI."""
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
    # WHERE 1=1 pattern avoids awkward "WHERE AND" when building dynamic SQL.
    if severity and severity != "All":
        query += " AND incidents.severity = ?"
        params.append(severity)
    if status and status not in ("All", "Open"):
        query += " AND incidents.status = ?"
        params.append(status)
    elif status == "Open":
        query += " AND incidents.status IN ('Active', 'Investigating')"
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

def get_incident_indicators(incident_id: int) -> list[dict]:
    """Return IOC (indicator) rows linked to an incident via join table."""
    query = """
        SELECT
            indicators.indicator_value,
            indicators.indicator_type,
            indicators.threat_actor_group,
            indicators.confidence_score
        FROM incident_indicators
        JOIN indicators ON incident_indicators.indicator_id = indicators.indicator_id
        WHERE incident_indicators.incident_id = ?
        ORDER BY indicators.confidence_score DESC;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query, (incident_id,)).fetchall()
    return [dict(row) for row in rows]

def get_incident_events(incident_id: int):
    """Return security telemetry events for one incident timeline."""
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
    """Return incident counts grouped by severity for pie/bar charts."""
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
    """Return hourly event counts for the last N hours."""
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
    """Return compact recent security events for overview ticker/scrolling feed."""
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
    """Return all active recommendations for an incident, display-order sorted."""
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
    """Return the latest active playbook-type recommendation for an incident."""
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


# ---------------------------------------------------------------------------
# Writes — recommendations, playbook actions, incidents, and telemetry
# ---------------------------------------------------------------------------
# AI-generated playbooks and user/sentinel actions persist here after UI events.

def insert_recommendation(
    incident_id: int,
    recommendation_text: str,
    *,
    recommendation_type: str = "general",
    playbook_actions_json: str | None = None,
    is_ai_generated: int = 1,
    display_order: int = 0,
) -> int:
    """Insert one recommendation row and return recommendation_id."""
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

def deactivate_playbook_recommendations(incident_id: int) -> None:
    """Soft-delete all active playbook recommendations before inserting a replacement."""
    query = """
        UPDATE recommendations
        SET is_active = 0
        WHERE incident_id = ?
          AND recommendation_type = 'playbook'
          AND is_active = 1;
    """
    with get_db_connection() as conn:
        conn.execute(query, (incident_id,))
        conn.commit()

def insert_playbook_recommendation(
    incident_id: int,
    recommendation_text: str,
    action_keys: list[str],
) -> int:
    """Convenience wrapper: store playbook recommendation with JSON action keys."""
    return insert_recommendation(
        incident_id,
        recommendation_text,
        recommendation_type="playbook",
        playbook_actions_json=json.dumps(action_keys),
        is_ai_generated=1,
        display_order=0,
    )

def get_incident_actions_list(incident_id: int) -> list[dict]:
    """Return chronological list of actions taken on an incident."""
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
    """Return set of action_key values already marked completed for an incident."""
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
    """Record an action taken on an incident; optional payload serialized to JSON."""
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
    """Append one security telemetry event to an incident timeline."""
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
    """Insert an IOC indicator and link it to an incident (many-to-many)."""
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
    """Update incident status and optionally monitor_until or authority_recommended."""
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
    # f-string builds SET clause from whitelisted field names only — values still bound.
    query = f"UPDATE incidents SET {', '.join(fields)} WHERE incident_id = ?;"
    with get_db_connection() as conn:
        conn.execute(query, params)
        conn.commit()

def acknowledge_incident(incident_id: int) -> None:
    """Mark incident acknowledged and move status to Investigating (idempotent)."""
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
    """Return True when acknowledged_at timestamp is set on the incident."""
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
    """Insert incident and run automated investigation actions (high-level orchestrator)."""
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


# ---------------------------------------------------------------------------
# Incident updates — two-tier alert system (pending updates + acknowledgment)
# ---------------------------------------------------------------------------
# Supports temporal narrative beats: new alerts layer on top of base incidents.

def clear_monitor_until(incident_id: int) -> None:
    """Clear the monitoring gate timestamp on an incident."""
    query = "UPDATE incidents SET monitor_until = NULL WHERE incident_id = ?;"
    with get_db_connection() as conn:
        conn.execute(query, (incident_id,))
        conn.commit()

def insert_incident_update(
    incident_id: int,
    update_type: str,
    title: str,
    *,
    summary_text: str = "",
    payload: dict | None = None,
) -> int | None:
    """Insert a pending incident update alert (deduplicated by type)."""
    with get_db_connection() as conn:
        # Dedupe: one pending alert per (incident_id, update_type) at a time.
        existing = conn.execute(
            """
            SELECT update_id FROM incident_updates
            WHERE incident_id = ? AND update_type = ? AND acknowledged_at IS NULL
            LIMIT 1;
            """,
            (incident_id, update_type),
        ).fetchone()
        if existing:
            return None

        cursor = conn.execute(
            """
            INSERT INTO incident_updates (
                incident_id, update_type, title, summary_text, payload_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, datetime('now'));
            """,
            (
                incident_id,
                update_type,
                title,
                summary_text,
                json.dumps(payload) if payload else None,
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)

def get_pending_incident_updates() -> list[dict]:
    """Return unacknowledged incident updates with incident and device context."""
    query = """
        SELECT
            incident_updates.update_id,
            incident_updates.incident_id,
            incident_updates.update_type,
            incident_updates.title,
            incident_updates.summary_text,
            incident_updates.payload_json,
            incident_updates.created_at,
            incidents.title AS incident_title,
            incidents.severity,
            incidents.status,
            devices.device_name
        FROM incident_updates
        JOIN incidents ON incident_updates.incident_id = incidents.incident_id
        JOIN devices ON incidents.device_id = devices.device_id
        WHERE incident_updates.acknowledged_at IS NULL
        ORDER BY incident_updates.created_at DESC;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query).fetchall()
    return [dict(row) for row in rows]

def get_pending_update_count() -> int:
    """Count unacknowledged rows in incident_updates."""
    query = """
        SELECT COUNT(*) AS count
        FROM incident_updates
        WHERE acknowledged_at IS NULL;
    """
    with get_db_connection() as conn:
        row = conn.execute(query).fetchone()
    return int(row["count"])

def get_notification_count() -> int:
    """Compute bell badge total: new Active incidents + pending incident updates."""
    return get_open_incident_count() + get_pending_update_count()

def acknowledge_incident_update(update_id: int) -> None:
    """Mark one incident update row acknowledged (idempotent)."""
    query = """
        UPDATE incident_updates
        SET acknowledged_at = datetime('now')
        WHERE update_id = ? AND acknowledged_at IS NULL;
    """
    with get_db_connection() as conn:
        conn.execute(query, (update_id,))
        conn.commit()

def get_incident_update_by_id(update_id: int) -> dict | None:
    """Fetch single incident_updates row by primary key."""
    query = """
        SELECT
            update_id, incident_id, update_type, title, summary_text,
            payload_json, created_at, acknowledged_at
        FROM incident_updates
        WHERE update_id = ?;
    """
    with get_db_connection() as conn:
        row = conn.execute(query, (update_id,)).fetchone()
    return dict(row) if row else None

def get_updates_for_incident(incident_id: int) -> list[dict]:
    """Return all update alerts (pending and acknowledged) for one incident."""
    query = """
        SELECT
            update_id, incident_id, update_type, title, summary_text,
            payload_json, created_at, acknowledged_at
        FROM incident_updates
        WHERE incident_id = ?
        ORDER BY created_at DESC;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query, (incident_id,)).fetchall()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Device and incident context — AI grounding helpers
# ---------------------------------------------------------------------------

def get_incidents_for_device(device_id: int, *, limit: int = 10) -> list[dict]:
    """Return prior incidents on the same device for system-context grounding."""
    query = """
        SELECT incident_id, title, severity, status, created_at
        FROM incidents
        WHERE device_id = ?
        ORDER BY created_at DESC
        LIMIT ?;
    """
    with get_db_connection() as conn:
        rows = conn.execute(query, (device_id, limit)).fetchall()
    return [dict(row) for row in rows]

def get_device_row(device_id: int) -> dict | None:
    """Fetch one device row by primary key."""
    query = """
        SELECT device_id, mac_address, device_name, device_type, internal_ip, owner_name
        FROM devices
        WHERE device_id = ?;
    """
    with get_db_connection() as conn:
        row = conn.execute(query, (device_id,)).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Module self-test — run ``python db.py`` for smoke checks (no pytest required)
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    # Manual smoke test: prints sample query results when executed as a script.
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
