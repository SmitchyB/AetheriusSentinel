"""
Database access layer for Aetherius Sentinel.

Architecture
------------
This module is the **only** sanctioned entry point for SQLite reads and writes in
the project. Higher layers (Streamlit UI components, ``ai_service.py``,
``chat_sessions.py``, ``sentinel_actions.py``, ``temporal_state.py``) import
``db`` functions rather than opening connections themselves. That separation keeps
SQL, schema knowledge, and migration logic in one place so UI code stays
presentation-focused.

Database file location
----------------------
``DB_PATH`` resolves to ``<project_root>/data/project.db``, anchored to this
file's directory via ``Path(__file__).resolve().parent``. Relative resolution
matters because Streamlit may be launched from different working directories;
an absolute path derived from the module location keeps the database findable
regardless of ``cwd``.

Schema source of truth vs. runtime migrations
---------------------------------------------
The canonical schema lives in ``schema.sql`` and is applied during seeding
(``seed.py``). **Existing** developer databases may lag behind ``schema.sql``;
three lightweight migration helpers run on every connection open:

1. ``ensure_incident_updates_schema`` — creates ``incident_updates`` if missing.
2. ``ensure_incidents_chat_session_schema`` — adds ``incidents.chat_session_id``.
3. ``migrate_incident_chat_sessions`` — merges legacy multi-session chat threads.

These use ``CREATE TABLE IF NOT EXISTS``, ``ALTER TABLE`` (with duplicate-column
tolerance), and data-fix ``UPDATE`` statements. They are idempotent: safe to run
on every ``get_db_connection()`` call.

Relationship to ``ai_service.py`` and Streamlit
-----------------------------------------------
``ai_service.py`` builds LLM prompts by calling read helpers here — especially
``get_ai_incident_context``, ``get_incident_by_id``, ``get_incident_events``,
``get_incident_actions_list``, ``get_incident_indicators``,
``get_recommendations_for_incident``, and chat history functions. Streamlit
components render dashboards and forms using the ``get_*``
DataFrame/list helpers; writes flow back through ``insert_*``, ``update_*``, and
``acknowledge_*`` after user or AI actions (often via ``sentinel_actions.py``).

Connection and row access patterns
----------------------------------
- ``get_db_connection()`` returns a standard ``sqlite3.Connection`` with
  ``row_factory = sqlite3.Row`` so columns are addressable by name
  (``row["incident_id"]``) instead of numeric indices.
- Most callers use ``with get_db_connection() as conn:`` for automatic close.
- Writes typically call ``conn.commit()`` explicitly inside that block; reads
  often omit commit (SQLite autocommit mode still applies per statement).
- User-supplied values **always** bind via ``?`` placeholders — never f-string
  interpolation into SQL except for whitelisted column lists built from fixed
  literals (see ``update_incident_status``).

Return type conventions
-----------------------
- **pandas DataFrame** — chart/table UI (``pd.read_sql_query``).
- **``list[dict]``** — JSON-serializable rows for Streamlit widgets and AI context.
- **``dict | None``** — single-row lookup; ``None`` when not found.
- **``int``** — scalar counts or newly inserted primary keys (``lastrowid``).

Tables touched (overview)
-------------------------
devices, incidents, incident_events, incident_indicators, indicators,
incident_actions, recommendations, chat_messages, incident_updates.
"""

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
    """
    Open a SQLite connection and run idempotent schema migrations.

    Purpose
        Central connection factory for all database access. Callers receive a
        connection that already has ``incident_updates``, ``chat_session_id``, and
        canonical chat threads in the expected shape.

    Returns
        ``sqlite3.Connection`` with ``row_factory = sqlite3.Row``.

    Tables touched
        ``incident_updates`` (CREATE IF NOT EXISTS), ``incidents`` (ALTER/migrate),
        ``chat_messages`` (data migration UPDATEs). No reads from app tables here
        beyond migration probes.

    Called by
        Every function in this module via ``with get_db_connection() as conn``.

    Row factory rationale
        ``sqlite3.Row`` supports dict-like ``row["column"]`` access and preserves
        column names from SELECT aliases — essential for ``fetchone()`` loops that
        build ``dict(row)`` payloads for Streamlit and ``ai_service.py``.

    Transaction boundary
        Migration helpers commit their own DDL/DML when invoked; this function does
        not commit — caller-owned transactions start after return.

    Edge cases
        If ``data/project.db`` is missing, ``sqlite3.connect`` creates an empty file;
        migrations create minimal tables but full seed data requires ``seed.py``.
    """
    conn = sqlite3.connect(DB_PATH)
    # Row factory: named column access without manual index bookkeeping.
    conn.row_factory = sqlite3.Row
    # Idempotent migrations — safe on every connect (dev DBs may predate schema.sql).
    ensure_incident_updates_schema(conn)
    ensure_incidents_chat_session_schema(conn)
    migrate_incident_chat_sessions(conn)
    return conn


def ensure_incident_updates_schema(conn: sqlite3.Connection | None = None) -> None:
    """
    Create ``incident_updates`` table and indexes on legacy databases.

    Purpose
        Support the two-tier alert system (pending updates + acknowledgment)
        without forcing a full database re-seed when ``schema.sql`` was updated.

    Parameters
        conn: Optional existing connection. When ``None``, opens and closes its own.

    Returns
        ``None``.

    Tables touched
        ``incident_updates`` (CREATE TABLE IF NOT EXISTS),
        indexes ``idx_incident_updates_incident`` and ``idx_incident_updates_pending``.

    Called by
        ``get_db_connection()`` on every connect; may also be invoked standalone.

    SQL injection safety
        Static DDL only — no user input.

    Index rationale
        ``(incident_id)`` speeds per-incident update lists;
        ``(incident_id, acknowledged_at)`` speeds "pending only" badge queries.

    Transaction boundary
        Commits before return; owns connection when ``conn is None``.

    Edge cases
        Safe to run repeatedly; ``IF NOT EXISTS`` prevents duplicate object errors.
    """
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
    """
    Add ``incidents.chat_session_id`` column and index on existing databases.

    Purpose
        Persist one canonical investigation chat thread per incident (UUID string)
        without requiring developers to drop and re-seed ``project.db``.

    Parameters
        conn: Optional connection; when omitted, function opens/closes its own.

    Returns
        ``None``.

    Tables touched
        ``incidents`` (ALTER TABLE ADD COLUMN, CREATE INDEX).

    Called by
        ``get_db_connection()``; ``set_incident_chat_session_id`` relies on column.

    Migration strategy
        ``ALTER TABLE ... ADD COLUMN`` fails on second run with "duplicate column";
        we catch ``OperationalError`` and ignore only that message — other errors
        (locked DB, corrupt file) still propagate.

    Transaction boundary
        Single commit after ALTER + index creation.

    Edge cases
        Column allows NULL for incidents never linked to chat; index still helps
        ``WHERE chat_session_id = ?`` reverse lookups in ``get_incident_id_for_chat_session``.
    """
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
    """
    Merge legacy multi-session incident chats into one canonical session.

    Purpose
        Early prototypes allowed multiple ``session_id`` values per ``incident_id``
        in ``chat_messages``. This one-time-style data fix picks the earliest session
        per incident and rewrites all messages + ``incidents.chat_session_id``.

    Parameters
        conn: Optional connection; when omitted, function opens/closes its own.

    Returns
        ``None``.

    Tables touched
        ``incidents``, ``chat_messages`` (SELECT probe + UPDATE).

    Called by
        ``get_db_connection()`` before any chat reads.

    SQL notes
        EXISTS subquery detects incidents with chat rows but missing or split
        ``chat_session_id``. GROUP BY ``incident_id, session_id`` with
        MIN(created_at) picks chronological "first thread" as canonical.

    Transaction boundary
        All UPDATEs batched in one commit after loop — partial migration avoided.

    Edge cases
        No-op when probe returns no rows. Incidents with NULL ``incident_id`` in
        chat_messages are excluded from GROUP BY source query (WHERE NOT NULL).
    """
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
    """
    Retrieve all monitored network devices as a pandas DataFrame.

    Purpose
        Inventory listing for coverage demos and ``components/db_coverage.py``.

    Returns
        ``pd.DataFrame`` columns: device_id, mac_address, device_name,
        device_type, internal_ip.

    Tables touched
        ``devices`` (SELECT only).

    Called by
        Module self-test; prototype device tables.

    SQL injection safety
        Static query — no parameters.

    Edge cases
        Empty database returns zero-row DataFrame (not an error).
    """
    query = """
        SELECT device_id, mac_address, device_name, device_type, internal_ip
        FROM devices;
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_incidents_by_severity(severity_level):
    """
    Retrieve incidents filtered by a specific severity level.

    Purpose
        Ad-hoc filtering demos and severity-scoped incident lists.

    Parameters
        severity_level: str — e.g. ``"Critical"``, ``"High"`` (bound via ``?``).

    Returns
        ``pd.DataFrame`` with incident_id, title, severity, status.

    Tables touched
        ``incidents`` (SELECT WHERE severity = ?).

    SQL injection safety
        Uses parameterized ``?`` placeholder — never interpolate user input.

    Edge cases
        Unknown severity string returns empty DataFrame (no validation layer here).
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

    Purpose
        Demonstrate INNER JOIN between incidents and devices for teaching/examples.

    Returns
        ``pd.DataFrame``: incident_id, title, device_name, internal_ip.

    Tables touched
        ``incidents``, ``devices`` (INNER JOIN on device_id).

    SQL notes
        INNER JOIN excludes incidents whose device_id is orphaned (should not
        happen with FK integrity).

    Edge cases
        Incidents without matching device rows are omitted entirely.
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
    Retrieve compressed incident context for LLM prompt assembly.

    Purpose
        Primary context bundle for ``ai_service.py`` when analyzing an incident.
        Collapses many event rows into one pipe-delimited string for token economy.

    Parameters
        incident_id: int — primary key of target incident.

    Returns
        ``pd.DataFrame`` (0 or 1 rows): incident_id, title, severity,
        device_name, event_logs (GROUP_CONCAT aggregate).

    Tables touched
        ``incidents``, ``devices`` (JOIN), ``incident_events`` (LEFT JOIN).

    Called by
        ``ai_service.py`` (``build_incident_analysis_context`` and related).

    SQL notes
        LEFT JOIN + GROUP BY keeps incidents with zero events (event_logs NULL).
        GROUP_CONCAT(payload_summary, ' | ') merges chronologically unordered
        summaries — order is not guaranteed unless subquery orders first.

    SQL injection safety
        ``incident_id`` bound via ``?``.

    Edge cases
        Missing incident returns empty DataFrame; callers must handle empty.
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
    """
    Return total number of monitored devices.

    Purpose
        KPI tile / AI system-context snippet (``ai_service.py`` dashboard context).

    Returns
        int — COUNT(*) from devices.

    Tables touched
        ``devices`` (aggregate SELECT).

    Edge cases
        Returns 0 when table empty.
    """
    query = "SELECT COUNT(*) AS count FROM devices;"
    with get_db_connection() as conn:
        row = conn.execute(query).fetchone()
    return int(row["count"])


def get_critical_incident_count() -> int:
    """
    Count open incidents at Critical severity.

    Purpose
        Header health metrics and AI context (``ai_service.py``).

    Returns
        int — rows where severity='Critical' AND status IN ('Active','Investigating').

    Tables touched
        ``incidents``.

    Edge cases
        Resolved/closed Critical incidents are excluded by status filter.
    """
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
    """
    Count incidents created in the current calendar month (local time).

    Purpose
        Monthly KPI for standard/expert dashboards and AI briefing context.

    Returns
        int — filtered by strftime year-month match to ``datetime('now','localtime')``.

    Tables touched
        ``incidents``.

    SQL notes
        ``strftime('%Y-%m', created_at)`` compares stored ISO-ish timestamps;
        timezone is SQLite ``localtime`` modifier, not UTC.

    Edge cases
        Future-dated created_at rows would count if month matches.
    """
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

    Purpose
        Maps worst open severity to dashboard header label:
        Operational → Stable → Elevated → Degraded → Critical.

    Returns
        str — one of ``"Operational"``, ``"Stable"``, ``"Elevated"``,
        ``"Degraded"``, ``"Critical"``.

    Tables touched
        ``incidents`` (GROUP BY severity for Active/Investigating only).

    Called by
        ``components/header_health_badge.py``, standard dashboard header.

    Edge cases
        Unknown severity strings rank 0 via ``.get(..., 0)`` — may yield
        Operational if only unknown severities exist. No open incidents → Operational.
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
    """
    Return recent security telemetry joined with incident context.

    Purpose
        Full event feed table for standard-mode security views.

    Returns
        ``pd.DataFrame`` with aliased columns: Time, Incident, Severity,
        Source IP, Destination IP, Protocol, Summary.

    Tables touched
        ``incident_events``, ``incidents`` (INNER JOIN).

    SQL notes
        ORDER BY timestamp DESC — most recent events first; no LIMIT (full history).

    Edge cases
        Events orphaned from deleted incidents would be excluded by INNER JOIN.
    """
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

    Purpose
        Prototype chart data for connection volume and synthetic kb traffic.

    Returns
        ``pd.DataFrame``: Hour (00:00–23:00), Connection Requests, Traffic Volume (kb).

    Tables touched
        ``incident_events``.

    SQL notes
        Traffic volume is **synthetic** — CASE on protocol assigns fixed kb weights
        (UDP 500, TCP 120, else 80), not real byte counts.
        GROUP BY strftime hour bucket; printf pads hour label for display.

    Edge cases
        Hours with zero events are omitted (not zero-filled).
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
    """
    Return incidents joined with device names for standard-mode list.

    Purpose
        Primary incidents table in ``components/incidents_list.py`` / standard dashboard.

    Returns
        ``pd.DataFrame`` with display aliases: ID, Title, Severity, Status, Device.

    Tables touched
        ``incidents``, ``devices`` (JOIN).

    SQL notes
        ORDER BY created_at DESC — newest incidents surface first.
    """
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
    """
    Return a single incident row with device context and top threat indicator.

    Purpose
        Detail pane, expert incident view, and ``ai_service.py`` incident lookups.

    Parameters
        incident_id: int — primary key.

    Returns
        ``dict | None`` — full incident + device fields + primary_indicator
        (highest-confidence IOC subquery), or None if not found.

    Tables touched
        ``incidents``, ``devices``, ``incident_indicators``, ``indicators`` (subquery).

    SQL notes
        Correlated subquery picks one indicator ORDER BY confidence_score DESC LIMIT 1.

    SQL injection safety
        incident_id bound via ``?``.

    Edge cases
        Invalid id returns None; primary_indicator may be NULL when no IOCs linked.
    """
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
    """
    Return unacknowledged Active alerts with device and indicator context.

    Purpose
        Sentinel panel / open-alert widgets needing rich rows without detail page.

    Returns
        ``list[dict]`` — sorted Critical-first, then newest created_at.

    Tables touched
        ``incidents``, ``devices``, ``incident_indicators``, ``indicators`` (subquery).

    Called by
        ``components/sentinel_panel.py``, open-incident banners.

    SQL notes
        CASE severity in ORDER BY maps enum to numeric rank for stable sort.
        status = 'Active' only — Investigating incidents excluded.

    Edge cases
        Empty list when no Active incidents; primary_indicator may be NULL.
    """
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
    """
    Insert a new incident row and return its primary key.

    Purpose
        Low-level incident creation; prefer ``create_incident_with_investigation``
        for user-facing flows that need automated investigation steps.

    Parameters
        device_id, title, severity: required incident fields.
        status: defaults to ``"Active"``; created_at set via ``datetime('now')``.

    Returns
        int — ``cursor.lastrowid`` (new incident_id).

    Tables touched
        ``incidents`` (INSERT).

    Called by
        ``create_incident_with_investigation``, ``incident_scenarios.py``.

    SQL injection safety
        All values bound via ``?`` placeholders.

    Transaction boundary
        Single INSERT + commit.

    Edge cases
        Invalid device_id may fail FK constraint if schema enforces it.
    """
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
    """
    Generate a new UUID string for a chat thread.

    Purpose
        Client-side session identifier before first message persist.

    Returns
        str — ``str(uuid.uuid4())`` (36-char hyphenated UUID).

    Tables touched
        None (pure Python).

    Called by
        ``get_or_create_incident_chat_session``, ``chat_sessions.py``, Streamlit UI.
    """
    return str(uuid.uuid4())


def save_chat_message(
    session_id: str,
    role: str,
    content: str,
    incident_id: int | None = None,
) -> int:
    """
    Persist one chat message and return its message_id.

    Purpose
        Append user/assistant/system turns to ``chat_messages`` for replay in UI
        and LLM context windows.

    Parameters
        session_id: UUID thread identifier.
        role: typically ``"user"``, ``"assistant"``, or ``"system"``.
        content: message body text.
        incident_id: optional FK; None for general (non-incident) chat.

    Returns
        int — new ``message_id`` (AUTOINCREMENT).

    Tables touched
        ``chat_messages`` (INSERT).

    Called by
        ``chat_sessions.py``, expert chat drawer after AI replies.

    SQL injection safety
        All fields bound via ``?`` — content may contain arbitrary user text safely.

    Edge cases
        Duplicate session_id values are allowed historically; migration merges them.
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
    """
    Return ordered messages for one session as role/content dicts.

    Purpose
        Hydrate Streamlit ``st.session_state.messages`` and AI chat history.

    Parameters
        session_id: UUID string.

    Returns
        ``list[dict]`` — keys ``role``, ``content``; oldest first (message_id ASC).

    Tables touched
        ``chat_messages`` (SELECT).

    Called by
        ``chat_sessions.py``, ``ai_service.py`` (canonical session replay).

    SQL injection safety
        session_id bound via ``?``.

    Edge cases
        Unknown session returns empty list (not an error).
    """
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
    """
    Count distinct chat sessions linked to an incident.

    Purpose
        Diagnostics / legacy detection before canonical session migration.

    Returns
        int — COUNT(DISTINCT session_id).

    Tables touched
        ``chat_messages``.

    Edge cases
        Returns 0 when incident has no messages (even if chat_session_id set).
    """
    query = """
        SELECT COUNT(DISTINCT session_id) AS count
        FROM chat_messages
        WHERE incident_id = ?;
    """
    with get_db_connection() as conn:
        row = conn.execute(query, (incident_id,)).fetchone()
    return int(row["count"])


def get_sessions_for_incident(incident_id: int) -> list[dict]:
    """
    Return per-session summary rows for an incident, newest activity first.

    Purpose
        Session picker UI when multiple legacy threads existed pre-migration.

    Returns
        ``list[dict]``: session_id, started_at, last_activity, message_count.

    Tables touched
        ``chat_messages`` (GROUP BY session_id).

    SQL notes
        MIN/MAX(created_at) approximate thread span; COUNT(*) is message total.
    """
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
    """
    Return chat messages across all sessions for an incident, oldest first.

    Purpose
        Fallback history when canonical session_id unset; caps rows for LLM token limits.

    Parameters
        incident_id: int FK.
        limit: max rows (default 40) — bound as second ``?`` parameter.

    Returns
        ``list[dict]``: role, content, created_at, session_id.

    Tables touched
        ``chat_messages``.

    Called by
        ``ai_service.py`` when building incident chat context.

    Edge cases
        Truncates oldest messages beyond limit (ORDER ASC then LIMIT).
    """
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
    """
    Return recent chat sessions with preview text and incident context.

    Purpose
        Chat history sidebar — mixed incident-linked and general sessions.

    Parameters
        limit: max sessions (default 20), bound via ``?``.

    Returns
        ``list[dict]``: session_id, incident_id, incident_title, timestamps,
        message_count, last_message (correlated subquery).

    Tables touched
        ``chat_messages``, ``incidents`` (LEFT JOIN — general chat keeps NULL title).

    SQL notes
        Correlated subquery fetches latest message content per session.
        COALESCE(i.title, 'General chat') labels non-incident threads.

    Edge cases
        Sessions with deleted incidents still appear with NULL incident_title
        unless COALESCE applies 'General chat' only when incident_id IS NULL.
    """
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
    """
    Reverse-lookup incident_id from canonical ``incidents.chat_session_id``.

    Purpose
        Resolve which incident a drawer session belongs to when messages alone
        lack incident_id (edge case after migration).

    Parameters
        session_id: UUID stored in ``incidents.chat_session_id``.

    Returns
        int | None — incident_id or None if session is not canonical for any incident.

    Tables touched
        ``incidents`` (SELECT WHERE chat_session_id = ?).

    Called by
        ``get_session_incident_id`` as secondary lookup path.
    """
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
    """
    Resolve incident_id for a chat session using messages then canonical pointer.

    Purpose
        Unified lookup for ``chat_sessions.py`` when loading session context.

    Returns
        int | None — prefers ``chat_messages.incident_id``; falls back to
        ``incidents.chat_session_id`` reverse map.

    Tables touched
        ``chat_messages``, ``incidents`` (via helper calls).

    Edge cases
        General chat (NULL incident_id everywhere) returns None.
    """
    from_messages = _get_session_incident_id_from_messages(session_id)
    if from_messages is not None:
        return from_messages
    return get_incident_id_for_chat_session(session_id)


def _get_session_incident_id_from_messages(session_id: str) -> int | None:
    """
    Private helper: read incident_id from first matching chat_messages row.

    Purpose
        Primary path for ``get_session_incident_id`` — messages are source of truth
        when incident_id column was populated at insert time.

    Returns
        int | None — None when no rows or incident_id IS NULL.

    Tables touched
        ``chat_messages`` (SELECT LIMIT 1).

    Note
        Leading underscore: internal; callers should use ``get_session_incident_id``.
    """
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
    """
    Return canonical chat session UUID stored on the incident row.

    Purpose
        Open correct thread in expert chat drawer; preferred by ``ai_service.py``.

    Returns
        str | None — empty/NULL chat_session_id yields None.

    Tables touched
        ``incidents``.
    """
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
    """
    Persist canonical investigation chat session UUID on incident row.

    Purpose
        Link newly created or migrated session to incident for O(1) lookup.

    Tables touched
        ``incidents`` (UPDATE chat_session_id).

    Transaction boundary
        Single UPDATE + commit.
    """
    query = """
        UPDATE incidents
        SET chat_session_id = ?
        WHERE incident_id = ?;
    """
    with get_db_connection() as conn:
        conn.execute(query, (session_id, incident_id))
        conn.commit()


def get_or_create_incident_chat_session(incident_id: int) -> str:
    """
    Return canonical session id for incident, creating UUID + DB row if missing.

    Purpose
        Idempotent session acquisition for chat drawer on incident detail pages.

    Returns
        str — existing or newly created session_id.

    Tables touched
        ``incidents`` (read via get_incident_chat_session_id, write via set_*).

    Edge cases
        Race: two concurrent creates could theoretically assign different UUIDs;
        last write wins on incidents row (acceptable for local Streamlit app).
    """
    existing = get_incident_chat_session_id(incident_id)
    if existing:
        return existing

    session_id = create_session_id()
    set_incident_chat_session_id(incident_id, session_id)
    return session_id


def session_has_messages(session_id: str) -> bool:
    """
    Return True when session_id has at least one persisted message.

    Purpose
        Skip empty-session UI states; guard before deleting orphan sessions.

    Tables touched
        ``chat_messages`` (EXISTS-style SELECT 1 LIMIT 1).
    """
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
    """
    Return latest message timestamp for a session.

    Purpose
        Sort/display "last active" in session history lists.

    Returns
        str | None — MAX(created_at) as string, or None if no messages.

    Tables touched
        ``chat_messages``.
    """
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
    """
    Return recent general (non-incident) chat sessions only.

    Purpose
        Separate history list where ``incident_id IS NULL`` in chat_messages.

    Returns
        Same shape as ``get_session_history`` but incident_title always
        ``'General chat'``.

    Tables touched
        ``chat_messages`` (filtered, no incidents JOIN).

    Edge cases
        Incident-linked messages accidentally saved with NULL incident_id appear here.
    """
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
    """
    Return inventory of connected network devices for hardware table UI.

    Purpose
        Standard-mode device table; column aliases match Streamlit header labels.

    Returns
        ``pd.DataFrame``: Device, Type, MAC Address, IP Address, Owner.

    Tables touched
        ``devices``.

    Called by
        ``components/standard_dashboard.py``, ``ai_service.py`` (system context).
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
    """
    Count incidents still in Active status (unacknowledged alerts).

    Purpose
        Notification badge component; part of ``get_notification_count`` sum.

    Returns
        int — WHERE status = 'Active' (Investigating not included).

    Tables touched
        ``incidents``.

    Called by
        ``components/expert_notifications.py``, ``get_notification_count``.
    """
    query = """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE status = 'Active';
    """
    with get_db_connection() as conn:
        row = conn.execute(query).fetchone()
    return int(row["count"])


def get_expert_incidents_list():
    """
    Return incidents with device context for expert-mode list view.

    Purpose
        Richer table than standard list — includes IP, Created, correlated Events count.

    Returns
        ``pd.DataFrame`` with expert column aliases; sorted severity then recency.

    Tables touched
        ``incidents``, ``devices``, ``incident_events`` (COUNT subquery).

    Called by
        ``components/expert_incidents_list.py``.

    SQL notes
        Correlated subquery COUNT(*) per incident for Events column — O(n) subqueries
        acceptable at prototype scale; index on incident_events(incident_id) helps.
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
    Return incidents with optional severity and status filters for expert UI.

    Purpose
        Filtered incident table driven by Streamlit select boxes.

    Parameters
        severity: str | None — ``"All"`` or None skips severity filter.
        status: str | None — ``"All"`` skips; ``"Open"`` maps to Active+Investigating.

    Returns
        ``pd.DataFrame`` — same columns as ``get_expert_incidents_list``.

    Tables touched
        ``incidents``, ``devices``, ``incident_events`` (subquery).

    Called by
        ``ai_service.py`` (Open incidents context), expert incidents list filters.

    SQL injection safety
        Dynamic WHERE fragments append only fixed SQL strings; **values** bind via
        ``params`` list — never embed severity/status strings in f-string SQL.

    Edge cases
        Both filters None/"All" returns full list. Unknown status strings only
        match when explicitly passed as exact equality (not "Open").
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
    """
    Return IOC (indicator) rows linked to an incident via join table.

    Purpose
        Threat intel panel and ``ai_service.py`` indicator context.

    Returns
        ``list[dict]``: indicator_value, indicator_type, threat_actor_group,
        confidence_score — highest confidence first.

    Tables touched
        ``incident_indicators``, ``indicators`` (INNER JOIN).

    SQL injection safety
        incident_id bound via ``?``.
    """
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
    """
    Return security telemetry events for one incident timeline.

    Purpose
        Expert incident detail events table and AI event context.

    Returns
        ``pd.DataFrame`` — Time, Source IP, Destination IP, Protocol, Summary.

    Tables touched
        ``incident_events``.

    Called by
        ``components/expert_incident_detail.py``, ``ai_service.py``.
    """
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
    """
    Return incident counts grouped by severity for pie/bar charts.

    Purpose
        ``components/expert_charts.py`` severity distribution visualization.

    Returns
        ``pd.DataFrame``: Severity, Count — ordered Critical → Low.

    Tables touched
        ``incidents`` (GROUP BY severity).
    """
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

    Purpose
        Time-series chart of security event volume on expert overview.

    Parameters
        hours: int — lookback window (default 48).

    Returns
        ``pd.DataFrame``: Hour (mm/dd HH:00), Events.

    Tables touched
        ``incident_events``.

    SQL notes
        ``datetime('now', ?)`` with bound string ``"-{hours} hours"`` — SQLite
        modifier syntax; negative offset selects recent window.
        GROUP BY strftime('%Y-%m-%d %H', timestamp) buckets to hour granularity.

    SQL injection safety
        hours interpolated only into **parameter value** ``f"-{hours} hours"``,
        not into SQL text — safe for integer hours from UI slider.
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
    """
    Return compact recent security events for overview ticker/scrolling feed.

    Purpose
        ``components/expert_security_ticker.py`` — short headlines, limited rows.

    Parameters
        limit: int — max rows (bound via ``?``).

    Returns
        ``pd.DataFrame``: Time, Severity, Incident, Summary.

    Tables touched
        ``incident_events``, ``incidents`` (JOIN).
    """
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
    """
    Return all active recommendations for an incident, display-order sorted.

    Purpose
        Recommendations panel and AI context (human + AI-generated rows).

    Returns
        ``list[dict]`` — full recommendations row shape including playbook JSON.

    Tables touched
        ``recommendations`` (WHERE is_active = 1).

    Called by
        ``ai_service.py``, expert incident detail UI.

    Edge cases
        Soft-deleted recommendations (is_active=0) hidden — not physically deleted.
    """
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
    """
    Return the latest active playbook-type recommendation for an incident.

    Purpose
        Single current AI playbook plan — ``playbook_actions_json`` drives action UI.

    Returns
        ``dict | None`` — subset of columns or None if no active playbook.

    Tables touched
        ``recommendations`` (filter recommendation_type='playbook', is_active=1).

    Called by
        ``ai_service.py`` heavily for playbook state and chat plan updates.
    """
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
    """
    Insert one recommendation row and return recommendation_id.

    Purpose
        Store AI or human guidance text linked to an incident.

    Parameters
        recommendation_type: ``"general"`` | ``"playbook"`` etc.
        playbook_actions_json: optional JSON string of action keys (playbooks).
        is_ai_generated: 1/0 flag for UI badge.
        display_order: sort key among active rows.

    Returns
        int — new recommendation_id.

    Tables touched
        ``recommendations`` (INSERT, is_active defaults to 1).

    Called by
        ``ai_service.py`` after analysis, ``insert_playbook_recommendation``.

    Transaction boundary
        INSERT + commit in one connection scope.
    """
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
    """
    Soft-delete all active playbook recommendations before inserting a replacement.

    Purpose
        Only one "current" AI playbook per incident — old rows marked is_active=0.

    Tables touched
        ``recommendations`` (UPDATE is_active).

    Called by
        ``ai_service.py`` / ``sentinel_actions.py`` before new playbook INSERT.

    Edge cases
        Idempotent when no active playbook rows exist (zero rows updated).
    """
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
    """
    Convenience wrapper: store playbook recommendation with JSON action keys.

    Purpose
        Serialize ``action_keys`` list via ``json.dumps`` for playbook_actions_json.

    Parameters
        action_keys: list of ``action_catalog`` keys (strings).

    Returns
        int — recommendation_id from ``insert_recommendation``.

    Tables touched
        ``recommendations`` (via insert_recommendation).
    """
    return insert_recommendation(
        incident_id,
        recommendation_text,
        recommendation_type="playbook",
        playbook_actions_json=json.dumps(action_keys),
        is_ai_generated=1,
        display_order=0,
    )


def get_incident_actions_list(incident_id: int) -> list[dict]:
    """
    Return chronological list of actions taken on an incident.

    Purpose
        Investigation timeline UI and AI context (what steps already ran).

    Returns
        ``list[dict]`` — full incident_actions columns including payload_json.

    Tables touched
        ``incident_actions``.

    Called by
        ``components/expert_incident_actions.py``, ``ai_service.py``.
    """
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
    """
    Return set of action_key values already marked completed for an incident.

    Purpose
        Dedupe playbook steps — ``ai_service.py`` skips completed action keys.

    Returns
        ``set[str]`` — may be empty.

    Tables touched
        ``incident_actions`` (WHERE status = 'completed').

    Called by
        ``ai_service.py``, ``sentinel_actions.py`` playbook progression logic.
    """
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
    """
    Record an action taken on an incident; optional payload serialized to JSON.

    Purpose
        Audit trail for investigation/remediation steps (manual or automated).

    Parameters
        payload: optional dict → stored as payload_json TEXT.
        status: defaults ``"completed"``; created_at and completed_at both set to now.

    Returns
        int — new action_id.

    Tables touched
        ``incident_actions`` (INSERT).

    Called by
        ``sentinel_actions.py``, ``create_incident_with_investigation``.

    Transaction boundary
        Single INSERT + commit.
    """
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
    """
    Append one security telemetry event to an incident timeline.

    Purpose
        Seed scenario events or record synthetic network activity during investigation.

    Returns
        int — new event row id (table-dependent AUTOINCREMENT if present).

    Tables touched
        ``incident_events`` (INSERT, timestamp = datetime('now')).

    Called by
        ``create_incident_with_investigation``, ``sentinel_actions.py``, scenarios.
    """
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
    Insert an IOC indicator and link it to an incident (many-to-many).

    Purpose
        Attach threat intel to incidents during scenario seeding or AI enrichment.

    Returns
        int — new indicator_id (from indicators table).

    Tables touched
        ``indicators`` (INSERT), ``incident_indicators`` (INSERT link row).

    Transaction boundary
        Both INSERTs share one connection + single commit — atomic link creation.

    Edge cases
        Same indicator_value may exist on multiple incidents via separate rows.
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
    """
    Update incident status and optionally monitor_until or authority_recommended.

    Purpose
        Lifecycle transitions (Active → Investigating → Resolved) and temporal gates.

    Parameters
        monitor_until: ISO timestamp string or None — skip column if omitted.
        authority_recommended: 0/1 flag for law-enforcement notice UI.

    Tables touched
        ``incidents`` (UPDATE).

    Called by
        ``sentinel_actions.py``, ``temporal_state.py``, scenario seeding.

    SQL injection safety
        Column names in SET clause come from fixed Python list ``fields`` — only
        **values** and incident_id use ``?`` binding. Do not extend with user input.

    Edge cases
        Partial update: omitted optional kwargs leave those columns unchanged.
    """
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
    """
    Mark incident acknowledged and move status to Investigating (idempotent).

    Purpose
        "Get started" flow — sets acknowledged_at once; repeats are no-ops.

    Tables touched
        ``incidents`` (UPDATE WHERE acknowledged_at IS NULL guard).

    Called by
        ``sentinel_actions.py``, expert incident UI acknowledge button.

    Edge cases
        Second acknowledge does not overwrite acknowledged_at (WHERE clause).
    """
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
    """
    Return True when acknowledged_at timestamp is set on the incident.

    Purpose
        Gate UI prompts (e.g. ``chat_sessions.py`` awaiting_get_started flag).

    Tables touched
        ``incidents`` (SELECT acknowledged_at).

    Edge cases
        Missing incident_id returns False (row is None).
    """
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
    Insert incident and run automated investigation actions (high-level orchestrator).

    Purpose
        Runtime entry when user or AI creates an incident: always runs fingerprint +
        ping_sweep actions, then optionally seeds scenario telemetry and IOCs.

    Parameters
        device_* / mac_address: passed to action_catalog formatters (not read from DB).
        scenario_key + indicator: when both set, replay ``scenario_telemetry`` templates.

    Returns
        int — new incident_id after full seeding pipeline.

    Tables touched
        ``incidents``, ``incident_actions``, ``incident_events``, ``indicators``,
        ``incident_indicators`` (via helper inserts).

    Called by
        ``incident_scenarios.py``, ``sentinel_actions.py``, demo flows.

    Design note
        Lazy imports of ``action_catalog`` / ``scenario_telemetry`` avoid circular
        imports (those modules may import db helpers).

    Edge cases
        Without scenario_key/indicator, inserts generic ICMP placeholder events only.
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


# ---------------------------------------------------------------------------
# Incident updates — two-tier alert system (pending updates + acknowledgment)
# ---------------------------------------------------------------------------
# Supports temporal narrative beats: new alerts layer on top of base incidents.


def clear_monitor_until(incident_id: int) -> None:
    """
    Clear the monitoring gate timestamp on an incident.

    Purpose
        Release temporal hold after monitor window expires or user dismisses gate.

    Tables touched
        ``incidents`` (UPDATE monitor_until = NULL).

    Called by
        ``temporal_state.py``, post-monitor sentinel flows.
    """
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
    """
    Insert a pending incident update alert (deduplicated by type).

    Purpose
        Second-tier notifications (escalations, new telemetry) without new incidents.

    Parameters
        update_type: dedupe key — only one unacknowledged row per (incident, type).
        payload: optional dict stored as payload_json TEXT.

    Returns
        int | None — new update_id, or None if duplicate pending update exists.

    Tables touched
        ``incident_updates`` (SELECT dedupe + INSERT).

    Transaction boundary
        Dedupe SELECT and INSERT share one connection; commit after INSERT only.

    Edge cases
        Re-insert after acknowledgment allowed (acknowledged_at no longer NULL).
    """
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
    """
    Return unacknowledged incident updates with incident and device context.

    Purpose
        Expert notifications panel — richer rows than bare update table.

    Returns
        ``list[dict]`` — update fields + incident_title, severity, status, device_name.

    Tables touched
        ``incident_updates``, ``incidents``, ``devices`` (JOIN chain).

    Called by
        ``components/expert_notifications.py``.
    """
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
    """
    Count unacknowledged rows in incident_updates.

    Purpose
        Notification badge partial sum (with ``get_open_incident_count``).

    Tables touched
        ``incident_updates`` (WHERE acknowledged_at IS NULL).

    Edge cases
        Uses idx_incident_updates_pending-friendly filter when index exists.
    """
    query = """
        SELECT COUNT(*) AS count
        FROM incident_updates
        WHERE acknowledged_at IS NULL;
    """
    with get_db_connection() as conn:
        row = conn.execute(query).fetchone()
    return int(row["count"])


def get_notification_count() -> int:
    """
    Compute bell badge total: new Active incidents + pending incident updates.

    Purpose
        Single KPI for header notification icon.

    Returns
        int — sum of two counts (not DISTINCT incidents — may double-count conceptually
        if same incident has both Active status and pending update; intentional for badge).

    Tables touched
        ``incidents``, ``incident_updates`` (via helper functions).
    """
    return get_open_incident_count() + get_pending_update_count()


def acknowledge_incident_update(update_id: int) -> None:
    """
    Mark one incident update row acknowledged (idempotent).

    Purpose
        Dismiss secondary alert from notifications UI.

    Tables touched
        ``incident_updates`` (UPDATE acknowledged_at WHERE still NULL).

    Edge cases
        Unknown update_id updates zero rows silently.
    """
    query = """
        UPDATE incident_updates
        SET acknowledged_at = datetime('now')
        WHERE update_id = ? AND acknowledged_at IS NULL;
    """
    with get_db_connection() as conn:
        conn.execute(query, (update_id,))
        conn.commit()


def get_incident_update_by_id(update_id: int) -> dict | None:
    """
    Fetch single incident_updates row by primary key.

    Purpose
        Detail drill-down when user clicks a specific update notification.

    Returns
        ``dict | None``.

    Tables touched
        ``incident_updates``.
    """
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
    """
    Return all update alerts (pending and acknowledged) for one incident.

    Purpose
        Incident detail timeline and ``ai_service.py`` update-aware re-analysis.

    Returns
        ``list[dict]`` — newest first (created_at DESC).

    Tables touched
        ``incident_updates``.
    """
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
    """
    Return prior incidents on the same device for system-context grounding.

    Purpose
        ``ai_service.py`` enriches prompts with device history (repeat offender context).

    Parameters
        limit: max rows (default 10), bound via ``?``.

    Returns
        ``list[dict]``: incident_id, title, severity, status, created_at.

    Tables touched
        ``incidents``.
    """
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
    """
    Fetch one device row by primary key.

    Purpose
        Device metadata for AI prompts when incident row alone is insufficient.

    Returns
        ``dict | None`` — device_id, mac_address, device_name, device_type,
        internal_ip, owner_name.

    Tables touched
        ``devices``.

    Called by
        ``ai_service.py`` (``build_device_context``).
    """
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
