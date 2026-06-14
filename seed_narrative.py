"""
Seed narrative helpers: chat scripts kept in sync with incident_actions.

Used exclusively by ``seed.py`` to build demo chat transcripts where each
user playbook step inserts both ``chat_messages`` rows and matching
``incident_actions`` rows with realistic timestamps and formatted summaries.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any

from action_catalog import (
    SCENARIO_PLAYBOOK_TEMPLATES,
    format_action_result,
    format_plain_action_result,
    get_action,
    get_draft_payload,
)


def _advance_time(base: str, minutes: int) -> str:
    """Add *minutes* to an ISO-like timestamp string and return the new value."""
    dt = datetime.strptime(base, "%Y-%m-%d %H:%M:%S")
    return (dt + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")


def insert_investigation_actions(
    conn: sqlite3.Connection,
    *,
    action_id: int,
    incident_id: int,
    incident_ctx: dict[str, Any],
    created_at: str,
) -> int:
    """
    Insert auto fingerprint + ping_sweep rows; return next action_id.

    Mirrors the automated investigation that ``db.create_incident_with_investigation``
    runs at runtime, but with explicit IDs and timestamps for seed data.
    """
    # Deferred import matches db.py pattern — action_catalog may import db helpers.
    from action_catalog import simulate_investigation_summaries

    fp_summary, sweep_summary = simulate_investigation_summaries(incident_ctx)
    # Two fixed investigation steps; timestamps staggered by one minute.
    rows = [
        (
            action_id,
            incident_id,
            "fingerprint_device",
            "investigation",
            "completed",
            None,
            fp_summary,
            1,
            0,
            None,
            _advance_time(created_at, 0),
            _advance_time(created_at, 0),
        ),
        (
            action_id + 1,
            incident_id,
            "ping_sweep",
            "investigation",
            "completed",
            None,
            sweep_summary,
            1,
            0,
            None,
            _advance_time(created_at, 1),
            _advance_time(created_at, 1),
        ),
    ]
    conn.executemany(
        """
        INSERT INTO incident_actions (
            action_id, incident_id, action_key, action_category, status,
            payload_json, result_summary, is_automated, is_recommended,
            playbook_order, created_at, completed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    return action_id + 2


def insert_response_action(
    conn: sqlite3.Connection,
    *,
    action_id: int,
    incident_id: int,
    incident_ctx: dict[str, Any],
    scenario_key: str,
    action_key: str,
    completed_at: str,
) -> tuple[int, str, str]:
    """
    Insert a playbook action row; return (next_action_id, user_label, assistant_text).

    Pulls labels and result text from action_catalog so seed chat matches live UI copy.
    """
    action = get_action(action_key)
    if not action:
        raise ValueError(f"Unknown action key: {action_key}")

    # Derive playbook metadata when this action belongs to the scenario template.
    playbook = SCENARIO_PLAYBOOK_TEMPLATES.get(scenario_key, [])
    playbook_order = playbook.index(action_key) + 1 if action_key in playbook else None
    is_recommended = 1 if action_key in playbook else 0
    payload = get_draft_payload(action_key, {**incident_ctx, "key": scenario_key})
    result_summary = format_action_result(action_key, {**incident_ctx, "key": scenario_key}, payload)
    user_label = action["plain_label"]
    assistant_text = format_plain_action_result(action_key, {**incident_ctx, "key": scenario_key})

    conn.execute(
        """
        INSERT INTO incident_actions (
            action_id, incident_id, action_key, action_category, status,
            payload_json, result_summary, is_automated, is_recommended,
            playbook_order, created_at, completed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            action_id,
            incident_id,
            action_key,
            action["category"],
            "completed",
            json.dumps(payload),
            result_summary,
            0,
            is_recommended,
            playbook_order,
            completed_at,
            completed_at,
        ),
    )
    return action_id + 1, user_label, assistant_text


def seed_chat_session(
    conn: sqlite3.Connection,
    *,
    message_id: int,
    action_id: int,
    incident_id: int,
    incident_ctx: dict[str, Any],
    scenario_key: str,
    session_id: str,
    session_start: str,
    script: list[tuple[str, str]],
) -> tuple[int, int]:
    """
    Run a chat script for one session.

    Script tuples:
      (``"assistant"``, message text) — single assistant bubble
      (``"action"``, action_key) — user label + assistant result + incident_action row

    Returns updated (message_id, action_id) cursors for the next session.
    """
    minute_offset = 0
    for entry_type, value in script:
        timestamp = _advance_time(session_start, minute_offset)
        minute_offset += 1

        if entry_type == "assistant":
            conn.execute(
                """
                INSERT INTO chat_messages (message_id, session_id, incident_id, role, content, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (message_id, session_id, incident_id, "assistant", value, timestamp),
            )
            message_id += 1
        elif entry_type == "action":
            # User "clicks" the action; DB row and chat triple (user + assistant) follow.
            action_id, user_label, assistant_text = insert_response_action(
                conn,
                action_id=action_id,
                incident_id=incident_id,
                incident_ctx=incident_ctx,
                scenario_key=scenario_key,
                action_key=value,
                completed_at=timestamp,
            )
            conn.execute(
                """
                INSERT INTO chat_messages (message_id, session_id, incident_id, role, content, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (message_id, session_id, incident_id, "user", user_label, timestamp),
            )
            message_id += 1
            # Assistant confirmation arrives one minute later in the script timeline.
            minute_offset += 1
            assistant_ts = _advance_time(session_start, minute_offset)
            conn.execute(
                """
                INSERT INTO chat_messages (message_id, session_id, incident_id, role, content, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (message_id, session_id, incident_id, "assistant", assistant_text, assistant_ts),
            )
            message_id += 1
        else:
            raise ValueError(f"Unknown script entry type: {entry_type}")

    return message_id, action_id
