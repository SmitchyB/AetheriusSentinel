"""Seed narrative helpers: synchronized chat transcripts and incident_actions."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any

from action_catalog import (
    format_action_result,
    format_plain_action_result,
    get_action,
    get_draft_payload,
)


def _advance_time(base: str, minutes: int) -> str:
    """Add *minutes* to a seed timestamp string."""
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
    """Insert the two automated investigation rows every new incident receives."""
    # Deferred import avoids circular import if action_catalog ever imports db.
    from action_catalog import simulate_investigation_summaries

    # Tuple of human-readable result strings for the two investigation steps.
    fp_summary, sweep_summary = simulate_investigation_summaries(incident_ctx)

    # Column order matches INSERT statement below (12 placeholders).
    rows = [
        (
            action_id,                  # action_id PK
            incident_id,                # incident_id FK
            "fingerprint_device",       # action_key — must exist in action_catalog
            "investigation",            # action_category — schema CHECK value
            "completed",                # status — seed skips pending/running states
            None,                       # payload_json — investigation actions have no payload
            fp_summary,                 # result_summary — shown in UI action log
            1,                          # is_automated — distinguishes from user clicks
            0,                          # is_recommended — not a playbook suggestion row
            None,                       # playbook_order — N/A for auto investigation
            _advance_time(created_at, 0),  # created_at
            _advance_time(created_at, 0),  # completed_at — instant completion in demo
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
            _advance_time(created_at, 1),  # one minute after fingerprint
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
    playbook_keys: list[str] | None = None,
) -> tuple[int, str, str]:
    """Insert one user-triggered playbook action and return chat copy for the session."""
    action = get_action(action_key)
    if not action:
        raise ValueError(f"Unknown action key: {action_key}")

    # Playbook metadata — when playbook_keys provided, marks row as recommended step N.
    playbook = playbook_keys or []
    playbook_order = playbook.index(action_key) + 1 if action_key in playbook else None
    is_recommended = 1 if action_key in playbook else 0

    # Catalog helpers need scenario key on the context dict for scenario-specific copy.
    formatter_ctx = {**incident_ctx, "key": scenario_key}
    payload = get_draft_payload(action_key, formatter_ctx)
    result_summary = format_action_result(action_key, formatter_ctx, payload)
    user_label = action["plain_label"]       # short text for chat user bubble
    assistant_text = format_plain_action_result(action_key, formatter_ctx)

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
            action["category"],       # from catalog — must satisfy schema CHECK
            "completed",
            json.dumps(payload),      # stored as TEXT JSON in SQLite
            result_summary,
            0,                        # user-driven response action
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
    """Execute a declarative chat script for one incident session."""
    minute_offset = 0
    for entry_type, value in script:
        timestamp = _advance_time(session_start, minute_offset)
        minute_offset += 1

        if entry_type == "assistant":
            # Pure narrative bubble — no incident_actions side effect.
            conn.execute(
                """
                INSERT INTO chat_messages (message_id, session_id, incident_id, role, content, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (message_id, session_id, incident_id, "assistant", value, timestamp),
            )
            message_id += 1

        elif entry_type == "action":
            # Simulates user clicking a playbook button in the chat drawer.
            action_id, user_label, assistant_text = insert_response_action(
                conn,
                action_id=action_id,
                incident_id=incident_id,
                incident_ctx=incident_ctx,
                scenario_key=scenario_key,
                action_key=value,
                completed_at=timestamp,
            )
            # User bubble — label matches styled button text in live UI.
            conn.execute(
                """
                INSERT INTO chat_messages (message_id, session_id, incident_id, role, content, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (message_id, session_id, incident_id, "user", user_label, timestamp),
            )
            message_id += 1

            # Assistant confirmation one minute later (simulates async action completion).
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
