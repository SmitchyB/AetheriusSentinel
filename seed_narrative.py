"""
Seed narrative helpers: synchronized chat transcripts and incident_actions.

Purpose
-------
Used **exclusively** by ``seed.py`` to build demo data where chat UI transcripts
and the ``incident_actions`` audit trail stay perfectly aligned. Each user
"playbook click" in a scripted session produces:

1. An ``incident_actions`` row (status=completed, payload/result from action_catalog)
2. A ``chat_messages`` user row (plain_label from action_catalog)
3. A ``chat_messages`` assistant row (formatted result text)

This mirrors runtime behavior in ``db.create_incident_with_investigation`` and
live action execution, but uses explicit ``action_id`` / ``message_id`` cursors
and fixed timestamps for reproducible demo narratives.

Schema relationships
--------------------
- ``incident_actions`` — see schema.sql; FK ``incident_id`` -> ``incidents``
- ``chat_messages``    — ``session_id`` groups a thread; ``incident_id`` optional FK

Dependencies
------------
- ``action_catalog`` — ``get_action``, ``get_draft_payload``, ``format_action_result``,
  ``format_plain_action_result``, ``simulate_investigation_summaries``

The ``incident_ctx`` dict shape is built by ``seed._incident_ctx()`` and must include
device fields plus ``source``, ``source_mac``, ``indicator``, and ``key`` (scenario_key).
"""

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
    """
    Add *minutes* to a seed timestamp string.

    All seed timestamps use the fixed format ``%Y-%m-%d %H:%M:%S`` (SQLite TEXT,
    no timezone). Used to stagger investigation actions, chat bubbles, and
    playbook completions within a scripted session.

    Parameters
    ----------
    base:
        Starting timestamp, e.g. ``"2026-06-10 01:15:00"``.
    minutes:
        Non-negative offset in minutes (negative not used in seed scripts).

    Returns
    -------
    str
        New timestamp in the same format.
    """
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
    Insert the two automated investigation rows every new incident receives.

    Runtime equivalent: the tail of ``db.create_incident_with_investigation`` which
    calls ``action_catalog.simulate_investigation_summaries``. Seed data uses the
    same summaries but pins ``action_id`` values and timestamps for deterministic
    ordering in the expert incident detail panel.

    Rows inserted into ``incident_actions``:
    ----------------------------------------
    1. ``fingerprint_device`` — category ``investigation``, is_automated=1
    2. ``ping_sweep``           — category ``investigation``, is_automated=1

    Both rows: status=``completed``, payload_json=NULL, is_recommended=0,
    playbook_order=NULL (not part of user playbook).

    Parameters
    ----------
    conn:
        Active SQLite connection (caller manages transaction).
    action_id:
        First available PK for ``incident_actions.action_id``.
    incident_id:
        Parent incident FK.
    incident_ctx:
        Device + scenario context for summary text generation.
    created_at:
        Base time; fingerprint at T+0 min, ping_sweep at T+1 min.

    Returns
    -------
    int
        Next unused ``action_id`` (always ``action_id + 2`` after two inserts).
    """
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
    """
    Insert one user-triggered playbook action and return chat copy for the session.

    Pulls metadata from ``action_catalog`` so seeded chat text matches what the
    live Dash UI would show after the same action_key is executed.

    Schema row semantics (``incident_actions``):
    --------------------------------------------
    - ``action_category`` — from catalog (containment, eradication, post_incident, etc.)
    - ``payload_json``      — JSON-serialized draft payload (targets, IPs, device names)
    - ``result_summary``    — technical summary for expert action log
    - ``is_automated``      — 0 for all response actions (user/chat-driven in seed)
    - ``is_recommended``    — 1 if action_key appears in optional playbook_keys list
    - ``playbook_order``    — 1-based index in playbook_keys when present

    Parameters
    ----------
    conn:
        Active SQLite connection.
    action_id:
        PK for this action row.
    incident_id:
        Parent incident FK.
    incident_ctx:
        Device/scenario context; merged with scenario_key for catalog formatters.
    scenario_key:
        e.g. ``"command_and_control"`` — passed as ``key`` in formatter context.
    action_key:
        Catalog key, e.g. ``"perm_block"``, ``"dns_sinkhole"``.
    completed_at:
        Both ``created_at`` and ``completed_at`` — instant completion in demo.
    playbook_keys:
        Optional ordered list to set is_recommended and playbook_order; seed_chat_session
        does not pass this today (defaults to empty), but hook exists for richer seeds.

    Returns
    -------
    tuple[int, str, str]
        (next_action_id, user_label, assistant_text) for chat_messages inserts.

    Raises
    ------
    ValueError
        If ``action_key`` is not registered in action_catalog.
    """
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
    """
    Execute a declarative chat script for one incident session.

    Walks ``script`` in order, advancing a synthetic timeline by one minute per
    script entry (with an extra minute after each action for assistant confirmation).
    All messages share ``session_id`` (indexed in schema: idx_chat_messages_session).

    Script tuple format
    -------------------
    (``"assistant"``, message_text)
        Inserts one ``chat_messages`` row with role=assistant.

    (``"action"``, action_key)
        Inserts incident_actions row via ``insert_response_action``, then:
        - user message with plain_label at action timestamp
        - assistant message with formatted result at timestamp + 1 minute

    Timeline model
    --------------
    minute_offset starts at 0 and increments once per script entry; action entries
    consume an additional minute before the assistant confirmation bubble so user
    and assistant replies do not share identical timestamps.

    Parameters
    ----------
    conn:
        Active SQLite connection.
    message_id:
        Next available ``chat_messages.message_id`` PK.
    action_id:
        Next available ``incident_actions.action_id`` PK.
    incident_id:
        FK on every chat message and action in this session.
    incident_ctx:
        Passed through to ``insert_response_action``.
    scenario_key:
        Scenario identifier for action catalog formatters.
    session_id:
        Stable thread id, e.g. ``"sess-inc1-001"``; later copied to
        ``incidents.chat_session_id`` by seed.py.
    session_start:
        Timestamp of the first script entry (before minute_offset).
    script:
        Ordered list of (entry_type, value) tuples.

    Returns
    -------
    tuple[int, int]
        Updated (message_id, action_id) cursors for the caller's next session.

    Raises
    ------
    ValueError
        If script contains an unknown entry_type (not assistant or action).
    """
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
