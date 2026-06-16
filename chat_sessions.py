"""
Chat session helpers — load persisted threads from SQLite into Streamlit session state.

**Why this module exists (import topology):**

``components/chat_history.py`` and ``components/sentinel_panel.py`` both need to
resume a saved chat thread without creating a circular import chain through the
heavier ``incident_scenarios`` package. This thin loader lives at the project
root beside ``db.py`` and delegates playbook rehydration to
``incident_scenarios`` via a lazy import inside ``load_chat_session``.

**What ``load_chat_session`` restores:**

1. **Chat layer** — ``active_session_id``, ``messages`` from ``chat_messages``.
2. **Incident binding** — ``active_incident_id`` from the session row.
3. **Playbook layer** — ``active_incident``, ``playbook_phase``, recommended
   action keys, and ``awaiting_get_started`` (pre-ack gate).
4. **Ephemeral UI flags** — clears ``pending_plan_update`` and deferred bootstrap
   ids so a resumed thread does not inherit stale sticky-bar state from another
   conversation.

**What it does NOT do:**

- Create new sessions (see ``sentinel_actions.start_general_chat`` or
  ``db.get_or_create_incident_chat_session``).
- Append bootstrap messages (see ``incident_scenarios.resume_incident_chat``).
- Run AI analysis (playbook should already exist in DB when user resumes).

**Typical call path:**

User clicks a row in chat history → ``load_chat_session(session_id)`` →
``st.rerun()`` → sentinel panel renders messages + sticky bar from restored state.
"""

import streamlit as st

import db


def load_chat_session(session_id: str):
    """
    Load a persisted chat thread into the active Sentinel panel.

    **Session-state keys written:**

    - ``active_session_id`` — binds future ``append_message`` calls to SQLite.
    - ``messages`` — full thread from ``db.get_messages_for_session``.
    - ``active_incident_id`` — FK from ``chat_sessions.incident_id`` (may be None).
    - ``pipeline_completed_count`` — reset to 0 (legacy pipeline UI counter).
    - ``pending_plan_update`` — cleared; plan offers are per-turn, not persisted.
    - ``pending_chat_bootstrap_incident_id`` — cleared; bootstrap runs elsewhere.

    **When an incident is linked:**

    - ``sync_recommended_actions_from_db`` hydrates ``recommended_action_keys``.
    - ``build_active_incident_from_db`` merges DB row + static ``INCIDENTS`` copy.
    - ``get_playbook_phase`` sets ``playbook_phase`` for gating and chat scope.
    - ``awaiting_get_started`` is True until ``db.is_incident_acknowledged``.

    **When no incident is linked (general analyst chat):**

    - Incident and playbook keys are nulled; phase defaults to ``awaiting_ack``.
    """
    # Lazy import avoids circular dependency at module import time:
    # incident_scenarios → chat_sessions → incident_scenarios
    from incident_scenarios import build_active_incident_from_db, get_playbook_phase, sync_recommended_actions_from_db

    incident_id = db.get_session_incident_id(session_id)

    # --- Chat identity ---
    st.session_state.active_session_id = session_id
    st.session_state.messages = db.get_messages_for_session(session_id)
    st.session_state.active_incident_id = incident_id

    # --- Reset ephemeral playbook UI flags from any prior thread ---
    st.session_state.pipeline_completed_count = 0
    st.session_state.pending_plan_update = None
    st.session_state.pending_chat_bootstrap_incident_id = None

    if incident_id:
        # --- Incident-scoped thread: rebuild playbook context from DB ---
        sync_recommended_actions_from_db(incident_id)
        db_row = db.get_incident_by_id(incident_id)
        if db_row:
            active_incident = build_active_incident_from_db(db_row)
            st.session_state.active_incident = active_incident
            st.session_state.playbook_phase = get_playbook_phase(active_incident)
            # Pre-ack: user sees summary + "Get started" before plan steps unlock.
            st.session_state.awaiting_get_started = not db.is_incident_acknowledged(incident_id)
        else:
            # Orphan session pointing at deleted incident — degrade gracefully.
            st.session_state.active_incident = None
            st.session_state.playbook_phase = "awaiting_ack"
            st.session_state.awaiting_get_started = False
    else:
        # --- General dashboard Q&A thread (no incident binding) ---
        st.session_state.active_incident = None
        st.session_state.active_incident_id = None
        st.session_state.playbook_phase = "awaiting_ack"
        st.session_state.awaiting_get_started = False
