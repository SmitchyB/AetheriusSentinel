"""Chat session helpers — load persisted threads from SQLite into Streamlit session state."""

import streamlit as st

import db

# ---------------------------------------------------------------------------
# Session hydration — map a DB session_id into Streamlit chat state
# ---------------------------------------------------------------------------
# Incident threads use one canonical session per incident (incidents.chat_session_id).
# General threads have incident_id NULL on all messages.


def load_chat_session(session_id: str):
    """Load a persisted chat thread into the active Sentinel panel."""
    # Lazy import avoids circular dependency at module import time:
    # incident_scenarios → chat_sessions → incident_scenarios
    from incident_scenarios import build_active_incident_from_db, get_playbook_phase, sync_recommended_actions_from_db

    incident_id = db.get_session_incident_id(session_id)

    # --- Chat identity ---
    st.session_state.active_session_id = session_id
    from sentinel_actions import hydrate_loaded_messages

    st.session_state.messages = hydrate_loaded_messages(db.get_messages_for_session(session_id))
    st.session_state.active_incident_id = incident_id

    # --- Reset ephemeral playbook UI flags from any prior thread ---
    st.session_state.pipeline_completed_count = 0
    st.session_state.pending_plan_update = None
    st.session_state.pending_chat_bootstrap_incident_id = None
    st.session_state.pending_chat_ai = None
    st.session_state.pending_chat_work_painted = False

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
