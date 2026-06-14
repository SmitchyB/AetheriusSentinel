"""
Chat session helpers — load persisted threads from SQLite into Streamlit session state.

Kept in a top-level module (not under components/) to avoid circular imports when
chat_history and sentinel_panel both need to resume sessions.
"""

import streamlit as st

import db


def load_chat_session(session_id: str):
    """
    Load a persisted chat thread into the active Sentinel panel.

    Restores messages from chat_messages, rehydrates the linked incident (if any),
    and resets playbook UI flags so the chat action buttons render correctly.
    """
    from incident_scenarios import build_active_incident_from_db, sync_recommended_actions_from_db

    # Look up which incident (if any) this session belongs to.
    incident_id = db.get_session_incident_id(session_id)

    # Wire Streamlit session state to the DB session row.
    st.session_state.active_session_id = session_id
    st.session_state.messages = db.get_messages_for_session(session_id)
    st.session_state.active_incident_id = incident_id
    st.session_state.pipeline_completed_count = 0
    st.session_state.awaiting_playbook_bootstrap = False
    st.session_state.playbook_phase = "awaiting_ack"

    if incident_id:
        # Pull recommended playbook keys from recommendations table into session.
        sync_recommended_actions_from_db(incident_id)
        db_row = db.get_incident_by_id(incident_id)
        if db_row:
            # Merge DB row with scenario metadata (description, indicator, etc.).
            active_incident = build_active_incident_from_db(db_row)
            st.session_state.active_incident = active_incident
            from incident_scenarios import get_playbook_phase

            st.session_state.playbook_phase = get_playbook_phase(active_incident)
        else:
            st.session_state.active_incident = None
    else:
        # General chat session with no linked incident.
        st.session_state.active_incident = None

