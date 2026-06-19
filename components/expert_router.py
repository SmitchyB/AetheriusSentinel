"""Expert mode view router — switches between overview dashboard and incident detail."""

import streamlit as st

from components.expert_incident_detail import render_expert_incident_detail
from components.expert_navigation import init_expert_state
from components.expert_overview import render_expert_overview


def render_expert_mode():
    """Render the active Expert mode screen based on ``expert_view`` session key."""
    from incident_scenarios import process_pending_incident_chat_work

    init_expert_state()

    if process_pending_incident_chat_work():
        st.rerun()

    if st.session_state.expert_view == "incident_detail":
        render_expert_incident_detail()
    else:
        render_expert_overview()
