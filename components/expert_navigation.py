"""
Expert mode navigation helpers — overview vs incident detail routing.

These session keys are separate from Standard mode's active_incident chat flow.
"""

import streamlit as st


def init_expert_state():
    """Ensure expert navigation keys exist with safe defaults on first load."""
    if "expert_view" not in st.session_state:
        st.session_state.expert_view = "overview"
    if "expert_incident_id" not in st.session_state:
        st.session_state.expert_incident_id = None
    if "notifications_open" not in st.session_state:
        st.session_state.notifications_open = False


def navigate_to_incident_detail(incident_id: int):
    """Switch Expert view to full incident detail for the given DB incident_id."""
    st.session_state.expert_view = "incident_detail"
    st.session_state.expert_incident_id = int(incident_id)
    st.session_state.notifications_open = False


def navigate_to_overview():
    """Return to the Expert overview dashboard (KPIs, charts, incident table)."""
    st.session_state.expert_view = "overview"
