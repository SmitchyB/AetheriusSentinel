"""
Expert mode incident detail page — full record inspection and response palette.

Assignment 4.2 detail view + future AI evidence preview (get_ai_incident_context).
"""

import streamlit as st

import db
import incident_scenarios
from components.expert_incident_actions import (
    render_acknowledge_button,
    render_actions_taken,
    render_ai_recommendations,
    render_response_actions,
)
from components.chat_history import render_incident_session_tiles
from components.expert_navigation import navigate_to_overview
from components.styled_buttons import UI_MARKERS, render_button_marker
from incident_scenarios import (
    can_show_open_analyst_chat,
    can_show_start_investigation,
    get_active_incident,
    open_incident_chat,
)


def _render_incident_summary(incident: dict):
    """Header block: title, severity badge, device/IP/MAC captions."""
    severity = incident.get("severity", "Unknown")
    severity_class = severity.lower().replace(" ", "-")
    st.markdown(
        f'<div class="expert-detail-header">'
        f'<span class="expert-detail-title">{incident["title"]}</span>'
        f'<span class="expert-severity-badge severity-{severity_class}">{severity}</span>'
        f"</div>",
        unsafe_allow_html=True,
    )
    st.caption(
        f"Status: **{incident.get('status', 'Unknown')}** | "
        f"Device: **{incident.get('device_name', 'Unknown')}** | "
        f"IP: `{incident.get('internal_ip', 'N/A')}` | "
        f"MAC: `{incident.get('mac_address', 'N/A')}`"
    )
    if incident.get("primary_indicator"):
        st.caption(f"Primary indicator: `{incident['primary_indicator']}`")
    if incident.get("created_at"):
        st.caption(f"Created: {incident['created_at']}")


def _render_ai_evidence(incident_id: int):
    """
    Display AI Analyst Evidence table — DB context for future LLM, not AI output.

    Uses get_ai_incident_context() JOIN + GROUP_CONCAT query from db.py.
    """
    st.markdown(
        '<h3 class="standard-section-title standard-section-title--compact">AI Analyst Evidence</h3>',
        unsafe_allow_html=True,
    )
    try:
        context_df = db.get_ai_incident_context(incident_id)
    except Exception as error:
        st.error("Could not load AI incident context from the database.")
        st.exception(error)
        return

    if context_df.empty:
        st.warning("No evidence found for this incident.")
    else:
        st.dataframe(context_df, use_container_width=True, hide_index=True)


def _render_incident_events(incident_id: int):
    """Security events timeline for one incident from incident_events table."""
    st.markdown(
        '<h3 class="standard-section-title standard-section-title--compact">Security Events</h3>',
        unsafe_allow_html=True,
    )
    try:
        events_df = db.get_incident_events(incident_id)
    except Exception as error:
        st.error("Could not load security events for this incident.")
        st.exception(error)
        return

    if events_df.empty:
        st.info("No security events recorded for this incident.")
    else:
        st.dataframe(
            events_df,
            use_container_width=True,
            hide_index=True,
            height=280,
        )


def _render_related_sessions(incident_id: int, incident_title: str):
    """Chat history tiles scoped to this incident_id."""
    st.markdown(
        '<h3 class="standard-section-title standard-section-title--compact">Related Chat Sessions</h3>',
        unsafe_allow_html=True,
    )
    render_incident_session_tiles(
        incident_id,
        incident_title=incident_title,
        key_prefix=f"expert_incident_sessions_{incident_id}",
        open_side_panel=True,
    )


def render_expert_incident_detail():
    """
    Full incident detail view — driven by st.session_state.expert_incident_id.

    Shown when expert_view == 'incident_detail' (see expert_router.py).
    """
    incident_id = st.session_state.get("expert_incident_id")
    if not incident_id:
        st.warning("No incident selected.")
        if st.button("← Back to Dashboard", key="expert_detail_back_empty"):
            navigate_to_overview()
            st.rerun()
        return

    if st.button("← Back to Dashboard", key="expert_detail_back"):
        navigate_to_overview()
        st.rerun()

    st.markdown('<div class="expert-incident-detail-root"></div>', unsafe_allow_html=True)

    if not db.DB_PATH.exists():
        st.error(
            f"Database not found at `{db.DB_PATH}`. "
            "Run `python seed.py` from the project root, then refresh."
        )
        return

    try:
        incident = db.get_incident_by_id(int(incident_id))
    except Exception as error:
        st.error("Could not load incident from the database.")
        st.exception(error)
        return

    if not incident:
        st.error(f"Incident ID {incident_id} not found.")
        return

    # Enrich DB row with scenario description/subtitle from incident_scenarios.INCIDENTS.
    active_incident = incident_scenarios.build_active_incident_from_db(incident)

    with st.container(border=True):
        st.markdown('<div class="standard-panel-card expert-detail-summary-panel"></div>', unsafe_allow_html=True)
        _render_incident_summary(incident)
        render_acknowledge_button(int(incident_id), incident)

        show_start = can_show_start_investigation(incident)
        show_analyst = can_show_open_analyst_chat(incident)
        if show_start or show_analyst:
            col_count = 2 if show_start and show_analyst else 1
            action_cols = st.columns(col_count)
            col_index = 0
            if show_start:
                with action_cols[col_index]:
                    render_button_marker(UI_MARKERS["investigation_flow"])
                    if st.button(
                        "Start investigation",
                        key="expert_detail_start_investigation",
                        type="primary",
                        use_container_width=True,
                    ):
                        open_incident_chat(int(incident_id))
                        st.session_state.side_panel_open = True
                        st.rerun()
                col_index += 1
            if show_analyst:
                with action_cols[col_index if show_start else 0]:
                    render_button_marker(UI_MARKERS["analyst_chat"])
                    if st.button(
                        "Open Analyst chat",
                        key="expert_detail_open_analyst",
                        use_container_width=True,
                    ):
                        if not get_active_incident() or get_active_incident().get("incident_id") != incident_id:
                            open_incident_chat(int(incident_id))
                        st.session_state.side_panel_open = True
                        st.rerun()

    with st.container(border=True):
        st.markdown('<div class="standard-panel-card expert-ai-recommendations-panel"></div>', unsafe_allow_html=True)
        render_ai_recommendations(int(incident_id))

    with st.container(border=True):
        st.markdown('<div class="standard-panel-card expert-actions-taken-panel"></div>', unsafe_allow_html=True)
        render_actions_taken(int(incident_id))

    with st.container(border=True):
        st.markdown('<div class="standard-panel-card expert-ai-evidence-panel"></div>', unsafe_allow_html=True)
        _render_ai_evidence(int(incident_id))

    with st.container(border=True):
        st.markdown('<div class="standard-panel-card expert-detail-events-panel"></div>', unsafe_allow_html=True)
        _render_incident_events(int(incident_id))

    with st.container(border=True):
        st.markdown('<div class="standard-panel-card expert-detail-playbook-panel"></div>', unsafe_allow_html=True)
        render_response_actions(int(incident_id), active_incident)

    with st.container(border=True):
        st.markdown(
            '<div class="standard-panel-card standard-history-panel expert-detail-sessions-panel"></div>',
            unsafe_allow_html=True,
        )
        _render_related_sessions(int(incident_id), incident["title"])
