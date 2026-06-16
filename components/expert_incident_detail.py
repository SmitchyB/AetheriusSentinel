"""
Expert mode incident detail page — full record inspection and response palette.

Purpose
-------
Assignment 4.2 drill-down view: summary header, chat actions, AI recommendations,
actions taken, AI analyst evidence table, security events timeline, and full
response action palette. Rendered when ``expert_view == "incident_detail"``.

Navigation / call graph
-----------------------
``expert_router`` → ``render_expert_incident_detail()`` when
``st.session_state.expert_incident_id`` is set.

Back button → ``navigate_to_overview()``.
Chat buttons → ``open_incident_chat`` / ``start_general_chat`` + drawer open.

Session state dependencies
--------------------------
- ``expert_incident_id`` — required; DB primary key for all panels.
- ``side_panel_open`` — opened by chat / start investigation buttons.
- Playbook phase from ``incident_scenarios.build_active_incident_from_db``.

Streamlit widget keys
---------------------
- ``expert_detail_back``, ``expert_detail_back_empty`` — back navigation.
- ``expert_detail_start_investigation`` — ack gate shortcut.
- ``expert_detail_new_general_chat_{incident_id}`` — general Q&A thread.
- Sub-module keys from ``expert_incident_actions``.

CSS marker divs
---------------
- ``expert-incident-detail-root`` — page scope.
- Panel cards: ``expert-detail-summary-panel``, ``expert-ai-recommendations-panel``,
  ``expert-actions-taken-panel``, ``expert-ai-evidence-panel``,
  ``expert-detail-events-panel``, ``expert-detail-playbook-panel``.
- ``expert-detail-back-row``, ``expert-detail-chat-actions``,
  ``expert-detail-investigation-action``.

db.py
-----
- ``DB_PATH.exists()``, ``get_incident_by_id``, ``is_incident_acknowledged``.
- ``get_ai_incident_context(incident_id)`` — evidence table (JOIN/GROUP_CONCAT).
- ``get_incident_events(incident_id)`` — security events dataframe.

ai_service.py
-------------
- **Not used** directly. ``get_ai_incident_context`` is DB context for future LLM
  prompts, not live AI output.
"""

import streamlit as st

import db
import incident_scenarios
from components.expert_incident_actions import (
    render_actions_taken,
    render_ai_recommendations,
    render_open_chat_button,
    render_response_actions,
)
from components.expert_navigation import navigate_to_overview
from components.styled_buttons import UI_MARKERS, render_button_marker
from incident_scenarios import (
    can_show_start_investigation,
    is_terminal_status,
    open_incident_chat,
)
from sentinel_actions import start_general_chat


def _render_incident_summary(incident: dict):
    """
    Header block: title, severity badge, device/IP/MAC captions.

    HTML: ``expert-detail-header``, ``expert-detail-title``, ``expert-severity-badge``.
    """
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

    db.py: ``get_ai_incident_context(incident_id)`` — JOIN + GROUP_CONCAT query.
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
    """
    Security events timeline for one incident from incident_events table.

    db.py: ``get_incident_events(incident_id)``.
    """
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


def _render_back_to_dashboard(*, key: str) -> None:
    """
    Left-aligned back navigation styled like other expert chrome buttons.

    Widget key: caller-supplied (``expert_detail_back`` or ``_empty`` variant).

    Navigation: ``navigate_to_overview()`` on click.
    """
    st.markdown('<div class="expert-detail-back-row"></div>', unsafe_allow_html=True)
    back_col, _ = st.columns([1.35, 4.65], gap="small")
    with back_col:
        st.markdown('<div class="expert-btn-marker expert-btn--back"></div>', unsafe_allow_html=True)
        if st.button("← Back to Dashboard", key=key, use_container_width=True):
            navigate_to_overview()
            st.rerun()


def _render_summary_chat_actions(incident_id: int) -> None:
    """
    Compact horizontal row — investigation chat and general Q&A side by side.

    Widget: ``expert_detail_new_general_chat_{incident_id}``.
    """
    st.markdown('<div class="expert-detail-chat-actions"></div>', unsafe_allow_html=True)
    open_col, general_col, _spacer = st.columns([1, 1, 1.6], gap="small")
    with open_col:
        render_open_chat_button(int(incident_id), use_container_width=True)
    with general_col:
        st.markdown('<div class="expert-btn-marker expert-btn--new-chat"></div>', unsafe_allow_html=True)
        if st.button(
            "New General Chat",
            key=f"expert_detail_new_general_chat_{incident_id}",
            use_container_width=True,
            help="Start a general analyst Q&A thread (not tied to this incident)",
        ):
            start_general_chat()
            st.rerun()


def render_expert_incident_detail():
    """
    Full incident detail view — driven by ``st.session_state.expert_incident_id``.

    Shown when ``expert_view == 'incident_detail'`` (see ``expert_router.py``).

    db.py: ``get_incident_by_id``, ``is_incident_acknowledged``,
    ``get_ai_incident_context``, ``get_incident_events``.

    Enriches DB row via ``incident_scenarios.build_active_incident_from_db`` for phase gating.
    """
    incident_id = st.session_state.get("expert_incident_id")
    if not incident_id:
        st.warning("No incident selected.")
        _render_back_to_dashboard(key="expert_detail_back_empty")
        return

    _render_back_to_dashboard(key="expert_detail_back")

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
        _render_summary_chat_actions(int(incident_id))
        if db.is_incident_acknowledged(int(incident_id)):
            phase_label = incident_scenarios.get_display_phase(active_incident)
            if is_terminal_status(incident.get("status", "")):
                st.caption(f"Incident closed · Status: **{incident.get('status', 'Unknown')}** · Phase: **{phase_label}**")
            else:
                st.caption(
                    f"Response plan active · Status: **{incident.get('status', 'Unknown')}** · "
                    f"Phase: **{phase_label}**"
                )
        elif is_terminal_status(incident.get("status", "")):
            st.caption(f"Incident closed · Status: **{incident.get('status', 'Unknown')}**")
        from temporal_state import format_monitoring_remaining, get_monitoring_narrative_hours, is_monitoring_active

        if is_monitoring_active(active_incident):
            hours = get_monitoring_narrative_hours(int(incident_id))
            remaining = format_monitoring_remaining(active_incident)
            st.info(
                f"**Monitoring active** — {hours}h enhanced watch on "
                f"**{active_incident.get('device_name', 'device')}**. "
                f"Demo unlock in **{remaining}**. You'll get an **Incident update** alert when ready."
            )
        elif incident.get("monitor_until"):
            st.caption(f"Monitoring until: {incident['monitor_until']}")

        if can_show_start_investigation(incident):
            st.markdown('<div class="expert-detail-investigation-action"></div>', unsafe_allow_html=True)
            start_col, _ = st.columns([1, 2.2], gap="small")
            with start_col:
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
