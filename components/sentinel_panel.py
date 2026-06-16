"""
Standard mode Sentinel Chat panel — message list, sticky action bar, and Ollama-backed Q&A.

Purpose
-------
Renders the main homeowner chat UI: incident header, scrollable messages, sticky
playbook actions, and text input form. Expert drawer reuses ``render_chat_messages``
and ``render_chat_context_banner`` with different welcome text and draft forms.

Navigation / call graph
-----------------------
``standard_dashboard`` → ``render_sentinel_panel()`` + ``render_sentinel_chat_input()``.
``expert_chat_drawer`` → shared message/banner renderers + ``st.chat_input``.

Session state dependencies
--------------------------
- ``messages`` — chat transcript list of {role, content, ...} dicts.
- ``active_incident_id`` — shows incident header vs general Q&A caption.
- ``side_panel_open`` — cleared by close button when ``show_close=True``.
- ``playbook_error_notice`` — one-shot error banner in ``render_ai_status_banner``.
- AI busy / playbook flags via ``incident_scenarios`` (disables input).

Streamlit widget keys
---------------------
- ``close_sentinel_panel`` — ✕ when ``show_close=True``.
- ``standard_sentinel_chat_input`` — text field inside form.
- Form id: ``standard_sentinel_chat_form`` (submit triggers ``handle_chat_prompt``).
- Expert drawer uses ``expert_drawer_chat`` (``st.chat_input`` in sibling module).

CSS marker divs
---------------
- ``standard-panel-card standard-chat-panel standard-chat-row`` — panel shell.
- ``standard-chat-scroll-box`` — message scroll region.
- ``standard-chat-footer``, ``standard-chat-action-bar-row``, ``standard-chat-input-row``.
- Incident header classes: ``standard-chat-incident-header``, ``standard-incident-title``,
  ``standard-severity-badge`` (Expert reuses ``expert-detail-*`` variants).

db.py / ai_service.py
---------------------
- **No direct calls in this module.**
- ``handle_chat_prompt`` (``sentinel_actions``) persists messages via ``db`` and may
  invoke ``ai_service`` for LLM responses and playbook generation.
"""

import streamlit as st

from components.sticky_action_bar import render_sticky_action_bar
from sentinel_actions import (
    STANDARD_WELCOME_MESSAGE,
    chat_input_disabled,
    handle_chat_prompt,
)


def render_incident_header(*, expert_mode: bool = False):
    """
    Show active incident title/severity above the chat when a session is linked.

    Reads incident mirror from ``incident_scenarios.get_active_incident()`` (session).
    Shows monitoring info via ``temporal_state`` when watch window is active.

    Args:
        expert_mode: Switches CSS classes to Expert detail header styling.
    """
    from incident_scenarios import (
        get_active_incident,
        get_display_phase,
        get_homeowner_phase_caption,
    )
    from temporal_state import (
        format_monitoring_remaining,
        get_monitoring_narrative_hours,
        is_monitoring_active,
    )

    incident = get_active_incident()
    if not incident:
        return

    severity = incident.get("severity", "Low")
    severity_class = severity.lower().replace(" ", "-")
    device = incident.get("device_name") or incident.get("source", "")
    status = incident.get("status", "")
    header_class = "expert-detail-header" if expert_mode else "standard-chat-incident-header"
    title_class = "expert-detail-title" if expert_mode else "standard-incident-title"
    badge_class = "expert-severity-badge" if expert_mode else "standard-severity-badge"

    st.markdown(
        f'<div class="{header_class}">'
        f'<span class="{title_class}">{incident["title"]}</span>'
        f'<span class="{badge_class} severity-{severity_class}">{severity}</span>'
        f"</div>",
        unsafe_allow_html=True,
    )
    st.caption(f"Device: **{device}** | Status: **{status}**")

    if expert_mode:
        phase_label = get_display_phase(incident)
        if phase_label:
            st.caption(f"Phase: **{phase_label}**")
    else:
        phase_caption = get_homeowner_phase_caption(incident)
        if phase_caption:
            st.caption(phase_caption)

    if is_monitoring_active(incident):
        incident_id = incident.get("incident_id")
        hours = get_monitoring_narrative_hours(incident_id) if incident_id else 36
        remaining = format_monitoring_remaining(incident)
        if expert_mode:
            st.info(
                f"**Monitoring active** — {hours}h enhanced watch on "
                f"**{device or 'device'}**. Demo unlock in **{remaining}**."
            )
        else:
            st.info(
                f"**Monitoring active** — {hours}h watch on **{device or 'this device'}**. "
                f"Next step unlocks in **{remaining}**."
            )


def render_chat_context_banner(*, expert_mode: bool = False):
    """
    Context line above messages — general Q&A caption or active incident header.

    Session read: ``active_incident_id``.
    """
    if st.session_state.get("active_incident_id"):
        render_incident_header(expert_mode=expert_mode)
    elif expert_mode:
        st.caption("General analyst Q&A — not tied to an incident")


def render_ai_status_banner():
    """
    Show loading feedback while playbook generation or AI work is in progress.

    Reads ``playbook_error_notice`` (one-shot), ``is_generating_playbook()``,
    ``is_ai_busy()`` — latter two gate on ``ai_service`` work in flight.
    """
    from incident_scenarios import is_ai_busy, is_generating_playbook

    if st.session_state.get("playbook_error_notice"):
        st.error(st.session_state.playbook_error_notice)
        st.session_state.playbook_error_notice = None
    if is_generating_playbook():
        st.info("Sentinel is building your response plan…")
    elif is_ai_busy():
        st.info("Sentinel is thinking…")


def render_chat_messages(
    *,
    welcome_message: str | None = None,
    render_draft_form=None,
    pending_draft_index: int | None = None,
):
    """
    Render the scrollable message list with optional welcome and draft forms.

    Args:
        welcome_message: Shown when no messages and no active incident (Standard/Expert welcome).
        render_draft_form: Optional callback(message, index, pending_draft_index) for inline forms.
        pending_draft_index: Which message index may show expert action approval form.

    Session read: ``messages``, ``active_incident_id``.
    """
    messages = st.session_state.get("messages", [])

    render_ai_status_banner()
    show_welcome = (
        welcome_message
        and not messages
        and not st.session_state.get("active_incident_id")
    )
    if show_welcome:
        with st.chat_message("assistant"):
            st.markdown(welcome_message)
    else:
        for index, message in enumerate(messages):
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
                if render_draft_form is not None and pending_draft_index is not None:
                    render_draft_form(message, index, pending_draft_index)


def render_sentinel_panel(show_close: bool = False):
    """
    Render the main chat message scroll area for Standard mode (and drawer reuse).

    Args:
        show_close: When True, show ✕ header for modal/drawer contexts.

    Widget key (when show_close): ``close_sentinel_panel``.

    CSS: ``standard-chat-panel``, ``standard-chat-scroll-box``.
    """
    if show_close:
        close_col, title_col = st.columns([1, 5])
        with close_col:
            if st.button("✕", key="close_sentinel_panel"):
                st.session_state.side_panel_open = False
                st.rerun()
        with title_col:
            st.markdown("**Sentinel Analyst**")

    st.markdown('<div class="standard-panel-card standard-chat-panel standard-chat-row"></div>', unsafe_allow_html=True)
    st.markdown(
        '<h3 class="standard-section-title standard-section-title--compact">Sentinel Chat</h3>',
        unsafe_allow_html=True,
    )

    with st.container(border=False):
        st.markdown('<div class="standard-chat-scroll-box"></div>', unsafe_allow_html=True)
        render_incident_header(expert_mode=False)
        render_chat_messages(welcome_message=STANDARD_WELCOME_MESSAGE)


def render_sentinel_chat_input():
    """
    Render compact sticky actions and Send form pinned to the bottom of the chat panel.

    Widget keys: form ``standard_sentinel_chat_form``, input ``standard_sentinel_chat_input``.

    CSS: ``standard-chat-footer``, ``standard-chat-action-bar-row``,
    ``standard-chat-input-row``, ``standard-btn--send`` marker.

    On submit: ``handle_chat_prompt`` → db persist + optional ``ai_service`` call.
    """
    st.markdown('<div class="standard-chat-footer"></div>', unsafe_allow_html=True)
    st.markdown('<div class="standard-chat-action-bar-row"></div>', unsafe_allow_html=True)
    render_sticky_action_bar(key_prefix="standard")

    st.markdown('<div class="standard-chat-input-row"></div>', unsafe_allow_html=True)
    input_disabled = chat_input_disabled()
    with st.form("standard_sentinel_chat_form", clear_on_submit=True, border=False):
        prompt = st.text_input(
            "Ask Sentinel about your home network...",
            key="standard_sentinel_chat_input",
            label_visibility="collapsed",
            placeholder="Ask Sentinel about this incident...",
            disabled=input_disabled,
        )
        st.markdown(
            '<div class="standard-btn-marker standard-btn--send"></div>',
            unsafe_allow_html=True,
        )
        submitted = st.form_submit_button(
            "Send",
            use_container_width=True,
            type="primary",
            disabled=input_disabled,
        )
        if submitted and handle_chat_prompt(prompt):
            st.rerun()
