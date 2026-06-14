"""
Standard mode Sentinel Chat panel — message list, playbook buttons, placeholder AI.

This is the primary chat UI for homeowners. Structured playbook steps use action
buttons embedded in messages; free-form text gets PLACEHOLDER_AI_REPLY (no LLM).
"""

import streamlit as st

from components.styled_buttons import render_action_button_marker
from sentinel_actions import (
    PLACEHOLDER_AI_REPLY,
    STANDARD_WELCOME_MESSAGE,
    append_message,
    latest_pending_action_index,
)


def _render_incident_header():
    """Show active incident title/severity above the chat when a session is linked."""
    from incident_scenarios import get_active_incident

    incident = get_active_incident()
    if not incident:
        return

    severity = incident.get("severity", "Low")
    severity_class = severity.lower().replace(" ", "-")
    device = incident.get("device_name") or incident.get("source", "")
    status = incident.get("status", "")

    st.markdown(
        f'<div class="standard-chat-incident-header">'
        f'<span class="standard-incident-title">{incident["title"]}</span>'
        f'<span class="standard-severity-badge severity-{severity_class}">{severity}</span>'
        f"</div>",
        unsafe_allow_html=True,
    )
    st.caption(f"Device: **{device}** | Status: **{status}**")


def _render_chat_actions(message: dict, message_index: int, pending_index: int | None):
    """
    Render clickable playbook buttons attached to an assistant message.

    Only the latest pending action row shows buttons (one step at a time UX).
    """
    from incident_scenarios import (
        handle_chat_action,
        handle_prior_session_action,
    )

    if not message.get("actions") or message.get("actions_consumed"):
        return
    if pending_index is not None and message_index != pending_index:
        return

    for action in message["actions"]:
        render_action_button_marker(action["key"])
        if st.button(
            action["label"],
            key=f"chat_action_{message_index}_{action['key']}",
            use_container_width=True,
            type="secondary",
        ):
            action_key = action["key"]
            # Prior-session bootstrap actions vs normal playbook actions.
            if action_key in ("summarize_past_sessions", "where_we_left_off"):
                handle_prior_session_action(action_key, message_index)
            else:
                handle_chat_action(action_key, message_index)
            st.rerun()


def _handle_sentinel_prompt(prompt: str):
    """
    Handle free-form user text — persists to DB but AI reply is placeholder only.

    Creates a new session_id on first message if user hasn't started a formal session.
    """
    if not prompt.strip():
        return

    if not st.session_state.get("active_session_id"):
        import db

        session_id = db.create_session_id()
        st.session_state.active_session_id = session_id
        st.session_state.active_incident_id = None
        st.session_state.messages = []

    append_message("user", prompt.strip())
    append_message("assistant", PLACEHOLDER_AI_REPLY)
    st.rerun()


def render_sentinel_panel(show_close: bool = False):
    """
    Render the main chat message scroll area for Standard mode (and drawer reuse).

    Args:
        show_close: When True, show ✕ header for modal/drawer contexts.
    """
    from incident_scenarios import sync_incident_chat

    if show_close:
        close_col, title_col = st.columns([1, 5])
        with close_col:
            if st.button("✕", key="close_sentinel_panel"):
                st.session_state.side_panel_open = False
                st.rerun()
        with title_col:
            st.markdown("**Sentinel Analyst**")

    st.markdown('<div class="standard-panel-card standard-chat-panel"></div>', unsafe_allow_html=True)
    st.markdown(
        '<h3 class="standard-section-title standard-section-title--compact">Sentinel Chat</h3>',
        unsafe_allow_html=True,
    )

    _render_incident_header()
    # Skip sync during prior-session bootstrap to avoid duplicate prompts.
    if not st.session_state.get("awaiting_playbook_bootstrap"):
        sync_incident_chat()

    pending_index = latest_pending_action_index()
    messages = st.session_state.get("messages", [])

    with st.container(border=False):
        st.markdown('<div class="standard-chat-scroll-box"></div>', unsafe_allow_html=True)
        if not messages and not st.session_state.get("active_session_id"):
            # Idle state before user selects incident or history tile.
            with st.chat_message("assistant"):
                st.markdown(STANDARD_WELCOME_MESSAGE)
        else:
            for index, message in enumerate(messages):
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])
                    _render_chat_actions(message, index, pending_index)


def render_sentinel_chat_input():
    """Render the Send form below the chat column (Standard mode layout)."""
    st.markdown('<div class="standard-chat-input-row"></div>', unsafe_allow_html=True)
    with st.form("standard_sentinel_chat_form", clear_on_submit=True, border=False):
        prompt = st.text_input(
            "Ask Sentinel about your home network...",
            key="standard_sentinel_chat_input",
            label_visibility="collapsed",
            placeholder="Ask Sentinel about your home network...",
        )
        st.markdown(
            '<div class="standard-btn-marker standard-btn--send"></div>',
            unsafe_allow_html=True,
        )
        submitted = st.form_submit_button("Send", use_container_width=True, type="primary")
        if submitted:
            _handle_sentinel_prompt(prompt)
