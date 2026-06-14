"""
Expert mode analyst chat drawer — @st.dialog modal with playbook + placeholder AI.

Opened from header ☰ when side_panel_open is True. Same message model as Standard chat.
"""

import streamlit as st

from components.expert_action_form import render_expert_action_approval
from components.styled_buttons import render_action_button_marker
from incident_scenarios import get_active_incident, handle_expert_chat_action, sync_incident_chat
from sentinel_actions import (
    PLACEHOLDER_AI_REPLY,
    append_message,
    latest_pending_action_index,
    latest_pending_draft_form_index,
)


def _close_expert_drawer():
    """Dialog on_dismiss callback — clears side_panel_open flag."""
    st.session_state.side_panel_open = False


def _render_expert_chat_actions(message: dict, message_index: int, pending_index: int | None):
    """Playbook action buttons inside drawer chat (Expert-specific handler)."""
    if not message.get("actions") or message.get("actions_consumed"):
        return
    if message_index != pending_index:
        return

    for action in message["actions"]:
        render_action_button_marker(action["key"])
        if st.button(
            action["label"],
            key=f"expert_chat_action_{message_index}_{action['key']}",
            use_container_width=True,
            type="secondary",
        ):
            handle_expert_chat_action(action["key"], message_index)
            st.rerun()


def _render_expert_draft_form(
    message: dict,
    message_index: int,
    pending_draft_index: int | None,
):
    """
    Inline parameter approval form embedded in a chat message.

    Shown when assistant message includes draft_form (e.g. perm_block parameters).
    """
    draft_form = message.get("draft_form")
    if not draft_form or message.get("draft_form_consumed"):
        return
    if message_index != pending_draft_index:
        return

    incident = get_active_incident()
    if not incident:
        return

    action_key = draft_form["action_key"]
    render_expert_action_approval(
        action_key,
        incident,
        key_prefix="expert_chat",
        in_chat=True,
        draft_message_index=message_index,
    )


@st.dialog("Sentinel Analyst", width="large", dismissible=True, on_dismiss=_close_expert_drawer)
def show_expert_chat_drawer():
    """
    Modal chat UI for Expert mode — st.chat_input + message history scroll.

    Free-form prompts receive PLACEHOLDER_AI_REPLY (no LLM connected).
    """
    st.caption("Ask Sentinel while reviewing the dashboard. Execute response actions on the incident page.")

    live_incident = get_active_incident()
    if live_incident:
        st.caption(
            f"Active: **{live_incident.get('title', 'Unknown')}** "
            f"({live_incident.get('severity', 'Unknown')})"
        )

    st.divider()
    st.markdown("**Chat**")

    if not st.session_state.get("awaiting_playbook_bootstrap"):
        sync_incident_chat()

    pending_action_index = latest_pending_action_index()
    pending_draft_index = latest_pending_draft_form_index()

    with st.container(height=420, border=False):
        for index, message in enumerate(st.session_state.messages):
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
                _render_expert_chat_actions(message, index, pending_action_index)
                _render_expert_draft_form(message, index, pending_draft_index)

    if prompt := st.chat_input("Ask Sentinel about your home network...", key="expert_drawer_chat"):
        append_message("user", prompt)
        append_message("assistant", PLACEHOLDER_AI_REPLY)
        st.rerun()


def open_expert_chat_drawer_if_needed():
    """Called from app.py each rerun — opens dialog when side_panel_open flag is set."""
    if st.session_state.get("side_panel_open"):
        show_expert_chat_drawer()
