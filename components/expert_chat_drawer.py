"""
Expert mode analyst chat drawer — @st.dialog modal with history, sticky action bar, and AI chat.

Purpose
-------
Expert-mode floating analyst panel opened when ``side_panel_open`` is True.
Combines history wing, context banner, message list, sticky playbook bar, chat input,
and inline expert action approval forms for draft messages.

Navigation / call graph
-----------------------
``app.py`` (Expert mode) → ``open_expert_chat_drawer_if_needed()`` →
``show_expert_chat_drawer()`` (@st.dialog).

Header hamburger (``expert_analyst_chat_toggle`` in app.py) sets ``side_panel_open``.

Session state dependencies
--------------------------
- ``side_panel_open`` — dialog visibility (cleared on dismiss).
- ``expert_drawer_history_expanded`` — history wing; cleared on drawer close.
- ``active_incident_id`` — incident context, sticky bar, placeholder text.
- ``messages`` — chat transcript (via ``render_chat_messages``).
- ``active_session_id`` — hamburger logic in app.py for history expand default.

Streamlit widget keys
---------------------
- ``expert_drawer_new_chat`` — start general chat inside drawer.
- ``expert_drawer_chat`` — ``st.chat_input`` for prompts.
- History wing keys from ``chat_history`` (``expert_history_wing_toggle``, etc.).
- Form keys from ``expert_action_form`` when draft inline.

CSS marker divs
---------------
- ``expert-drawer-root`` — dialog root scope for expert.css.
- ``expert-drawer-main``, ``expert-drawer-main-body``, ``expert-drawer-actions-row``.
- ``expert-btn-marker expert-btn--new-chat`` — new chat button.
- ``expert-drawer-chat-panel`` — fixed-height message container.

db.py / ai_service.py
---------------------
- **No direct calls.** ``handle_chat_prompt`` → db + ai_service;
  ``start_general_chat`` may create session rows via chat_sessions/db.
"""

import streamlit as st

from components.chat_history import render_expert_drawer_history
from components.expert_action_form import render_expert_action_approval
from components.sentinel_panel import render_chat_context_banner, render_chat_messages
from components.sticky_action_bar import render_sticky_action_bar
from incident_scenarios import get_active_incident
from sentinel_actions import (
    EXPERT_WELCOME_MESSAGE,
    chat_input_disabled,
    handle_chat_prompt,
    latest_pending_draft_form_index,
    start_general_chat,
)


def _close_expert_drawer():
    """
    Dialog ``on_dismiss`` callback — clears drawer visibility flags.

    Session writes: ``side_panel_open=False``, ``expert_drawer_history_expanded=False``.
    """
    st.session_state.side_panel_open = False
    st.session_state.expert_drawer_history_expanded = False


def _render_expert_draft_form(
    message: dict,
    message_index: int,
    pending_draft_index: int | None,
):
    """
    Inline parameter approval form embedded in a chat message.

    Only renders for the pending draft index when message has unconsumed ``draft_form``.
    Delegates to ``render_expert_action_approval(..., in_chat=True)``.
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
    Modal chat UI for Expert mode — history, context banner, messages, and input.

    Widget keys: ``expert_drawer_new_chat``, ``expert_drawer_chat``.

    Child renderers: ``render_expert_drawer_history``, ``render_chat_context_banner``,
    ``render_chat_messages``, ``render_sticky_action_bar(key_prefix="expert")``.

    AI path: ``handle_chat_prompt`` on chat input submit.
    """
    st.markdown('<div class="expert-drawer-root"></div>', unsafe_allow_html=True)
    render_expert_drawer_history()

    st.markdown('<div class="expert-drawer-main"></div>', unsafe_allow_html=True)

    with st.container(border=False):
        st.markdown('<div class="expert-drawer-main-body"></div>', unsafe_allow_html=True)

        st.markdown('<div class="expert-drawer-actions-row"></div>', unsafe_allow_html=True)
        _, new_chat_col = st.columns([2.2, 1])
        with new_chat_col:
            st.markdown('<div class="expert-btn-marker expert-btn--new-chat"></div>', unsafe_allow_html=True)
            if st.button(
                "New chat",
                key="expert_drawer_new_chat",
                use_container_width=True,
                help="Start a new general analyst conversation",
            ):
                start_general_chat(open_drawer=True)
                st.rerun()

        render_chat_context_banner(expert_mode=True)

        pending_draft_index = latest_pending_draft_form_index()

        st.markdown('<div class="expert-drawer-chat-panel"></div>', unsafe_allow_html=True)
        with st.container(height=360, border=False):
            render_chat_messages(
                welcome_message=EXPERT_WELCOME_MESSAGE,
                render_draft_form=_render_expert_draft_form,
                pending_draft_index=pending_draft_index,
            )

        if st.session_state.get("active_incident_id"):
            render_sticky_action_bar(key_prefix="expert")

        placeholder = (
            "Ask Sentinel about this incident..."
            if st.session_state.get("active_incident_id")
            else "Ask Sentinel a technical question..."
        )
        if prompt := st.chat_input(
            placeholder,
            key="expert_drawer_chat",
            disabled=chat_input_disabled(),
        ):
            if handle_chat_prompt(prompt):
                st.rerun()


def open_expert_chat_drawer_if_needed():
    """
    Called from ``app.py`` each Expert-mode rerun — opens dialog when ``side_panel_open``.

    Session read: ``side_panel_open``.
    """
    if st.session_state.get("side_panel_open"):
        show_expert_chat_drawer()
