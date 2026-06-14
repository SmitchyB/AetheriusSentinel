"""Chat session state helpers and placeholder AI responses for Sentinel.

This module manages the Streamlit chat layer:

- Session initialization (messages list, expert mode flags, side panel state)
- Message append/load/clear with optional SQLite persistence via ``db``
- Consumption flags for one-shot action buttons and expert draft forms
- Pending-step detection so the UI can block free-text until choices resolve
- Legacy placeholder response dicts (SCAN_RESPONSES, RESPONSE_RESPONSES) for
  demo buttons not yet wired through ``incident_scenarios``
- PLACEHOLDER_AI_REPLY when no LLM backend is connected

There is no real AI model here — assistant copy comes from hard-coded strings
and from ``incident_scenarios`` / ``action_catalog`` formatters.
"""

import streamlit as st

# ---------------------------------------------------------------------------
# Welcome messages — first assistant turn per dashboard mode
# ---------------------------------------------------------------------------
EXPERT_WELCOME_MESSAGE = (
    "Hi, I am Sentinel. I help watch over your home network. "
    "Run a scan when you want me to check things, and I will explain what I find "
    "in plain language and walk you through what to do next."
)

STANDARD_WELCOME_MESSAGE = (
    "Hi, I am Sentinel. I help watch over your home network. "
    "Select an incident from the list, or pick a past conversation from Chat History."
)

# Default alias; expert UI sets expert_mode and uses EXPERT_WELCOME_MESSAGE.
WELCOME_MESSAGE = EXPERT_WELCOME_MESSAGE

# ---------------------------------------------------------------------------
# Legacy demo responses — used by older action_button flows (not playbook engine)
# ---------------------------------------------------------------------------
SCAN_RESPONSES = {
    "ai_threat_sweep": (
        "AI Threat Sweep complete. Reviewed recent local logs and traffic patterns. "
        "One anomaly detected: repeated SSH login attempts against your Smart Gateway "
        "from 103.45.67.89. No lateral movement observed."
    ),
    "active_connections": (
        "Active connection scan complete. 14 devices are currently communicating "
        "on your local network: Smart Gateway, Living Room Cam, Thermostat, "
        "MacBook Pro, and 10 additional nodes. All devices are identified."
    ),
}

RESPONSE_RESPONSES = {
    "isolate_device": (
        "Device isolated. Local firewall rules applied to cut off the targeted node "
        "from the network, stopping potential lateral movement."
    ),
    "sever_connection": (
        "Connection severed. A TCP Reset was injected to instantly terminate the "
        "dangerous traffic flow."
    ),
    "port_lockdown": (
        "Port lockdown applied. The specified port on the target machine has been "
        "shut down to stop the rogue service."
    ),
    "permanent_block": (
        "Permanent block applied. 103.45.67.89 has been added to the firewall "
        "blocklist."
    ),
    "trust_snooze": (
        "Alert snoozed. This behavior has been temporarily suppressed to reduce "
        "dashboard noise. You can review it again from your alert history."
    ),
    "incident_report": (
        "Incident Report generated.\n\n"
        "**Summary:** Brute-force SSH attempts detected against Smart Gateway "
        "(103.45.67.89).\n\n"
        "**Mitigation steps taken:** Connection monitoring active; recommended "
        "permanent block available.\n\n"
        "**Status:** Contained at network edge. No internal spread detected."
    ),
}

# ---------------------------------------------------------------------------
# Placeholder AI — fallback when user sends free-text chat (no LLM hooked up)
# ---------------------------------------------------------------------------
PLACEHOLDER_AI_REPLY = (
    "I am not hooked up to a full answer system yet, but I got your message. "
    "For now, run a scan if you want help with something on your network."
)


def _is_persisting() -> bool:
    """Return True when messages should be written to SQLite (active session id set)."""
    return bool(st.session_state.get("active_session_id"))


def init_session_state():
    """Initialize all chat-related Streamlit session keys with defaults.

    On first load in expert mode, seeds a single welcome assistant message.
    """
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "side_panel_open" not in st.session_state:
        st.session_state.side_panel_open = False
    if "active_session_id" not in st.session_state:
        st.session_state.active_session_id = None
    if "active_incident_id" not in st.session_state:
        st.session_state.active_incident_id = None
    if "expert_mode" not in st.session_state:
        st.session_state.expert_mode = False
    if "auto_defense" not in st.session_state:
        st.session_state.auto_defense = False
    if "expert_view" not in st.session_state:
        st.session_state.expert_view = "overview"
    if "expert_incident_id" not in st.session_state:
        st.session_state.expert_incident_id = None
    if "notifications_open" not in st.session_state:
        st.session_state.notifications_open = False

    from incident_scenarios import is_expert_mode

    if is_expert_mode() and not st.session_state.messages:
        st.session_state.messages = [
            {"role": "assistant", "content": EXPERT_WELCOME_MESSAGE},
        ]


def reset_expert_state():
    """Clear expert-only navigation state when leaving expert mode."""
    st.session_state.expert_view = "overview"
    st.session_state.expert_incident_id = None
    st.session_state.notifications_open = False
    st.session_state.side_panel_open = False


def load_messages_from_db(session_id: str):
    """Hydrate in-memory chat from a saved session row."""
    import db

    st.session_state.active_session_id = session_id
    st.session_state.messages = db.get_messages_for_session(session_id)
    st.session_state.active_incident_id = db.get_session_incident_id(session_id)


def clear_active_chat():
    """Drop current session binding and empty the message list."""
    st.session_state.active_session_id = None
    st.session_state.active_incident_id = None
    st.session_state.messages = []


def append_message(
    role: str,
    content: str,
    actions: list | None = None,
    draft_form: dict | None = None,
    persist: bool = True,
):
    """Append a message dict to ``st.session_state.messages``.

    Optional ``actions`` adds clickable playbook buttons (consumed once).
    Optional ``draft_form`` adds an expert parameter editor (consumed on deploy).
    When ``persist`` is True and a session id exists, also writes to SQLite.
    """
    message = {"role": role, "content": content}
    if actions:
        message["actions"] = actions
        message["actions_consumed"] = False
    if draft_form:
        message["draft_form"] = draft_form
        message["draft_form_consumed"] = False
    st.session_state.messages.append(message)

    if persist and _is_persisting():
        import db

        db.save_chat_message(
            st.session_state.active_session_id,
            role,
            content,
            st.session_state.active_incident_id,
        )


def append_user_choice(label: str):
    """Shortcut: append a user-role message (button label as content)."""
    append_message("user", label)


def consume_message_actions(index: int):
    """Mark action buttons on message ``index`` as used (prevents double-click)."""
    if 0 <= index < len(st.session_state.messages):
        st.session_state.messages[index]["actions_consumed"] = True


def consume_draft_form(index: int):
    """Mark expert draft form on message ``index`` as submitted."""
    if 0 <= index < len(st.session_state.messages):
        st.session_state.messages[index]["draft_form_consumed"] = True


def has_pending_chat_actions() -> bool:
    """Return True if any message still has unconsumed action buttons."""
    for message in st.session_state.messages:
        if message.get("actions") and not message.get("actions_consumed"):
            return True
    return False


def latest_pending_action_index() -> int | None:
    """Return the index of the last message with pending actions (or None)."""
    pending = None
    for index, message in enumerate(st.session_state.messages):
        if message.get("actions") and not message.get("actions_consumed"):
            pending = index
    return pending


def latest_pending_draft_form_index() -> int | None:
    """Return the index of the last message with an unconsumed expert draft form."""
    pending = None
    for index, message in enumerate(st.session_state.messages):
        draft_form = message.get("draft_form")
        if draft_form and not message.get("draft_form_consumed"):
            pending = index
    return pending


def chat_has_pending_step_for_current_playbook() -> bool:
    """Return True when UI should block free-text until user completes a step.

    Pending states: prior-session bootstrap, action buttons, or draft forms.
    """
    if st.session_state.get("awaiting_playbook_bootstrap"):
        return True
    if has_pending_chat_actions():
        return True
    for message in st.session_state.messages:
        draft_form = message.get("draft_form")
        if draft_form and not message.get("draft_form_consumed"):
            return True
    return False


def action_button(label: str, response_key: str, responses: dict, **button_kwargs):
    """Legacy Streamlit button that appends a canned response and reruns.

    Used by older demo paths; playbook flow prefers ``incident_scenarios`` handlers.
    """
    if st.button(label, use_container_width=True, **button_kwargs):
        append_message("assistant", responses[response_key])
        st.rerun()
