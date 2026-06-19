"""Chat session state helpers and AI chat orchestration for Sentinel."""

import streamlit as st

# ---------------------------------------------------------------------------
# Welcome messages — first assistant turn per dashboard mode
# ---------------------------------------------------------------------------
# Components render these when starting a fresh thread with no messages.
# WELCOME_MESSAGE is the default alias; app.py sets expert_mode and may swap.
EXPERT_WELCOME_MESSAGE = (
    "Sentinel Analyst online. Dashboard Q&A — ask about any incident, device, or system telemetry. "
    "Open an incident's investigation chat for case-specific response work."
)

STANDARD_WELCOME_MESSAGE = (
    "Hi, I am Sentinel. I help watch over your home network. "
    "Ask about your network or any alert — I will explain in plain language. "
    "Pick an open incident below when you want step-by-step help with that specific alert."
)

# Default alias; expert UI sets expert_mode and uses EXPERT_WELCOME_MESSAGE.
WELCOME_MESSAGE = EXPERT_WELCOME_MESSAGE

# ---------------------------------------------------------------------------
# Legacy demo responses — kept for older action_button flows (not playbook engine)
# ---------------------------------------------------------------------------
# Intentional compatibility layer; new work should use the playbook engine in
# incident_scenarios rather than these canned SCAN_RESPONSES / RESPONSE_RESPONSES.
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
# Placeholder AI — fallback when Ollama is unreachable or chat is disabled
# ---------------------------------------------------------------------------
PLACEHOLDER_AI_REPLY = (
    "I am not hooked up to a full answer system yet, but I got your message. "
    "For now, run a scan if you want help with something on your network."
)


def generate_sentinel_reply(user_message: str) -> str:
    """Run AI chat and append assistant message(s). Returns the main reply text."""
    return handle_sentinel_chat_message(user_message)


def is_get_started_intent(message: str) -> bool:
    """Return True when free-text looks like the user wants to begin the plan."""
    normalized = message.strip().lower()
    phrases = (
        "get started",
        "let's go",
        "lets go",
        "yes",
        "ready",
        "start the plan",
        "show me the plan",
        "begin",
    )
    return any(normalized == phrase or normalized.startswith(f"{phrase} ") for phrase in phrases)


def is_progress_intent(message: str) -> bool:
    """Return True when the user is asking for status, recap, or the next playbook step."""
    normalized = message.strip().lower()
    if is_get_started_intent(normalized):
        return True

    phrases = (
        "where are we",
        "where we at",
        "where we left",
        "what's the next step",
        "whats the next step",
        "what is the next step",
        "next step",
        "what do i do now",
        "what should i do",
        "what now",
        "status update",
        "catch me up",
        "recap",
        "summarize",
        "summary",
        "run down",
        "rundown",
        "run through",
        "run-through",
        "walk me through",
        "what happened",
        "break down",
        "breakdown",
        "overview",
        "tell me about",
        "explain the incident",
        "explain what",
        "progress",
        "how far",
        "what have we done",
        "what steps",
        "pick up where",
        "resume",
    )
    return any(phrase in normalized for phrase in phrases)


# ---------------------------------------------------------------------------
# Intent-detection phrase lists — free-text substitutes for chat buttons
# ---------------------------------------------------------------------------
# Used when awaiting_get_started or when user asks "where are we" instead of
# clicking sticky-bar buttons. Kept as module-level tuples for easy tuning.
_OFF_TOPIC_MARKERS = (
    "weather",
    "recipe",
    "joke",
    "poem",
    "stock",
    "bitcoin",
    "movie",
    "sports",
    "who won",
    "what time is it",
)

_GENERAL_DOMAIN_MARKERS = (
    "incident",
    "alert",
    "attack",
    "threat",
    "malware",
    "network",
    "device",
    "scan",
    "sentinel",
    "security",
    "hack",
    "password",
    "firewall",
    "ransomware",
    "phishing",
    "critical",
    "severity",
    "status",
    "hardware",
    "home",
    "router",
    "gateway",
    "telemetry",
    "ioc",
    "contain",
    "block",
    "isolate",
)


def _scope_redirect_message(
    kind: str,
    *,
    expert_mode: bool,
    incident: dict | None = None,
) -> str:
    """Tone-aware short-circuit replies for scope and off-topic guards."""
    title = (incident or {}).get("title", "this incident")
    if kind == "off_topic_general":
        if expert_mode:
            return (
                "Out of scope for general analyst chat. "
                "Ask about incidents, devices, alerts, or network telemetry."
            )
        return (
            "I'm here to help with your home network and security alerts. "
            "Ask me about a device, an incident, or your network."
        )
    if kind == "other_incident":
        if expert_mode:
            return (
                f"Scoped to **{title}** only. "
                "Use general analyst chat for other incidents or dashboard questions."
            )
        return (
            f"I'm focused on **{title}** right now. "
            "For questions about other alerts, start a general chat from the dashboard."
        )
    if kind == "off_topic_incident_pre_ack":
        if expert_mode:
            return (
                f"Scoped to **{title}**. Ask about this case, its evidence, or click **Get started** "
                "for the response plan."
            )
        return (
            f"I'm focused on **{title}** right now. "
            "Ask me about this alert, or click **Get started** when you're ready for the response plan."
        )
    if kind == "off_topic_incident_complete":
        if expert_mode:
            return (
                f"Scoped to **{title}**. Ask about documentation, evidence preservation, "
                "or authority materials—or use the documentation buttons below."
            )
        return (
            f"I'm focused on **{title}** right now. "
            "Ask me about wrapping up this alert, or use the buttons below for next steps."
        )
    if expert_mode:
        return (
            f"Scoped to **{title}**. Ask about this incident, its evidence, or the next response step."
        )
    return (
        f"I'm focused on **{title}** right now. "
        "Ask me about this incident or the next step."
    )


def is_likely_off_topic_general(user_message: str) -> bool:
    """Heuristic guard for general-scoped chat."""
    normalized = user_message.strip().lower()
    if any(marker in normalized for marker in _OFF_TOPIC_MARKERS):
        return True
    if any(marker in normalized for marker in _GENERAL_DOMAIN_MARKERS):
        return False
    return False


def is_asking_about_other_incident(user_message: str, current_incident_id: int) -> bool:
    """Return True when the user appears to ask about a different open incident."""
    import db

    normalized = user_message.strip().lower()
    try:
        incidents_df = db.get_incidents_filtered(status="Open")
    except Exception:
        return False

    if incidents_df.empty:
        return False

    for _, row in incidents_df.iterrows():
        other_id = int(row.get("ID", 0))
        if other_id == current_incident_id:
            continue
        title = str(row.get("Title", "")).strip().lower()
        if title and len(title) > 4 and title in normalized:
            return True
        for pattern in (f"incident {other_id}", f"incident #{other_id}", f"id {other_id}"):
            if pattern in normalized:
                return True
    return False


def is_likely_off_topic(user_message: str, incident: dict | None) -> bool:
    """Heuristic guard for incident-scoped chat when no incident context applies."""
    if not incident:
        return False

    normalized = user_message.strip().lower()
    if is_get_started_intent(normalized):
        return False

    incident_terms = {
        incident.get("title", "").lower(),
        incident.get("device_name", "").lower(),
        incident.get("source", "").lower(),
        incident.get("indicator", "").lower(),
        "incident",
        "alert",
        "attack",
        "threat",
        "malware",
        "block",
        "isolate",
        "scan",
        "step",
        "plan",
        "playbook",
        "sentinel",
        "network",
        "device",
        "hack",
        "password",
        "firewall",
    }
    incident_terms = {term for term in incident_terms if term}

    if any(term in normalized for term in incident_terms):
        return False

    off_topic_markers = _OFF_TOPIC_MARKERS
    return any(marker in normalized for marker in off_topic_markers)


# ---------------------------------------------------------------------------
# AI chat orchestration — scope guards, two-phase evidence + LLM rerun
# ---------------------------------------------------------------------------

def chat_input_disabled() -> bool:
    """Return True when free-text input should be blocked."""
    return chat_has_pending_step_for_current_playbook()


def handle_sentinel_chat_message(user_message: str) -> str:
    """Run AI chat, append assistant message(s), and offer plan updates when suggested."""
    import db
    from incident_scenarios import (
        get_active_incident,
        get_playbook_phase,
        is_playbook_complete,
    )

    incident_id = st.session_state.get("active_incident_id")
    expert_mode = bool(st.session_state.get("expert_mode"))
    chat_scope = "incident" if incident_id else "general"
    phase = "closed"
    incident = None
    if incident_id:
        incident = get_active_incident()
        if incident:
            phase = get_playbook_phase(incident)

    # --- Scope guards: short-circuit before LLM to save tokens and stay on-rails ---
    if chat_scope == "general":
        if is_likely_off_topic_general(user_message):
            reply = _scope_redirect_message("off_topic_general", expert_mode=expert_mode)
            append_message("assistant", reply)
            return reply
    elif incident_id and incident:
        if is_asking_about_other_incident(user_message, int(incident_id)):
            reply = _scope_redirect_message(
                "other_incident",
                expert_mode=expert_mode,
                incident=incident,
            )
            append_message("assistant", reply)
            return reply

    if incident_id and incident and st.session_state.get("awaiting_get_started"):
        # User has not clicked Get started — prefer deterministic handlers
        if is_get_started_intent(user_message):
            from incident_scenarios import GET_STARTED_ACTION, handle_sticky_action

            handle_sticky_action(GET_STARTED_ACTION)
            return "Get started"
        elif is_progress_intent(user_message):
            from incident_scenarios import build_progress_chat_response

            text, _actions = build_progress_chat_response(
                incident_id,
                incident,
                expert_mode=expert_mode,
            )
            append_message("assistant", text)
            return text
        elif is_likely_off_topic(user_message, incident):
            reply = _scope_redirect_message(
                "off_topic_incident_pre_ack",
                expert_mode=expert_mode,
                incident=incident,
            )
            append_message("assistant", reply)
            return reply

    if incident_id and incident and not st.session_state.get("awaiting_get_started"):
        if is_progress_intent(user_message):
            from incident_scenarios import build_progress_chat_response

            text, _actions = build_progress_chat_response(
                incident_id,
                incident,
                expert_mode=expert_mode,
            )
            append_message("assistant", text)
            return text
        if is_likely_off_topic(user_message, incident):
            kind = (
                "off_topic_incident_complete"
                if is_playbook_complete(incident)
                else "off_topic_incident"
            )
            reply = _scope_redirect_message(
                kind,
                expert_mode=expert_mode,
                incident=incident,
            )
            append_message("assistant", reply)
            return reply

    return _queue_chat_ai_request(
        user_message=user_message,
        incident_id=incident_id,
        chat_scope=chat_scope,
        expert_mode=expert_mode,
        phase=phase,
        incident=incident,
    )


def _queue_chat_ai_request(
    *,
    user_message: str,
    incident_id: int | None,
    chat_scope: str,
    expert_mode: bool,
    phase: str,
    incident: dict | None,
) -> str:
    """Phase 1: show DB evidence in chat, then rerun to run the LLM on the next pass."""
    request_kind = "general_chat" if chat_scope == "general" else "chat"
    append_evidence_message(
        incident_id=int(incident_id) if incident_id else None,
        request_label="Chat question",
        request_kind=request_kind,
        expert_mode=expert_mode,
    )
    st.session_state.pending_chat_ai = {
        "kind": "answer_chat",
        "user_message": user_message,
        "incident_id": incident_id,
        "chat_scope": chat_scope,
        "expert_mode": expert_mode,
        "phase": phase,
        "awaiting_get_started": bool(st.session_state.get("awaiting_get_started")),
    }
    st.rerun()
    return user_message


def _is_persisting() -> bool:
    """Return True when messages should be written to SQLite (active session id set)."""
    return bool(st.session_state.get("active_session_id"))


# ---------------------------------------------------------------------------
# Streamlit session state — chat identity, expert navigation, pending AI work
# ---------------------------------------------------------------------------

def init_session_state():
    """Initialize all chat-related Streamlit session keys with defaults."""
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "side_panel_open" not in st.session_state:
        st.session_state.side_panel_open = False
    if "expert_drawer_history_expanded" not in st.session_state:
        st.session_state.expert_drawer_history_expanded = False
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
    if "pending_plan_update" not in st.session_state:
        st.session_state.pending_plan_update = None
    if "pending_action_verification" not in st.session_state:
        st.session_state.pending_action_verification = None
    if "pending_chat_ai" not in st.session_state:
        st.session_state.pending_chat_ai = None
    if "pending_chat_work_painted" not in st.session_state:
        st.session_state.pending_chat_work_painted = False
    if "ai_status_message" not in st.session_state:
        st.session_state.ai_status_message = None


def start_general_chat(*, open_drawer: bool = True) -> None:
    """Start a new general analyst thread with no incident binding."""
    import db

    st.session_state.active_session_id = db.create_session_id()
    st.session_state.active_incident_id = None
    st.session_state.active_incident = None
    st.session_state.messages = []
    st.session_state.awaiting_get_started = False
    st.session_state.playbook_phase = None
    st.session_state.pending_plan_update = None
    st.session_state.pending_chat_ai = None
    st.session_state.pending_chat_work_painted = False
    st.session_state.ai_status_message = None
    st.session_state.expert_drawer_history_expanded = False
    if open_drawer:
        st.session_state.side_panel_open = True


def handle_chat_prompt(prompt: str) -> bool:
    """Handle free-form user text — persists to DB and returns an AI-grounded reply."""
    if not prompt.strip():
        return False

    if not st.session_state.get("active_session_id"):
        import db

        st.session_state.active_session_id = db.create_session_id()
        if st.session_state.get("active_incident_id") is None:
            st.session_state.messages = []

    append_message("user", prompt.strip())
    handle_sentinel_chat_message(prompt.strip())
    return True


def bump_incidents_table_revision() -> None:
    """Force incidents table widgets to reload from the database on next render."""
    st.session_state.incidents_table_revision = (
        st.session_state.get("incidents_table_revision", 0) + 1
    )


def bump_notifications_revision() -> None:
    """Force notification bell/panel to reflect new alerts or incident updates."""
    st.session_state.notifications_revision = (
        st.session_state.get("notifications_revision", 0) + 1
    )
    bump_incidents_table_revision()


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
    st.session_state.messages = hydrate_loaded_messages(db.get_messages_for_session(session_id))
    st.session_state.active_incident_id = db.get_session_incident_id(session_id)


def clear_active_chat():
    """Drop current session binding and empty the message list."""
    st.session_state.active_session_id = None
    st.session_state.active_incident_id = None
    st.session_state.messages = []


# ---------------------------------------------------------------------------
# Message persistence — append to session state and optional SQLite write
# ---------------------------------------------------------------------------

def append_message(
    role: str,
    content: str,
    actions: list | None = None,
    draft_form: dict | None = None,
    plan_update: dict | None = None,
    persist: bool = True,
    message_kind: str | None = None,
):
    """Append a message dict to ``st.session_state.messages``."""
    message = {"role": role, "content": content}
    if message_kind:
        message["message_kind"] = message_kind
    if actions:
        message["actions"] = actions
        message["actions_consumed"] = False
    if draft_form:
        message["draft_form"] = draft_form
        message["draft_form_consumed"] = False
    if plan_update:
        message["plan_update"] = plan_update
    st.session_state.messages.append(message)

    if persist and _is_persisting():
        import db

        db.save_chat_message(
            st.session_state.active_session_id,
            role,
            content,
            st.session_state.active_incident_id,
        )


def append_evidence_message(
    *,
    incident_id: int | None,
    request_label: str,
    request_kind: str,
    expert_mode: bool | None = None,
    next_action_key: str | None = None,
    update_row: dict | None = None,
    persist: bool = True,
) -> None:
    """Append an assistant turn showing database evidence retrieved for an AI request."""
    import ai_service

    if expert_mode is None:
        expert_mode = bool(st.session_state.get("expert_mode"))

    body = ai_service.format_request_evidence_markdown(
        incident_id=incident_id,
        request_label=request_label,
        request_kind=request_kind,
        expert_mode=expert_mode,
        next_action_key=next_action_key,
        update_row=update_row,
    )
    content = ai_service.build_evidence_message_content(request_label, body)
    append_message("assistant", content, message_kind="evidence", persist=persist)


def hydrate_loaded_messages(messages: list[dict]) -> list[dict]:
    """Restore in-memory metadata (e.g. message_kind) when loading from SQLite."""
    import ai_service

    hydrated: list[dict] = []
    for message in messages:
        row = dict(message)
        if row.get("message_kind"):
            hydrated.append(row)
            continue
        content = str(row.get("content") or "")
        if ai_service.is_evidence_message_content(content):
            row["message_kind"] = "evidence"
        hydrated.append(row)
    return hydrated


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
    """Return True when UI should block free-text until user completes a step."""
    if has_pending_chat_actions():
        return True
    for message in st.session_state.messages:
        draft_form = message.get("draft_form")
        if draft_form and not message.get("draft_form_consumed"):
            return True
    return False


def action_button(label: str, response_key: str, responses: dict, **button_kwargs):
    """Legacy Streamlit button that appends a canned response and reruns."""
    if st.button(label, use_container_width=True, **button_kwargs):
        append_message("assistant", responses[response_key])
        st.rerun()
