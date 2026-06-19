"""Standard mode Sentinel Chat panel — message list, sticky action bar, and Ollama-backed Q&A."""

import streamlit as st

import ai_service
from components.sticky_action_bar import render_sticky_action_bar
from sentinel_actions import (
    STANDARD_WELCOME_MESSAGE,
    chat_input_disabled,
    handle_chat_prompt,
)


# ---------------------------------------------------------------------------
# Context banner — incident header or general Q&A caption above messages
# ---------------------------------------------------------------------------

def render_incident_header(*, expert_mode: bool = False):
    """Show active incident title/severity above the chat when a session is linked."""
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
    """Context line above messages — general Q&A caption or active incident header."""
    if st.session_state.get("active_incident_id"):
        render_incident_header(expert_mode=expert_mode)
    elif expert_mode:
        st.caption("General analyst Q&A — not tied to an incident")


def render_ai_status_banner():
    """Show one-shot playbook errors above the message list."""
    if st.session_state.get("playbook_error_notice"):
        st.error(st.session_state.playbook_error_notice)
        st.session_state.playbook_error_notice = None


def _get_chat_thinking_message() -> str | None:
    """Return in-chat thinking copy while deferred or in-flight AI work is active."""
    from incident_scenarios import get_ai_status_message, is_ai_busy, is_generating_playbook

    pending = st.session_state.get("pending_chat_ai")
    if pending:
        kind = pending.get("kind", "")
        by_kind = {
            "answer_chat": "Sentinel is thinking…",
            "step_guidance": "Sentinel is preparing your next step…",
            "incident_report": "Sentinel is generating your incident report…",
            "execute_action": "Sentinel is thinking…",
            "verify_resolution": "Sentinel is reviewing this choice…",
        }
        return by_kind.get(kind, get_ai_status_message())

    bootstrap_id = st.session_state.get("pending_chat_bootstrap_incident_id")
    if bootstrap_id and is_generating_playbook(bootstrap_id):
        return "Sentinel is analyzing incident evidence…"

    if is_ai_busy():
        return get_ai_status_message()

    return None


def _render_chat_thinking_indicator() -> None:
    """Render a Sentinel thinking row inside the chat transcript."""
    message = _get_chat_thinking_message()
    if not message:
        return
    with st.chat_message("assistant"):
        st.markdown(
            '<div class="sentinel-chat-thinking-marker"></div>'
            '<div class="sentinel-chat-thinking">'
            '<span class="sentinel-chat-thinking__spinner" aria-hidden="true"></span>'
            f"<span>{message}</span>"
            "</div>",
            unsafe_allow_html=True,
        )


def _render_chat_message_body(message: dict) -> None:
    """Render one chat message — evidence turns get distinct styling and verify warning."""
    content = str(message.get("content") or "")
    is_evidence = message.get("message_kind") == "evidence" or ai_service.is_evidence_message_content(
        content
    )
    if is_evidence:
        display = content
        if ai_service.is_evidence_message_content(content):
            display = content[len(ai_service.EVIDENCE_MESSAGE_PREFIX) :].lstrip("\n")
        st.markdown(
            f'<div class="sentinel-chat-evidence-marker"></div>\n\n'
            f'<div class="sentinel-chat-evidence">\n\n'
            f"**Database evidence used**\n\n{display}\n\n"
            f"> AI output is generated from the database evidence shown above. "
            f"Verify the response against the source records.\n\n"
            f"</div>",
            unsafe_allow_html=True,
        )
        return
    st.markdown(content)


# ---------------------------------------------------------------------------
# Pending AI work — two-phase rerun (evidence visible, then LLM)
# ---------------------------------------------------------------------------

def finish_pending_chat_work() -> bool:
    """Paint evidence + thinking first, then run deferred AI on the next rerun."""
    from incident_scenarios import (
        is_generating_playbook,
        process_pending_chat_ai,
        process_pending_incident_chat_work,
    )

    has_pending_ai = bool(st.session_state.get("pending_chat_ai"))
    bootstrap_id = st.session_state.get("pending_chat_bootstrap_incident_id")
    has_bootstrap = bool(bootstrap_id and is_generating_playbook(bootstrap_id))

    if not has_pending_ai and not has_bootstrap:
        st.session_state.pending_chat_work_painted = False
        return False

    if not st.session_state.get("pending_chat_work_painted"):
        st.session_state.pending_chat_work_painted = True
        return True

    if process_pending_chat_ai():
        st.session_state.pending_chat_work_painted = False
        return True
    if process_pending_incident_chat_work():
        st.session_state.pending_chat_work_painted = False
        return True
    return False


# ---------------------------------------------------------------------------
# Message list — scrollable transcript, welcome, and thinking indicator
# ---------------------------------------------------------------------------

def render_chat_messages(
    *,
    welcome_message: str | None = None,
    render_draft_form=None,
    pending_draft_index: int | None = None,
):
    """Render the scrollable message list with optional welcome and draft forms."""
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
                _render_chat_message_body(message)
                if render_draft_form is not None and pending_draft_index is not None:
                    render_draft_form(message, index, pending_draft_index)

    _render_chat_thinking_indicator()


# ---------------------------------------------------------------------------
# Standard panel shell — message area and pinned chat input
# ---------------------------------------------------------------------------

def render_sentinel_panel(show_close: bool = False):
    """Render the main chat message scroll area for Standard mode (and drawer reuse)."""
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
        if finish_pending_chat_work():
            st.rerun()


def render_sentinel_chat_input():
    """Render compact sticky actions and Send form pinned to the bottom of the chat panel."""
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
