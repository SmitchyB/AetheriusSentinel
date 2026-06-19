"""Chat history sidebar — resume past analyst sessions from chat_messages table."""

import streamlit as st

import db
from sentinel_actions import start_general_chat
from components.styled_buttons import render_button_marker, UI_MARKERS

# Max characters shown on history tile title before ellipsis truncation.
_HISTORY_TITLE_MAX = 22


# ---------------------------------------------------------------------------
# History tile helpers — truncate titles and format activity timestamps
# ---------------------------------------------------------------------------

def _truncate_title(title: str) -> str:
    """Shorten long incident titles for narrow history column tiles."""
    if len(title) <= _HISTORY_TITLE_MAX:
        return title
    return f"{title[: _HISTORY_TITLE_MAX - 1].rstrip()}…"


def _format_history_date(activity: str) -> str:
    """Format SQLite datetime string to 'YYYY-MM-DD HH:MM' for tile subtitle."""
    if not activity:
        return "—"
    parts = activity.split(" ")
    if len(parts) >= 2:
        return f"{parts[0]} {parts[1][:5]}"
    return activity


# ---------------------------------------------------------------------------
# Session tiles — clickable buttons that reload a persisted thread
# ---------------------------------------------------------------------------

def render_session_tiles(    sessions: list[dict],
    *,
    key_prefix: str,
    active_session_id: str | None = None,
    open_side_panel: bool = False,
    title_field: str = "incident_title",
    date_field: str = "last_activity",
):
    """Render clickable history tiles as styled Streamlit buttons."""
    if not sessions:
        return False

    for index, session in enumerate(sessions):
        session_id = session["session_id"]
        is_active = session_id == active_session_id
        title = session.get(title_field) or "General chat"
        label = _truncate_title(title)
        activity = _format_history_date(session.get(date_field, ""))
        button_label = f"{label} · {activity}" if activity != "—" else label

        if st.button(
            button_label,
            key=f"{key_prefix}_{index}_{session_id[:8]}",
            help=title,
            use_container_width=True,
            type="primary" if is_active else "secondary",
        ):
            import chat_sessions

            chat_sessions.load_chat_session(session_id)
            if open_side_panel:
                st.session_state.side_panel_open = True
            st.session_state.expert_drawer_history_expanded = False
            st.rerun()

    return True


# ---------------------------------------------------------------------------
# Standard mode — general conversation history column
# ---------------------------------------------------------------------------

def render_chat_history():
    """Standard mode left column — recent general (non-incident) chat sessions."""
    st.markdown(
        '<div class="standard-panel-card standard-history-panel standard-chat-row"></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<h3 class="standard-section-title standard-section-title--compact">General Conversations</h3>',
        unsafe_allow_html=True,
    )

    new_col, _ = st.columns([1, 0.01])
    with new_col:
        render_button_marker(UI_MARKERS["start_chat"])
        if st.button(
            "New general chat",
            key="standard_history_new_general_chat",
            use_container_width=True,
            help="Start a fresh analyst conversation not tied to an incident",
        ):
            start_general_chat(open_drawer=False)
            st.rerun()

    if not db.DB_PATH.exists():
        st.error(
            f"Database not found at `{db.DB_PATH}`. "
            "Run `python seed.py` from the project root, then refresh."
        )
        return

    try:
        sessions = db.get_general_session_history(limit=20)
    except Exception as error:
        st.error("Could not load chat history.")
        st.exception(error)
        return

    active_session = st.session_state.get("active_session_id")

    with st.container(border=False):
        st.markdown('<div class="standard-history-scroll-box"></div>', unsafe_allow_html=True)
        if not sessions:
            st.caption("No general chats yet.")
            return

        render_session_tiles(
            sessions,
            key_prefix="history_card",
            active_session_id=active_session,
        )


def render_incident_session_tiles(
    incident_id: int,
    *,
    incident_title: str,
    key_prefix: str,
    open_side_panel: bool = True,
):
    """History tiles filtered to one incident (Expert incident detail / drawer)."""
    try:
        sessions = db.get_sessions_for_incident(incident_id)
    except Exception as error:
        st.error("Could not load chat sessions for this incident.")
        st.exception(error)
        return

    if not sessions:
        st.caption("No chat sessions linked to this incident yet.")
        return

    display_sessions = [
        {
            "session_id": row["session_id"],
            "incident_title": incident_title,
            "last_activity": row.get("last_activity") or row.get("started_at", ""),
        }
        for row in sessions
    ]

    with st.container(border=False):
        st.markdown('<div class="standard-history-scroll-box"></div>', unsafe_allow_html=True)
        render_session_tiles(
            display_sessions,
            key_prefix=key_prefix,
            active_session_id=st.session_state.get("active_session_id"),
            open_side_panel=open_side_panel,
        )


# ---------------------------------------------------------------------------
# Expert drawer — collapsible history wing beside analyst chat
# ---------------------------------------------------------------------------

def _render_expert_drawer_history_content():
    """Session lists rendered inside the Expert drawer history wing (General + This incident)."""
    if not db.DB_PATH.exists():
        st.caption("Database not found — run `python seed.py` to enable chat history.")
        return

    st.markdown("**General**")
    try:
        general_sessions = db.get_general_session_history(limit=20)
    except Exception as error:
        st.error("Could not load chat history.")
        st.exception(error)
        general_sessions = []

    st.markdown('<div class="expert-drawer-history-scroll standard-history-scroll-box"></div>', unsafe_allow_html=True)
    if not general_sessions:
        st.caption("No general chats yet.")
    else:
        render_session_tiles(
            general_sessions,
            key_prefix="expert_history_general",
            active_session_id=st.session_state.get("active_session_id"),
            open_side_panel=False,
        )

    incident_id = st.session_state.get("active_incident_id")
    if incident_id:
        from incident_scenarios import get_active_incident

        incident = get_active_incident()
        incident_title = (incident or {}).get("title", f"Incident {incident_id}")
        st.markdown("**This incident**")
        render_incident_session_tiles(
            int(incident_id),
            incident_title=incident_title,
            key_prefix="expert_history_incident",
            open_side_panel=False,
        )
    elif st.session_state.get("expert_incident_id"):
        detail_incident_id = int(st.session_state.expert_incident_id)
        try:
            incident_row = db.get_incident_by_id(detail_incident_id)
        except Exception:
            incident_row = None
        if incident_row:
            st.markdown("**This incident**")
            render_incident_session_tiles(
                detail_incident_id,
                incident_title=incident_row.get("title", f"Incident {detail_incident_id}"),
                key_prefix="expert_history_detail_incident",
                open_side_panel=False,
            )


def render_expert_drawer_history():
    """Collapsible side wing — full-height history panel left of the analyst drawer."""
    wing_open = bool(st.session_state.get("expert_drawer_history_expanded"))
    wing_state = "is-open" if wing_open else "is-collapsed"
    st.markdown(
        f'<div class="expert-drawer-history-wing {wing_state}"></div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="expert-drawer-history-strip-marker"></div>', unsafe_allow_html=True)
    strip_label = "‹" if wing_open else "›"
    if st.button(
        strip_label,
        key="expert_history_wing_toggle",
        help="Show or hide chat history",
    ):
        st.session_state.expert_drawer_history_expanded = not wing_open
        st.rerun()

    if wing_open:
        with st.container(border=False):
            st.markdown('<div class="expert-drawer-history-wing-panel"></div>', unsafe_allow_html=True)
            st.markdown(
                '<h3 class="standard-section-title standard-section-title--compact expert-drawer-history-title">History</h3>',
                unsafe_allow_html=True,
            )
            _render_expert_drawer_history_content()
