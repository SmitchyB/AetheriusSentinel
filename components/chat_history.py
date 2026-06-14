"""
Chat history sidebar — resume past analyst sessions from chat_messages table.

Renders clickable session tiles; selecting one calls chat_sessions.load_chat_session().
"""

import streamlit as st

import db

# Max characters shown on history tile title before ellipsis truncation.
_HISTORY_TITLE_MAX = 22


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


def render_session_tiles(
    sessions: list[dict],
    *,
    key_prefix: str,
    active_session_id: str | None = None,
    open_side_panel: bool = False,
    title_field: str = "incident_title",
    date_field: str = "last_activity",
):
    """
    Render clickable history tiles as styled Streamlit buttons.

    Args:
        sessions: List of dicts with session_id, title, and activity fields.
        key_prefix: Unique prefix for button keys (avoids collisions across panels).
        active_session_id: Highlight the currently loaded session.
        open_side_panel: If True, open Expert chat drawer after load.
        title_field: Dict key for tile primary label.
        date_field: Dict key for tile secondary timestamp.
    """
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
            st.rerun()

    return True


def render_chat_history():
    """
    Standard mode left column — recent sessions from get_session_history(limit=20).

    Includes optional spacer div when an active incident header is shown in chat.
    """
    st.markdown('<div class="standard-panel-card standard-history-panel"></div>', unsafe_allow_html=True)
    st.markdown(
        '<h3 class="standard-section-title standard-section-title--compact">Chat History</h3>',
        unsafe_allow_html=True,
    )

    from incident_scenarios import get_active_incident

    # Spacer aligns history scroll top with chat incident header (sized by layout JS).
    if get_active_incident():
        st.markdown('<div class="standard-history-incident-spacer"></div>', unsafe_allow_html=True)

    if not db.DB_PATH.exists():
        st.error(
            f"Database not found at `{db.DB_PATH}`. "
            "Run `python seed.py` from the project root, then refresh."
        )
        return

    try:
        sessions = db.get_session_history(limit=20)
    except Exception as error:
        st.error("Could not load chat history.")
        st.exception(error)
        return

    active_session = st.session_state.get("active_session_id")

    with st.container(border=False):
        st.markdown('<div class="standard-history-scroll-box"></div>', unsafe_allow_html=True)
        if not sessions:
            st.caption("No conversations yet.")
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
    """
    History tiles filtered to one incident (Expert incident detail panel).

    Uses get_sessions_for_incident() instead of global session history.
    """
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
