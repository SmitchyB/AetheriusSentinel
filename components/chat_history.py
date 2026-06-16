"""
Chat history sidebar — resume past analyst sessions from chat_messages table.

Purpose
-------
Renders clickable session tiles for general (non-incident) chats and
incident-scoped chats. Used in Standard mode left column and Expert drawer
history wing. Selecting a tile calls ``chat_sessions.load_chat_session()`` which
reads messages from SQLite via ``db``.

Navigation / call graph
-----------------------
- ``standard_dashboard`` → ``render_chat_history()`` (Standard left column).
- ``expert_chat_drawer`` → ``render_expert_drawer_history()`` (collapsible wing).

Session state dependencies
----------------------------
- ``active_session_id`` — highlights active tile; read for button type primary/secondary.
- ``side_panel_open`` — set True when ``open_side_panel=True`` on tile click.
- ``expert_drawer_history_expanded`` — wing open/closed; toggled by strip button.
- ``active_incident_id`` — filters "This incident" section in drawer.
- ``expert_incident_id`` — detail-page incident for drawer history when no active chat.

Streamlit widget keys
---------------------
- ``{key_prefix}_{index}_{session_id[:8]}`` — per session tile (prefix varies).
- ``expert_history_wing_toggle`` — ‹/› collapse strip in Expert drawer.

CSS marker divs
---------------
- ``standard-panel-card standard-history-panel standard-chat-row`` — Standard panel.
- ``standard-history-scroll-box`` — internal scroll region hook.
- ``expert-drawer-history-wing`` (+ ``is-open`` / ``is-collapsed``) — wing state.
- ``expert-drawer-history-strip-marker`` — toggle strip anchor.
- ``expert-drawer-history-wing-panel`` — expanded wing content.
- ``expert-drawer-history-scroll`` — drawer scroll box.

db.py
-----
- ``DB_PATH.exists()`` — error gate.
- ``get_general_session_history(limit=20)`` — general chat tiles.
- ``get_sessions_for_incident(incident_id)`` — incident-scoped tiles.
- ``get_incident_by_id(detail_incident_id)`` — title for detail-page history section.

ai_service.py
-------------
- **Not used** (history is DB-backed; AI runs only after session load + new prompt).
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
        active_session_id: Highlight the currently loaded session (primary button).
        open_side_panel: If True, set ``side_panel_open`` after load (Expert drawer).
        title_field: Dict key for tile primary label.
        date_field: Dict key for tile secondary timestamp.

    Widget keys:
        ``{key_prefix}_{index}_{session_id[:8]}``.

    On click:
        ``chat_sessions.load_chat_session(session_id)`` → db message load;
        optionally opens side panel; clears ``expert_drawer_history_expanded``.
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
            st.session_state.expert_drawer_history_expanded = False
            st.rerun()

    return True


def render_chat_history():
    """
    Standard mode left column — recent general (non-incident) chat sessions.

    db.py: ``get_general_session_history(limit=20)``.

    CSS: ``standard-history-panel``, ``standard-history-scroll-box``.

    Widget key prefix: ``history_card``.
    """
    st.markdown(
        '<div class="standard-panel-card standard-history-panel standard-chat-row"></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<h3 class="standard-section-title standard-section-title--compact">General Conversations</h3>',
        unsafe_allow_html=True,
    )

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
    """
    History tiles filtered to one incident (Expert incident detail / drawer).

    Uses ``get_sessions_for_incident()`` instead of global session history.

    db.py: ``get_sessions_for_incident(incident_id)``.
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


def _render_expert_drawer_history_content():
    """
    Session lists rendered inside the Expert drawer history wing (General + This incident).

    db.py: ``get_general_session_history``, ``get_sessions_for_incident``, ``get_incident_by_id``.
    """
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
    """
    Collapsible side wing — full-height history panel left of the analyst drawer.

    Widget key: ``expert_history_wing_toggle`` (‹/› strip).

    Session: ``expert_drawer_history_expanded`` toggled on strip click.

    CSS: ``expert-drawer-history-wing``, ``expert-drawer-history-strip-marker``,
    ``expert-drawer-history-wing-panel``.
    """
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
