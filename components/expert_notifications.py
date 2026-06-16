"""
Header alerts bell and open-incidents notification dropdown.

Purpose
-------
Renders the global "Alerts" bell in the header (both Standard and Expert modes)
and the fixed overlay panel listing new open incidents and pending incident updates.
Clicking an item routes differently by mode: Expert → incident detail page;
Standard → ``incident_scenarios.open_incident_chat`` or ``open_incident_update``.

Navigation / call graph
-----------------------
``app.py`` header → ``render_expert_notification_bell()``.
``app.py`` below divider → ``render_expert_notifications_panel()`` when open.

Session state
-------------
- ``notifications_open`` (bool): Toggled by bell; closed on item click or ✕.
- ``notifications_revision`` (read-only bump): Forces bell badge refresh on reruns.
- ``expert_mode`` — routes alert clicks to detail vs chat.

Streamlit widget keys
---------------------
- ``expert_notification_bell`` — header bell toggle.
- ``expert_close_notifications`` — panel close ✕.
- ``expert_notify_{incident_id}`` — one per open incident row.
- ``expert_update_{update_id}`` — one per pending update row.

CSS marker divs
---------------
- ``standard-btn-marker sentinel-btn--header-alerts`` — bell button anchor.
- ``standard-panel-card sentinel-notifications-overlay`` + mode suffix
  (``expert-notifications-panel`` | ``standard-notifications-panel``).
- ``sentinel-notifications-scroll`` — scrollable list region.
- ``sentinel-alert--update`` — visual accent before update rows.

db.py
-----
- ``get_open_incident_count()``, ``get_pending_update_count()`` — badge counts.
- ``get_open_incidents()``, ``get_pending_incident_updates()`` — panel lists.
- ``DB_PATH.exists()`` — missing-db warning.

ai_service.py
-------------
- **Not used.**
"""

import streamlit as st

import db
import incident_scenarios
from components.expert_navigation import navigate_to_incident_detail


def render_expert_notification_bell():
    """
    Header bell button with new-alert and pending-update counts.

    Toggles ``notifications_open`` session flag (panel rendered in ``app.py``
    below the header divider).

    Widget key: ``expert_notification_bell``.

    db.py: ``get_open_incident_count()``, ``get_pending_update_count()``.

    CSS: ``sentinel-btn--header-alerts`` marker before button.
    """
    _ = st.session_state.get("notifications_revision", 0)
    try:
        new_count = db.get_open_incident_count()
        update_count = db.get_pending_update_count()
        count = new_count + update_count
    except Exception:
        new_count = 0
        update_count = 0
        count = 0

    badge = f" ({count})" if count else ""
    label = f"Alerts{badge}"
    st.markdown(
        '<div class="standard-btn-marker sentinel-btn--header-alerts"></div>',
        unsafe_allow_html=True,
    )
    if st.button(
        label,
        key="expert_notification_bell",
        help="Open incident notifications",
    ):
        st.session_state.notifications_open = not st.session_state.get("notifications_open", False)
        st.rerun()


def _compact_incident_label(title: str, severity: str, device: str, max_len: int = 42) -> str:
    """Single-line label for the compact overlay list (truncated with ellipsis)."""
    label = f"{title} — {severity} — {device}"
    if len(label) <= max_len:
        return label
    return f"{label[: max_len - 1]}…"


def _compact_update_label(title: str, max_len: int = 46) -> str:
    """Single-line label for pending incident update rows."""
    label = f"↻ {title}"
    if len(label) <= max_len:
        return label
    return f"{label[: max_len - 1]}…"


def render_expert_notifications_panel():
    """
    Fixed overlay panel anchored to the header alerts button.

    Lists new Active incidents and pending incident updates in separate sections.
    Early-returns when ``notifications_open`` is False.

    Navigation on click:
        Expert + new alert → ``navigate_to_incident_detail``.
        Standard + new alert → ``open_incident_chat``.
        Update row → detail (Expert) + ``open_incident_update`` (both modes).

    Widget keys: ``expert_close_notifications``, ``expert_notify_*``, ``expert_update_*``.

    db.py: ``get_open_incidents()``, ``get_pending_incident_updates()``.
    """
    if not st.session_state.get("notifications_open"):
        return

    is_expert = bool(st.session_state.get("expert_mode"))
    panel_marker = (
        "expert-notifications-panel"
        if is_expert
        else "standard-notifications-panel"
    )

    with st.container(border=True):
        st.markdown(
            (
                f'<div class="standard-panel-card sentinel-notifications-overlay '
                f'{panel_marker}"></div>'
            ),
            unsafe_allow_html=True,
        )
        header_col, close_col = st.columns([5, 1])
        with header_col:
            try:
                new_count = db.get_open_incident_count()
                update_count = db.get_pending_update_count()
            except Exception:
                new_count = 0
                update_count = 0
            st.markdown(f"**Alerts** — New: {new_count} | Updates: {update_count}")
        with close_col:
            if st.button("✕", key="expert_close_notifications", help="Close notifications"):
                st.session_state.notifications_open = False
                st.rerun()

        if not db.DB_PATH.exists():
            st.warning("Database not found. Run `python seed.py` to load incidents.")
            return

        try:
            open_incidents = db.get_open_incidents()
            pending_updates = db.get_pending_incident_updates()
        except Exception as error:
            st.error("Could not load notifications.")
            st.exception(error)
            return

        if not open_incidents and not pending_updates:
            st.info("No open alerts — incidents under investigation are tracked on the dashboard.")
            return

        st.markdown('<div class="sentinel-notifications-scroll"></div>', unsafe_allow_html=True)

        if open_incidents:
            st.markdown("**New alerts**")
            for row in open_incidents:
                incident_id = row["incident_id"]
                title = row["title"]
                severity = row["severity"]
                device = row.get("device_name", "Unknown")
                if st.button(
                    _compact_incident_label(title, severity, device),
                    key=f"expert_notify_{incident_id}",
                    use_container_width=True,
                ):
                    st.session_state.notifications_open = False
                    if is_expert:
                        navigate_to_incident_detail(incident_id)
                    else:
                        incident_scenarios.open_incident_chat(incident_id)
                    st.rerun()

        if pending_updates:
            if open_incidents:
                st.divider()
            st.markdown("**Incident updates**")
            for row in pending_updates:
                update_id = row["update_id"]
                incident_id = row["incident_id"]
                title = row.get("title", row.get("incident_title", "Incident update"))
                st.markdown(
                    '<div class="sentinel-alert--update"></div>',
                    unsafe_allow_html=True,
                )
                if st.button(
                    _compact_update_label(title),
                    key=f"expert_update_{update_id}",
                    use_container_width=True,
                ):
                    st.session_state.notifications_open = False
                    if is_expert:
                        navigate_to_incident_detail(incident_id)
                    incident_scenarios.open_incident_update(incident_id, update_id)
                    st.rerun()
