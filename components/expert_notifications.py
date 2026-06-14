"""
Header alerts bell and open-incidents notification dropdown.

Works in both Standard and Expert mode; click routes to chat or incident detail.
"""

import streamlit as st

import db
import incident_scenarios
from components.expert_navigation import navigate_to_incident_detail


def render_expert_notification_bell():
    """
    Header bell button with open-incident count badge from get_open_incident_count().

    Toggles notifications_open session flag (panel rendered in app.py below divider).
    """
    try:
        count = db.get_open_incident_count()
    except Exception:
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


def render_expert_notifications_panel():
    """
    Dropdown-style panel below header when notifications_open is True.

    Lists open incidents from get_open_incidents(); click opens detail (Expert)
    or starts chat (Standard).
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
            f'<div class="standard-panel-card {panel_marker}"></div>',
            unsafe_allow_html=True,
        )
        header_col, close_col = st.columns([5, 1])
        with header_col:
            st.markdown("**Open Incidents**")
        with close_col:
            if st.button("✕", key="expert_close_notifications", help="Close notifications"):
                st.session_state.notifications_open = False
                st.rerun()

        if not db.DB_PATH.exists():
            st.warning("Database not found. Run `python seed.py` to load incidents.")
            return

        try:
            open_incidents = db.get_open_incidents()
        except Exception as error:
            st.error("Could not load open incidents.")
            st.exception(error)
            return

        if not open_incidents:
            st.info("No open incidents.")
            return

        for row in open_incidents:
            incident_id = row["incident_id"]
            title = row["title"]
            severity = row["severity"]
            device = row.get("device_name", "Unknown")
            if st.button(
                f"{title} — {severity} — {device}",
                key=f"expert_notify_{incident_id}",
                use_container_width=True,
            ):
                st.session_state.notifications_open = False
                if is_expert:
                    navigate_to_incident_detail(incident_id)
                else:
                    incident_scenarios.open_incident_chat(incident_id)
                st.rerun()
