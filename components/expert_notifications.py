"""Header alerts bell and open-incidents notification dropdown."""

import streamlit as st

import db
import incident_scenarios
from components.expert_navigation import navigate_to_incident_detail


# ---------------------------------------------------------------------------
# Header bell — badge counts for new alerts and pending incident updates
# ---------------------------------------------------------------------------

def render_expert_notification_bell():
    """Header bell button with new-alert and pending-update counts."""
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


# ---------------------------------------------------------------------------
# Notifications overlay — open incidents and pending update routing
# ---------------------------------------------------------------------------

def render_expert_notifications_panel():
    """Fixed overlay panel anchored to the header alerts button."""
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
