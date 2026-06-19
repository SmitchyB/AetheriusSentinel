"""Header system health badge — summarizes open incident severities from the DB."""

import streamlit as st

import db


def render_header_health_badge():
    """Render DB-backed system health badge for the header toolbar."""
    status = "Unknown"
    tone = "unknown"

    if db.DB_PATH.exists():
        try:
            # Derived from worst open incident severity — see db.get_system_status().
            status = db.get_system_status()
        except Exception:
            status = "Unknown"

    # CSS class suffix controls badge color in app.css.
    tone_map = {
        "Operational": "operational",
        "Stable": "stable",
        "Elevated": "elevated",
        "Degraded": "degraded",
        "Critical": "critical",
    }
    tone = tone_map.get(status, "unknown")

    st.markdown(
        f"""
        <div class="sentinel-header-health-slot">
            <span class="sentinel-health-badge sentinel-health-badge--{tone}">
                <span class="sentinel-health-badge__label">System</span>
                <span class="sentinel-health-badge__value">{status}</span>
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )
