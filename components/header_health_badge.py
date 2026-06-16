"""
Header system health badge — summarizes open incident severities from the DB.

Purpose
-------
Renders the leftmost item in the global header toolbar: a pill showing
"System" + status label (Operational, Stable, Elevated, Degraded, Critical).
Status is **fully DB-backed** via ``db.get_system_status()``, which derives the
worst severity among open incidents.

Navigation / call graph
-----------------------
``app.py`` → ``render_header_health_badge()`` in ``health_col`` (both modes).

Session state
-------------
- None read or written.

Streamlit widget keys
---------------------
- None (pure HTML badge via ``st.markdown``).

CSS marker divs
---------------
- ``sentinel-header-health-slot`` — positions badge in toolbar grid.
- ``sentinel-health-badge`` + ``sentinel-health-badge--{tone}`` — color by status
  (operational, stable, elevated, degraded, critical, unknown).

db.py
-----
- ``db.DB_PATH.exists()`` — gate before query.
- ``db.get_system_status()`` — returns human-readable status string.

ai_service.py
-------------
- **Not used.**
"""

import streamlit as st

import db


def render_header_health_badge():
    """
    Render DB-backed system health badge for the header toolbar.

    Falls back to "Unknown" if the database file is missing or the query fails.

    db.py calls:
        ``get_system_status()`` when ``DB_PATH`` exists.

    CSS markers:
        ``sentinel-header-health-slot``, ``sentinel-health-badge--{tone}``.
    """
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
