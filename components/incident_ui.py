"""
Legacy incident alert banners — optional pipeline-style incident cards.

Purpose
-------
Renders severity-colored alert banners for active or open incidents. Used when
embedding ``incident_ui`` in older layouts; **Standard/Expert main flows** use
the incidents table and detail views instead. Not called from current ``app.py``.

Session state dependencies
--------------------------
- Prefers ``incident_scenarios.get_active_incident()`` (live chat session mirror).
- Falls back to ``db.get_open_incidents()`` when no active session.

Streamlit widget keys
---------------------
- None (uses ``st.error`` / ``st.warning`` / ``st.info`` native alerts).

CSS marker divs
---------------
- ``incident-alert-card`` — hook before each banner (``pipeline.css`` if loaded).

db.py
-----
- ``DB_PATH.exists()``, ``get_open_incidents()`` — fallback list when no session.

ai_service.py
-------------
- **Not used.**
"""

from pathlib import Path

import streamlit as st

import db
import incident_scenarios


def load_pipeline_css():
    """
    Load optional ``assets/pipeline.css`` for legacy incident alert styling.

    Injected via ``st.markdown("<style>...")`` when file exists.
    """
    css_path = Path("assets/pipeline.css")
    if css_path.exists():
        st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)


def render_incident_alert():
    """
    Show incident banner(s) from live session or, if none, all open DB incidents.

    Prefers ``st.session_state`` active incident mirror when a scan/chat session
    is active; otherwise iterates ``db.get_open_incidents()``.

    db.py: ``get_open_incidents()`` when no live session.
    """
    incident = incident_scenarios.get_active_incident()
    if incident:
        _render_incident_banner(incident, source_label="Live session")
        return

    if not db.DB_PATH.exists():
        st.warning(
            f"Database not found at `{db.DB_PATH}`. "
            "Run `python seed.py`, then refresh to load open incidents."
        )
        return

    try:
        open_incidents = db.get_open_incidents()
    except Exception as error:
        st.error("Could not load open incidents from the database.")
        st.exception(error)
        return

    if not open_incidents:
        st.info("No open incidents in the database. Run a scan to simulate a new threat.")
        return

    st.caption("Showing open incidents from the database (no live session active).")
    for row in open_incidents:
        incident = incident_scenarios.build_active_incident_from_db(row)
        _render_incident_banner(incident, source_label="Database")


def _render_incident_banner(incident: dict, source_label: str):
    """
    Render one severity-colored alert box for an incident dict.

    Args:
        incident: Enriched incident dict (title, subtitle, description, severity, etc.).
        source_label: "Live session" or "Database" for caption provenance.

    CSS: ``incident-alert-card`` marker before Streamlit alert component.
    """
    severity = incident["severity"]
    tone = incident_scenarios.SEVERITY_COLORS.get(severity, "info")
    st.markdown('<div class="incident-alert-card"></div>', unsafe_allow_html=True)

    # Streamlit native alert components by severity tier.
    if tone == "critical":
        st.error(
            f"**{incident['title']}** — {incident['subtitle']}  \n"
            f"{incident['description']}"
        )
    elif tone == "high":
        st.warning(
            f"**{incident['title']}** — {incident['subtitle']}  \n"
            f"{incident['description']}"
        )
    else:
        st.info(
            f"**{incident['title']}** — {incident['subtitle']}  \n"
            f"{incident['description']}"
        )

    caption = (
        f"Severity: **{incident['severity']}** | Source: **{incident['source']}** | "
        f"Indicator: `{incident['indicator']}`"
    )
    if incident.get("source_mac"):
        caption += f" | MAC: `{incident['source_mac']}`"
    caption += f" | Data: _{source_label}_"
    st.caption(caption)
