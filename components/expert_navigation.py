"""
Expert mode navigation helpers — overview vs incident detail routing.

Purpose
-------
Expert mode uses a **separate navigation stack** from Standard mode's incident
chat flow (``active_incident_id``). These helpers set ``expert_view`` and
``expert_incident_id`` so ``expert_router.render_expert_mode()`` knows whether
to show the SOC overview dashboard or a single incident detail page.

Navigation flow
---------------
1. Default: ``expert_view == "overview"`` → ``expert_overview.render_expert_overview()``.
2. User selects row in incidents table OR clicks alert in notifications panel
   → ``navigate_to_incident_detail(incident_id)`` → ``expert_view == "incident_detail"``
   → ``expert_incident_detail.render_expert_incident_detail()``.
3. User clicks "← Back to Dashboard" on detail page
   → ``navigate_to_overview()`` → returns to overview (does not clear
   ``expert_incident_id`` explicitly but view switch hides detail).

Session state keys (owned here)
-------------------------------
- ``expert_view``: ``"overview"`` | ``"incident_detail"`` — router discriminator.
- ``expert_incident_id``: int | None — DB ``incidents.incident_id`` for detail view.
- ``notifications_open``: bool — closed when navigating to detail (avoids overlay
  obscuring the new page).

Streamlit widget keys
---------------------
- None in this module (navigation is triggered by buttons in other components).

CSS marker divs
---------------
- None (navigation is pure session state).

db.py / ai_service.py
---------------------
- **Neither.** Only mutates session state; callers load incident rows via ``db``.
"""

import streamlit as st


def init_expert_state():
    """
    Ensure expert navigation keys exist with safe defaults on first load.

    Called at the start of every ``render_expert_mode()`` rerun so missing keys
    after hot-reload or partial resets do not crash the router.

    Session state initialized:
        ``expert_view`` → ``"overview"``
        ``expert_incident_id`` → ``None``
        ``notifications_open`` → ``False``
    """
    if "expert_view" not in st.session_state:
        st.session_state.expert_view = "overview"
    if "expert_incident_id" not in st.session_state:
        st.session_state.expert_incident_id = None
    if "notifications_open" not in st.session_state:
        st.session_state.notifications_open = False


def navigate_to_incident_detail(incident_id: int):
    """
    Switch Expert view to full incident detail for the given DB incident_id.

    Args:
        incident_id: Primary key from ``incidents`` table.

    Session state written:
        ``expert_view`` = ``"incident_detail"``
        ``expert_incident_id`` = int(incident_id)
        ``notifications_open`` = False
    """
    st.session_state.expert_view = "incident_detail"
    st.session_state.expert_incident_id = int(incident_id)
    st.session_state.notifications_open = False


def navigate_to_overview():
    """
    Return to the Expert overview dashboard (KPIs, charts, incident table).

    Session state written:
        ``expert_view`` = ``"overview"``

    Note: Does not clear ``expert_incident_id``; detail page simply stops rendering.
    """
    st.session_state.expert_view = "overview"
