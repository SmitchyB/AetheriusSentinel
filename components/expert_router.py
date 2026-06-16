"""
Expert mode view router — switches between overview dashboard and incident detail.

Purpose
-------
Single entry point for Expert mode body content, called from ``app.py`` when
``expert_mode`` toggle is ON. Delegates to overview or detail based on
``st.session_state.expert_view``.

Navigation flow
---------------
::
    app.py (expert_mode=True)
      → render_expert_mode()
          → init_expert_state()
          → process_pending_incident_chat_work()  # deferred chat opens
          → if expert_view == "incident_detail":
                expert_incident_detail.render_expert_incident_detail()
            else:
                expert_overview.render_expert_overview()

Parallel paths into detail view
-------------------------------
- ``incidents_list`` row select (Expert mode) → ``navigate_to_incident_detail``
- ``expert_notifications`` alert click → same
- ``expert_incident_detail`` back button → ``navigate_to_overview``

Session state dependencies
--------------------------
- ``expert_view``, ``expert_incident_id`` — routing (see ``expert_navigation``).
- Pending chat work from ``incident_scenarios.process_pending_incident_chat_work``
  may trigger ``st.rerun()`` before view render.

Streamlit widget keys
---------------------
- None in this module (router only).

CSS marker divs
----------------
- Child views inject their own markers (``expert-incident-detail-root``, KPI cards, etc.).

db.py / ai_service.py
---------------------
- **Neither** directly. Child views call ``db``; chat/AI via ``incident_scenarios``.
"""

import streamlit as st

from components.expert_incident_detail import render_expert_incident_detail
from components.expert_navigation import init_expert_state
from components.expert_overview import render_expert_overview


def render_expert_mode():
    """
    Render the active Expert mode screen based on ``expert_view`` session key.

    Called from ``app.py`` when the Expert mode toggle is on.

    Flow:
        1. Initialize expert navigation session keys.
        2. Flush any deferred incident-chat open requests (playbook/chat bootstrap).
        3. Branch on ``expert_view`` to detail or overview renderer.

    Session state read:
        ``expert_view``, ``expert_incident_id`` (indirectly via detail module).

    db.py / ai_service.py:
        No direct calls; delegated to child render functions.
    """
    from incident_scenarios import process_pending_incident_chat_work

    init_expert_state()

    if process_pending_incident_chat_work():
        st.rerun()

    if st.session_state.expert_view == "incident_detail":
        render_expert_incident_detail()
    else:
        render_expert_overview()
