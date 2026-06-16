"""
Standard mode dashboard — homeowner layout with scans, history, chat, and incidents.

Purpose
-------
Composes the full Standard (homeowner) page when ``expert_mode`` is OFF.
Layout zones top-to-bottom: scans strip → chat row (history | Sentinel Chat) →
incidents table.

Navigation / call graph
-----------------------
``app.py`` (``expert_mode`` False) → ``render_standard_mode()``.

Session state
-------------
- ``process_pending_incident_chat_work()`` may set chat/incident keys and rerun.
- Child modules read ``messages``, ``active_session_id``, ``active_incident_id``, etc.

Streamlit widget keys
---------------------
- Defined in child modules (``scans``, ``chat_history``, ``sentinel_panel``, ``incidents_list``).

CSS marker divs
---------------
- ``standard-mode-root`` — duplicate root marker inside body (``app.py`` also injects one).
- ``standard-panel-card standard-scan-strip`` — scans bordered panel.
- ``standard-chat-row-wrapper`` — grid wrapper for history + chat columns.

db.py / ai_service.py
---------------------
- **No direct calls.** Delegated to ``chat_history``, ``incidents_list``;
  chat AI via ``sentinel_panel`` → ``handle_chat_prompt`` → ``ai_service`` (indirect).
"""

from pathlib import Path

import streamlit as st

from components.chat_history import render_chat_history
from components.incidents_list import render_incidents_list
from components.scans import render_scan_actions
from components.sentinel_panel import render_sentinel_chat_input, render_sentinel_panel

# Fixed incidents table height — tune with --standard-incidents-table-height in standard.css
STANDARD_INCIDENTS_TABLE_HEIGHT = 240


def load_standard_css():
    """
    Inject Standard-mode stylesheet (lighter homeowner theme).

    Called from ``app.py`` when Expert mode is off, after ``standard-mode-root`` marker.
    Tries ``Assets/standard.css`` then ``assets/standard.css``.
    """
    for css_path in (Path("Assets/standard.css"), Path("assets/standard.css")):
        if css_path.exists():
            st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)
            return


def render_standard_mode():
    """
    Compose the full Standard mode page.

    Layout:
        1. Scans strip (bordered panel).
        2. Chat block — 1:4 columns: Chat History | Sentinel Chat + input footer.
        3. Incidents table (fixed height ``STANDARD_INCIDENTS_TABLE_HEIGHT``).

    Child renderers:
        ``render_scan_actions``, ``render_chat_history``, ``render_sentinel_panel``,
        ``render_sentinel_chat_input``, ``render_incidents_list(mode="standard")``.

    Session: may rerun once for pending incident chat bootstrap.
    """
    from incident_scenarios import process_pending_incident_chat_work

    if process_pending_incident_chat_work():
        st.rerun()

    st.markdown('<div class="standard-mode-root"></div>', unsafe_allow_html=True)

    with st.container(border=True):
        st.markdown('<div class="standard-panel-card standard-scan-strip"></div>', unsafe_allow_html=True)
        render_scan_actions(show_label=True)

    st.markdown('<div class="standard-chat-row-wrapper"></div>', unsafe_allow_html=True)
    history_col, chat_col = st.columns([1, 4], gap="medium")

    with history_col:
        with st.container(border=True):
            render_chat_history()

    with chat_col:
        with st.container(border=True):
            render_sentinel_panel()
            render_sentinel_chat_input()

    with st.container(border=True):
        render_incidents_list(mode="standard", height=STANDARD_INCIDENTS_TABLE_HEIGHT)
