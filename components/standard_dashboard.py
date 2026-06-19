"""Standard mode dashboard — homeowner layout with scans, history, chat, and incidents."""

from pathlib import Path

import streamlit as st

from components.chat_history import render_chat_history
from components.incidents_list import render_incidents_list
from components.scans import render_scan_actions
from components.sentinel_panel import render_sentinel_chat_input, render_sentinel_panel

# Fixed incidents table height — tune with --standard-incidents-table-height in standard.css
STANDARD_INCIDENTS_TABLE_HEIGHT = 240


def load_standard_css():
    """Inject Standard-mode stylesheet (lighter homeowner theme)."""
    for css_path in (Path("Assets/standard.css"), Path("assets/standard.css")):
        if css_path.exists():
            st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)
            return


# ---------------------------------------------------------------------------
# Standard layout — scan strip, chat row, incidents table
# ---------------------------------------------------------------------------

def render_standard_mode():
    """Compose the full Standard mode page."""
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
