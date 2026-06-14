"""
Aetherius Sentinel — Streamlit application entry point.

This file is intentionally thin: it wires together the header toolbar, mode-specific
CSS, and either Standard mode (homeowner UI) or Expert mode (SOC dashboard).
All database queries live in db.py; UI panels live under components/.

Run with: streamlit run app.py
"""

import importlib
import sys
from pathlib import Path

# Ensure project root is on sys.path so imports work regardless of cwd.
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Core modules (business logic + DB layer).
import action_catalog
import chat_sessions
import db
import incident_scenarios
import sentinel_actions

# Hot-reload during development so edits to these modules apply without restarting Streamlit.
# action_catalog must reload before incident_scenarios (it imports new symbols from the catalog).
for _module in (action_catalog, db, incident_scenarios, chat_sessions, sentinel_actions):
    importlib.reload(_module)

import streamlit as st

# UI component modules — each renders one panel or feature area.
import components.chat_history as chat_history
import components.expert_charts as expert_charts
import components.expert_chat_drawer as expert_chat_drawer
import components.expert_dashboard as expert_dashboard
import components.expert_incident_detail as expert_incident_detail
import components.expert_incidents_list as expert_incidents_list
import components.expert_navigation as expert_navigation
import components.expert_notifications as expert_notifications
import components.expert_overview as expert_overview
import components.expert_router as expert_router
import components.expert_security_ticker as expert_security_ticker
import components.expert_theme as expert_theme
import components.auto_defense_toggle as auto_defense_toggle
import components.expert_mode_toggle as expert_mode_toggle
import components.scans as scans
import components.sentinel_panel as sentinel_panel
import components.standard_dashboard as standard_dashboard
import components.standard_layout_sizer as standard_layout_sizer

for _module in (
    chat_history,
    expert_charts,
    expert_chat_drawer,
    expert_dashboard,
    expert_incident_detail,
    expert_incidents_list,
    expert_navigation,
    expert_notifications,
    expert_overview,
    expert_router,
    expert_security_ticker,
    expert_theme,
    auto_defense_toggle,
    expert_mode_toggle,
    scans,
    sentinel_panel,
    standard_layout_sizer,
    standard_dashboard,
):
    importlib.reload(_module)

from incident_scenarios import init_incident_state, open_incident_chat  # noqa: F401 — re-export for compatibility
from sentinel_actions import init_session_state
from components.expert_chat_drawer import open_expert_chat_drawer_if_needed
from components.expert_dashboard import load_expert_css
from components.expert_notifications import (
    render_expert_notification_bell,
    render_expert_notifications_panel,
)
from components.expert_router import render_expert_mode
from components.auto_defense_toggle import render_auto_defense_toggle
from components.expert_mode_toggle import render_expert_mode_toggle
from components.standard_dashboard import load_standard_css, render_standard_mode
from components.header_health_badge import render_header_health_badge

# Wide layout fits the dual-column Standard chat row and Expert dashboard grids.
st.set_page_config(page_title="Aetherius Sentinel", layout="wide")


def load_app_css():
    """Inject global stylesheet shared by both Standard and Expert modes."""
    # Try capital-A Assets first (Windows), then lowercase assets.
    for css_path in (Path("Assets/app.css"), Path("assets/app.css")):
        if css_path.exists():
            st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)
            return


# --- Bootstrap: CSS + session state before any widgets render ---
load_app_css()

init_session_state()   # Chat messages, expert toggles, panel open flags
init_incident_state()  # Playbook phase, active incident mirror, scan rotation

# --- Header row: title (left) and toolbar controls (right) ---
header_left, header_right = st.columns([0.22, 0.78], vertical_alignment="center")
with header_left:
    st.markdown(
        '<h1 class="sentinel-app-title">Aetherius Sentinel</h1>',
        unsafe_allow_html=True,
    )
with header_right:
    # Empty shell div — CSS positions the real Streamlit widgets over this slot.
    st.markdown('<div class="sentinel-header-toolbar"></div>', unsafe_allow_html=True)
    # Expert mode is read from session state so the toolbar column count is stable
    # before widgets render. The hamburger is the only header difference in Expert mode.
    toolbar_expert_mode = bool(st.session_state.get("expert_mode", False))
    if toolbar_expert_mode:
        health_col, expert_col, defense_col, alerts_col, analyst_col = st.columns(
            [0.95, 1, 1, 0.72, 0.38],
            gap="small",
            vertical_alignment="center",
        )
    else:
        health_col, expert_col, defense_col, alerts_col = st.columns(
            [0.95, 1, 1, 0.72],
            gap="small",
            vertical_alignment="center",
        )
    with health_col:
        render_header_health_badge()  # DB-backed Operational / Critical / etc.
    with expert_col:
        expert_mode = render_expert_mode_toggle()  # Switches entire body layout
    with defense_col:
        render_auto_defense_toggle()  # UI-only for now; no policy engine wired
    with alerts_col:
        render_expert_notification_bell()  # Open incident count badge (both modes)
    if toolbar_expert_mode:
        with analyst_col:
            st.markdown(
                '<div class="standard-btn-marker sentinel-btn--header-analyst"></div>',
                unsafe_allow_html=True,
            )
            if st.button(
                "☰",
                key="expert_analyst_chat_toggle",
                help="Open Sentinel Analyst panel",
            ):
                st.session_state.side_panel_open = not st.session_state.side_panel_open
                st.rerun()

# --- Mode-specific root marker + CSS (drives theming via injected selectors) ---
if expert_mode:
    st.markdown('<div class="expert-mode-root"></div>', unsafe_allow_html=True)
    load_expert_css()
else:
    st.markdown('<div class="standard-mode-root"></div>', unsafe_allow_html=True)
    load_standard_css()

st.divider()

# Notifications dropdown renders below header when bell is toggled (both modes).
render_expert_notifications_panel()

# --- Main body: Expert SOC dashboard vs Standard homeowner layout ---
if expert_mode:
    render_expert_mode()
    open_expert_chat_drawer_if_needed()  # @st.dialog when side_panel_open
else:
    render_standard_mode()
