"""
Expert dashboard CSS loader and legacy re-export.

render_expert_dashboard() is deprecated — app.py uses expert_router.render_expert_mode().
"""

from pathlib import Path

import streamlit as st


def load_expert_css():
    """Inject Expert-mode stylesheet (dark SOC theme) after expert-mode-root marker."""
    for css_path in (Path("Assets/expert.css"), Path("assets/expert.css")):
        if css_path.exists():
            st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)
            return


def render_expert_dashboard():
    """Deprecated: use components.expert_router.render_expert_mode instead."""
    from components.expert_router import render_expert_mode

    render_expert_mode()
