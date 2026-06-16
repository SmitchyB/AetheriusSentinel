"""
Expert dashboard CSS loader and legacy re-export.

Purpose
-------
This module's **active** responsibility is loading Expert-mode CSS after the
``expert-mode-root`` marker is injected in ``app.py``. The deprecated
``render_expert_dashboard()`` simply forwards to ``expert_router.render_expert_mode``.

Navigation / call graph
-----------------------
``app.py`` (when ``expert_mode``) → ``load_expert_css()`` before body render.
Legacy callers may still invoke ``render_expert_dashboard()`` → router.

Session state
-------------
- None read or written here.

Streamlit widget keys
---------------------
- None.

CSS marker divs
---------------
- Expects ``div.expert-mode-root`` to already exist in the DOM (injected by
  ``app.py``). ``Assets/expert.css`` scopes dark SOC theme rules under that root.

db.py / ai_service.py
---------------------
- **Neither.**
"""

from pathlib import Path

import streamlit as st


def load_expert_css():
    """
    Inject Expert-mode stylesheet (dark SOC theme) after ``expert-mode-root`` marker.

    Tries ``Assets/expert.css`` then ``assets/expert.css`` for cross-platform paths.
    Injects via ``st.markdown("<style>...</style>")`` — standard Streamlit pattern.
    """
    for css_path in (Path("Assets/expert.css"), Path("assets/expert.css")):
        if css_path.exists():
            st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)
            return


def render_expert_dashboard():
    """
    Deprecated: use ``components.expert_router.render_expert_mode`` instead.

    Kept for backward compatibility with older import paths.
    """
    from components.expert_router import render_expert_mode

    render_expert_mode()
