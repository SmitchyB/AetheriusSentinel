"""
Expert mode header toggle — switches between Standard and Expert dashboard layouts.

Purpose
-------
The primary mode switch for the entire application body. When ON, ``app.py``
injects ``expert-mode-root``, loads ``expert.css``, and calls
``expert_router.render_expert_mode()`` instead of ``standard_dashboard``.

Navigation / call graph
-----------------------
``app.py`` (header) → ``render_expert_mode_toggle()`` → return value drives:
  - Root CSS marker (``expert-mode-root`` vs ``standard-mode-root``)
  - Extra header column (hamburger analyst chat in Expert only)
  - Main body branch (Expert router vs Standard dashboard)

Session state
-------------
- ``expert_mode`` (bool): Widget key and session key; default ``False``.
- On toggle OFF: ``_on_expert_mode_change`` calls ``reset_expert_state()`` which
  clears Expert-only navigation (``expert_view``, ``expert_incident_id``, etc.).
- ``incidents_table_revision`` bumped on any change so dataframe selection keys
  reset (avoids stale Streamlit widget state).

Streamlit widget keys
---------------------
- ``expert_mode`` — ``st.toggle`` with ``on_change=_on_expert_mode_change``.

CSS marker divs
---------------
- ``expert-mode-toggle`` (+ ``is-on`` / ``is-off``): Decorative label shell,
  same pattern as ``auto_defense_toggle``.

db.py / ai_service.py
---------------------
- **Neither** at this layer. Mode is session-only until future persistence.
"""

import streamlit as st

from sentinel_actions import bump_incidents_table_revision, reset_expert_state


def _on_expert_mode_change():
    """
    Streamlit ``on_change`` callback when user toggles Expert mode.

    Side effects:
        - Bumps ``incidents_table_revision`` (invalidates dataframe widget keys).
        - If turning Expert OFF, calls ``reset_expert_state()`` to drop
          ``expert_view``, ``expert_incident_id``, and related Expert keys.
    """
    bump_incidents_table_revision()
    if not st.session_state.expert_mode:
        reset_expert_state()


def render_expert_mode_toggle() -> bool:
    """
    Render the styled Expert Mode toggle in the header toolbar.

    Returns:
        True if Expert mode is active (drives ``app.py`` body branch).

    Session state:
        Reads/writes ``expert_mode``.

    Widget key:
        ``expert_mode`` — collapsed toggle with ``on_change`` callback.

    CSS markers:
        ``div.expert-mode-toggle`` with ``is-on`` or ``is-off``.
    """
    if "expert_mode" not in st.session_state:
        st.session_state.expert_mode = False

    is_on = bool(st.session_state.expert_mode)
    state_class = "is-on" if is_on else "is-off"

    st.markdown(
        f"""
        <div class="expert-mode-toggle {state_class}" data-testid="expert-mode-toggle-shell">
            <span class="expert-mode-toggle__label">Expert Mode</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.toggle(
        "Expert Mode",
        key="expert_mode",
        label_visibility="collapsed",
        on_change=_on_expert_mode_change,
    )
    return bool(st.session_state.expert_mode)
