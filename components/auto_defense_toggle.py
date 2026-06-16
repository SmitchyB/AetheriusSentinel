"""
Auto Defense header toggle — visual placeholder for a future policy engine.

Purpose
-------
Renders the "Auto Defense" switch in the global header toolbar (``app.py``,
``header_right`` column). When a real policy engine exists, this toggle would
enable automated containment (block, isolate, etc.) without manual analyst ack.
**Today it is UI-only:** the value lives in ``st.session_state.auto_defense``
and is never persisted to SQLite or sent to any API.

Navigation / call graph
-----------------------
``app.py`` → ``render_auto_defense_toggle()`` (both Standard and Expert modes).

Session state
-------------
- ``auto_defense`` (bool): Initialized to ``False`` on first render if missing.
  Bound to the Streamlit toggle widget via ``key="auto_defense"`` (widget and
  session key are the same — Streamlit syncs them automatically).

Streamlit widget keys
---------------------
- ``auto_defense`` — ``st.toggle``; label collapsed; drives session state.

CSS marker divs
---------------
- ``auto-defense-toggle`` (+ ``is-on`` / ``is-off``): Decorative shell showing
  the label "Auto Defense". The real control is the collapsed toggle placed
  immediately after this div; ``app.css`` overlays them.

db.py / ai_service.py
---------------------
- **Neither.** No database or LLM integration for this toggle yet.
  ``db_coverage.render_db_coverage_notes()`` documents this gap for developers.
"""

import streamlit as st


def render_auto_defense_toggle() -> bool:
    """
    Render the styled Auto Defense toggle in the header toolbar.

    Returns:
        Current on/off state from session (not persisted to DB).

    Session state read/write:
        ``auto_defense`` — default ``False`` if absent.

    Widget key:
        ``auto_defense`` — ``st.toggle`` with ``label_visibility="collapsed"``.

    CSS markers:
        ``div.auto-defense-toggle`` with ``is-on`` or ``is-off`` class suffix.
    """
    if "auto_defense" not in st.session_state:
        st.session_state.auto_defense = False

    is_on = bool(st.session_state.auto_defense)
    state_class = "is-on" if is_on else "is-off"

    # Decorative label shell — real control is the hidden Streamlit toggle below.
    # app.css positions the toggle over this shell using adjacent-sibling selectors.
    st.markdown(
        f"""
        <div class="auto-defense-toggle {state_class}" data-testid="auto-defense-toggle-shell">
            <span class="auto-defense-toggle__label">Auto Defense</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.toggle(
        "Auto Defense",
        key="auto_defense",
        label_visibility="collapsed",
    )
    return bool(st.session_state.auto_defense)
