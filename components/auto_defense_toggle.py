"""
Auto Defense header toggle — visual placeholder for a future policy engine.

When built, this toggle would allow automated containment without manual ack.
Today it only stores True/False in st.session_state.auto_defense.
"""

import streamlit as st


def render_auto_defense_toggle() -> bool:
    """
    Render the styled Auto Defense toggle in the header toolbar.

    Returns:
        Current on/off state from session (not persisted to DB).
    """
    if "auto_defense" not in st.session_state:
        st.session_state.auto_defense = False

    is_on = bool(st.session_state.auto_defense)
    state_class = "is-on" if is_on else "is-off"

    # Decorative label shell — real control is the hidden Streamlit toggle below.
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
