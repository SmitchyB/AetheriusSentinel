"""Auto Defense header toggle — visual placeholder for a future policy engine."""

import streamlit as st


def render_auto_defense_toggle() -> bool:
    """Render the styled Auto Defense toggle in the header toolbar."""
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
