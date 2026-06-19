"""Expert mode header toggle — switches between Standard and Expert dashboard layouts."""

import streamlit as st

from sentinel_actions import bump_incidents_table_revision, reset_expert_state


def _on_expert_mode_change():
    """Streamlit ``on_change`` callback when user toggles Expert mode."""
    bump_incidents_table_revision()
    if not st.session_state.expert_mode:
        reset_expert_state()


def render_expert_mode_toggle() -> bool:
    """Render the styled Expert Mode toggle in the header toolbar."""
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
