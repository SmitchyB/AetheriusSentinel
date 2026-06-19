"""Sticky bottom action bar — playbook steps and resolution shortcuts above chat input."""

from __future__ import annotations

import streamlit as st

from components.styled_buttons import render_action_button_marker
from incident_scenarios import (
    VERIFICATION_CANCEL_ACTION,
    VERIFICATION_CONFIRM_ACTION,
    get_active_incident,
    get_sticky_bar_state,
    handle_sticky_action,
)


def _render_action_button(
    action: dict,
    *,
    key_prefix: str,
    slot: str,
    disabled: bool,
    use_container_width: bool = True,
) -> None:
    """Render one sticky-bar playbook button with category-colored CSS marker."""
    render_action_button_marker(action["key"])
    if st.button(
        action["label"],
        key=f"{key_prefix}_sticky_{slot}_{action['key']}",
        use_container_width=use_container_width,
        type="primary" if action.get("type") == "primary" else "secondary",
        disabled=disabled,
    ):
        handle_sticky_action(action["key"])
        st.rerun()


# ---------------------------------------------------------------------------
# Sticky bar modes — verification, plan update, playbook, monitoring idle
# ---------------------------------------------------------------------------

def render_sticky_action_bar(*, key_prefix: str = "standard") -> None:
    """Render fixed action strip above the chat input."""
    incident = get_active_incident()
    state = get_sticky_bar_state(incident)
    disabled = False

    st.markdown('<div class="standard-chat-action-bar"></div>', unsafe_allow_html=True)

    mode = state.get("mode", "idle")
    if mode == "idle":
        return

    if mode == "verification":
        verification = state.get("verification") or {}
        st.caption("Review before continuing")
        st.warning(verification.get("warning", ""))
        if verification.get("error_detail"):
            st.caption(verification["error_detail"])
        for item in verification.get("checklist", []):
            st.markdown(f"- {item}")
        confirm_label = verification.get("confirm_label", "Confirm")
        col1, col2 = st.columns(2)
        with col1:
            if st.button(
                confirm_label,
                key=f"{key_prefix}_verify_confirm",
                use_container_width=True,
                type="primary",
                disabled=disabled,
            ):
                handle_sticky_action(VERIFICATION_CONFIRM_ACTION)
                st.rerun()
        with col2:
            if st.button(
                "Cancel",
                key=f"{key_prefix}_verify_cancel",
                use_container_width=True,
                type="secondary",
                disabled=disabled,
            ):
                handle_sticky_action(VERIFICATION_CANCEL_ACTION)
                st.rerun()
        return

    if mode == "plan_update":
        actions = state.get("actions", [])
        if actions:
            st.markdown('<div class="standard-chat-action-buttons"></div>', unsafe_allow_html=True)
            cols = st.columns(len(actions), gap="small")
            for index, action in enumerate(actions):
                with cols[index]:
                    _render_action_button(
                        action,
                        key_prefix=key_prefix,
                        slot="plan",
                        disabled=disabled,
                    )
        return

    primary = state.get("primary")
    shortcuts = state.get("shortcuts", [])
    post_actions = state.get("post_incident_actions", [])

    row_actions: list[tuple[str, dict]] = []
    if primary:
        row_actions.append(("primary", primary))
    row_actions.extend((f"short_{index}", action) for index, action in enumerate(shortcuts))

    if row_actions:
        st.markdown('<div class="standard-chat-action-buttons"></div>', unsafe_allow_html=True)
        cols = st.columns(len(row_actions), gap="small")
        for col, (slot, action) in zip(cols, row_actions):
            with col:
                _render_action_button(
                    action,
                    key_prefix=key_prefix,
                    slot=slot,
                    disabled=disabled,
                )

    if post_actions and not primary:
        st.markdown('<div class="standard-chat-action-buttons"></div>', unsafe_allow_html=True)
        cols = st.columns(min(len(post_actions[:3]), 3), gap="small")
        for index, action in enumerate(post_actions[:3]):
            with cols[index % len(cols)]:
                _render_action_button(
                    action,
                    key_prefix=key_prefix,
                    slot=f"doc_{index}",
                    disabled=disabled,
                )

    if mode == "monitoring" and not primary and not shortcuts:
        st.caption("Enhanced monitoring in progress.")
