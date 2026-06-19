"""CSS marker classes for styled Streamlit buttons."""

from action_catalog import get_action, normalize_action_key

# Maps incident response category → CSS marker suffix.
CATEGORY_MARKERS = {
    "investigation": "standard-btn--action-investigation",
    "containment": "standard-btn--action-containment",
    "eradication": "standard-btn--action-eradication",
    "post_incident": "standard-btn--action-post-incident",
}

# Chat-only actions that are not in the main ACTIONS registry keys.
SPECIAL_MARKERS = {
    "get_started": "standard-btn--action-containment",
    "acknowledge_alert": "standard-btn--action-containment",
}

# Static UI chrome buttons (start chat, history, deploy).
UI_MARKERS = {
    "start_chat": "standard-btn--start-chat",
    "history": "standard-btn--chat-history",
    "investigation_flow": "standard-btn--action-investigation",
    "analyst_chat": "standard-btn--start-chat",
    "deploy": "standard-btn--action-eradication",
}


def marker_class_for_action(action_key: str) -> str:
    """Resolve the CSS marker class for a playbook or chat action button."""
    action_key = normalize_action_key(action_key)
    if action_key in SPECIAL_MARKERS:
        return SPECIAL_MARKERS[action_key]
    action = get_action(action_key)
    if action:
        return CATEGORY_MARKERS.get(action["category"], "standard-btn--start-chat")
    return "standard-btn--start-chat"


def render_button_marker(marker_class: str) -> None:
    """Inject an empty div that app.css uses as a styling anchor for the next button."""
    import streamlit as st

    st.markdown(
        f'<div class="standard-btn-marker {marker_class}"></div>',
        unsafe_allow_html=True,
    )


def render_action_button_marker(action_key: str) -> None:
    """Convenience wrapper: resolve marker class from action_key → render_button_marker."""
    render_button_marker(marker_class_for_action(action_key))
