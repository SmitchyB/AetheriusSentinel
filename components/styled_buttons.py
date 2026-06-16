"""
CSS marker classes for styled Streamlit buttons.

Purpose
-------
Streamlit renders native ``st.button`` / ``st.form_submit_button`` widgets without
custom CSS class hooks. This module injects **invisible marker divs** placed
immediately *before* each button so ``Assets/app.css`` and ``Assets/standard.css``
can target glow colors, sizes, and header placement via adjacent-sibling selectors.

Usage pattern
-------------
::
    render_action_button_marker("perm_block")
    st.button("Configure ...", key="...")  # CSS styles this button

Navigation / consumers
----------------------
- ``sticky_action_bar`` — playbook step buttons.
- ``expert_incident_actions`` — response palette configure buttons.
- ``expert_incident_detail`` — start investigation, new chat.
- ``incidents_list`` — Standard mode "Start investigation".
- ``scans`` — threat sweep / active connections.
- ``sentinel_panel`` — send button.
- ``expert_action_form`` — deploy / run-it submit (via ``render_action_button_marker``).

Session state
-------------
- None.

Streamlit widget keys
---------------------
- None defined here (callers supply keys on their ``st.button`` calls).

CSS marker divs (this module's core output)
---------------------------------------------
- Base class: ``standard-btn-marker`` on every marker div.
- ``CATEGORY_MARKERS`` — investigation, containment, eradication, post_incident.
- ``SPECIAL_MARKERS`` — chat-only keys (get_started, acknowledge_alert).
- ``UI_MARKERS`` — chrome buttons (start_chat, history, deploy, etc.).

db.py / ai_service.py
---------------------
- **Neither.**
"""

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
    """
    Resolve the CSS marker class for a playbook or chat action button.

    Lookup order:
        1. ``SPECIAL_MARKERS`` for chat gate actions.
        2. ``action_catalog.get_action`` → category → ``CATEGORY_MARKERS``.
        3. Fallback ``standard-btn--start-chat``.

    Args:
        action_key: Raw or alias key; normalized via ``normalize_action_key``.

    Returns:
        CSS class suffix string (without ``standard-btn-marker`` base).
    """
    action_key = normalize_action_key(action_key)
    if action_key in SPECIAL_MARKERS:
        return SPECIAL_MARKERS[action_key]
    action = get_action(action_key)
    if action:
        return CATEGORY_MARKERS.get(action["category"], "standard-btn--start-chat")
    return "standard-btn--start-chat"


def render_button_marker(marker_class: str) -> None:
    """
    Inject an empty div that app.css uses as a styling anchor for the next button.

    Args:
        marker_class: Full BEM suffix, e.g. ``standard-btn--start-chat``.

    CSS output:
        ``<div class="standard-btn-marker {marker_class}"></div>``
    """
    import streamlit as st

    st.markdown(
        f'<div class="standard-btn-marker {marker_class}"></div>',
        unsafe_allow_html=True,
    )


def render_action_button_marker(action_key: str) -> None:
    """
    Convenience wrapper: resolve marker class from action_key → render_button_marker.

    Args:
        action_key: Playbook or sticky-bar action identifier.
    """
    render_button_marker(marker_class_for_action(action_key))
