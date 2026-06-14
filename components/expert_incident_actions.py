"""Expert incident detail — recommendations, actions taken, and response palette."""

from __future__ import annotations

import json

import streamlit as st

import db
from action_catalog import ACTION_CATEGORIES, ACTIONS, get_action, normalize_action_key
from components.expert_action_form import render_expert_action_approval
from components.styled_buttons import render_action_button_marker, render_button_marker
from incident_scenarios import (
    acknowledge_incident_flow,
    can_execute_action,
    can_show_acknowledge,
    format_playbook_complete_message,
    get_next_executable_recommended_step,
    get_playbook_phase,
    get_recommended_action_keys,
    is_playbook_complete,
    is_terminal_status,
)


def _section_title(label: str):
    """Compact section heading matching Standard/Expert shared title CSS class."""
    st.markdown(
        f'<h3 class="standard-section-title standard-section-title--compact">{label}</h3>',
        unsafe_allow_html=True,
    )


def render_ai_recommendations(incident_id: int):
    """
    Show recommendations rows from DB — playbook, authority notices, general advice.

    Playbook section lists recommended action keys with ✓/○ based on incident_actions.
    """
    _section_title("AI Recommendations")
    try:
        recommendations = db.get_recommendations_for_incident(incident_id)
    except Exception as error:
        st.error("Could not load recommendations.")
        st.exception(error)
        return

    if not recommendations:
        st.info("No recommendations yet. Acknowledge the alert to generate a playbook.")
        return

    completed = db.get_incident_action_keys_completed(incident_id)

    for rec in recommendations:
        rec_type = rec.get("recommendation_type", "general")
        text = rec.get("recommendation_text", "")

        if rec_type == "playbook":
            st.markdown("**Recommended Playbook**")
            st.markdown(text)
            raw = rec.get("playbook_actions_json")
            if raw:
                try:
                    keys = json.loads(raw)
                except json.JSONDecodeError:
                    keys = []
                for index, key in enumerate(keys, start=1):
                    action = get_action(key)
                    label = action["label"] if action else key
                    mark = "✓" if key in completed else "○"
                    st.markdown(f"{mark} {index}. **{label}**")
            st.divider()
        elif rec_type == "authority_notice":
            st.warning(text)
        else:
            prefix = "AI: " if rec.get("is_ai_generated") else ""
            st.markdown(f"- {prefix}{text}")


def render_actions_taken(incident_id: int):
    """Chronological list of incident_actions rows (auto + manual steps)."""
    _section_title("Actions Taken")
    try:
        actions = db.get_incident_actions_list(incident_id)
    except Exception as error:
        st.error("Could not load actions taken.")
        st.exception(error)
        return

    if not actions:
        st.caption("No actions recorded yet.")
        return

    for row in actions:
        action = get_action(row["action_key"])
        label = action["label"] if action else row["action_key"]
        auto = " (auto)" if row.get("is_automated") else ""
        rec = " ★" if row.get("is_recommended") else ""
        st.markdown(f"**{label}**{auto}{rec} — _{row.get('result_summary', '')}_")
        st.caption(f"{row.get('created_at', '')} · {row.get('action_category', '')}")


def _select_detail_action(incident_id: int, action_key: str) -> None:
    """Store which response action the analyst chose to configure on the detail page."""
    st.session_state[f"expert_action_form_{incident_id}"] = action_key


def _clear_detail_action(incident_id: int) -> None:
    st.session_state.pop(f"expert_action_form_{incident_id}", None)


def _active_response_category(
    *,
    phase: str,
    next_category: str | None,
    selected: str | None,
) -> str | None:
    """Pick which IR category expander should stay open for buttons and inline forms."""
    if selected:
        selected_action = get_action(selected)
        if selected_action:
            return selected_action["category"]
    if next_category:
        return next_category
    if phase in ACTION_CATEGORIES:
        return phase
    if phase == "closed":
        return "post_incident"
    return None


def render_response_actions(incident_id: int, incident: dict):
    """
    Expandable action palette grouped by IR category (containment, eradication, etc.).

    Buttons respect get_playbook_phase() gating via can_execute_action().
    Simulated deploy writes to incident_actions — no live network API.
    """
    _section_title("Response Actions")
    phase = get_playbook_phase(incident)
    recommended = set(get_recommended_action_keys(incident_id))
    completed = db.get_incident_action_keys_completed(incident_id)

    st.caption(f"Current phase: **{phase.replace('_', ' ').title()}**")

    if phase == "awaiting_ack":
        st.info("Acknowledge the alert to unlock containment and resolution actions.")
        return

    if phase == "closed" and not is_terminal_status(incident.get("status", "")):
        if is_playbook_complete(incident):
            st.success(format_playbook_complete_message(incident))

    if is_terminal_status(incident.get("status", "")):
        st.info(
            "This incident is closed. Only post-incident and documentation actions are available."
        )

    category_labels = {
        "investigation": "Investigation",
        "containment": "Containment",
        "eradication": "Eradication & Resolution",
        "post_incident": "Post-Incident & Documentation",
    }

    next_key = get_next_executable_recommended_step(incident)
    next_category = None
    if next_key:
        next_action = get_action(next_key)
        if next_action:
            next_category = next_action["category"]

    selected = st.session_state.get(f"expert_action_form_{incident_id}")
    active_category = _active_response_category(
        phase=phase,
        next_category=next_category,
        selected=selected,
    )

    for category in ACTION_CATEGORIES:
        # Closed incidents hide all categories except post_incident documentation.
        if is_terminal_status(incident.get("status", "")) and category != "post_incident":
            continue

        expanded = category == "post_incident" if is_terminal_status(incident.get("status", "")) else (
            category == active_category
        )
        with st.expander(category_labels.get(category, category.title()), expanded=expanded):
            category_actions = [
                (key, action)
                for key, action in ACTIONS.items()
                if action["category"] == category
            ]
            if not category_actions:
                continue

            visible_actions = False
            for action_key, action in category_actions:
                if action_key in completed:
                    st.success(f"**{action['label']}** — completed")
                    visible_actions = True
                    continue

                if not can_execute_action(action_key, incident):
                    continue

                visible_actions = True
                highlight = action_key in recommended
                hint = action.get("hint", "")
                label_prefix = "★ " if highlight else ""
                st.markdown(f"{label_prefix}**{action['label']}** — _{hint}_")

                form_key = f"expert_detail_action_{incident_id}_{action_key}"
                render_action_button_marker(action_key)
                st.button(
                    f"Configure {action['label']}",
                    key=form_key,
                    use_container_width=True,
                    type="secondary",
                    on_click=_select_detail_action,
                    args=(incident_id, action_key),
                )

                if selected == action_key:
                    st.markdown('<div class="expert-draft-form"></div>', unsafe_allow_html=True)
                    render_expert_action_approval(
                        action_key,
                        incident,
                        key_prefix=f"expert_detail_{incident_id}",
                        incident_id=incident_id,
                    )
                    if st.button(
                        "Cancel",
                        key=f"expert_detail_cancel_{incident_id}_{action_key}",
                        use_container_width=True,
                    ):
                        _clear_detail_action(incident_id)
                        st.rerun()

            if not visible_actions:
                st.caption("No actions available in this category right now.")


def render_acknowledge_button(incident_id: int, incident: dict):
    """
    Primary ack button — triggers acknowledge_incident_flow() and playbook insert.

    Hidden when already acknowledged or incident is in terminal status.
    """
    if not can_show_acknowledge(incident_id, incident):
        if db.is_incident_acknowledged(incident_id):
            st.caption(f"Alert acknowledged · Status: **{incident.get('status', 'Unknown')}**")
        elif is_terminal_status(incident.get("status", "")):
            st.caption(f"Incident closed · Status: **{incident.get('status', 'Unknown')}**")
        if incident.get("monitor_until"):
            st.caption(f"Monitoring until: {incident['monitor_until']}")
        return

    render_button_marker("standard-btn--action-containment")
    if st.button(
        "Acknowledge alert",
        key=f"expert_ack_{incident_id}",
        type="primary",
        use_container_width=True,
    ):
        acknowledge_incident_flow(incident_id)
        st.rerun()
