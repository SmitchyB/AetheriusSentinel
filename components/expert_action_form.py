"""Expert action parameter forms — review/edit draft payloads before simulated deploy."""

import streamlit as st

from action_catalog import get_action, get_draft_payload, normalize_action_key
from components.styled_buttons import render_action_button_marker
from incident_scenarios import execute_incident_action, handle_expert_deploy


def render_expert_action_approval(
    action_key: str,
    incident: dict,
    key_prefix: str,
    *,
    in_chat: bool = False,
    draft_message_index: int | None = None,
    incident_id: int | None = None,
) -> None:
    """Render a Streamlit form pre-filled with get_draft_payload() defaults."""
    action_key = normalize_action_key(action_key)
    # Pre-fill from action_catalog templates based on incident device/indicator.
    draft = get_draft_payload(action_key, incident)

    if not in_chat:
        action = get_action(action_key)
        label = action["label"] if action else action_key.replace("_", " ").title()
        st.markdown(f"### Proposed Action: {label}")
        st.info(
            "Review the parameters below, edit if needed, then deploy when ready."
        )

    with st.form(key=f"{key_prefix}_expert_form_{action_key}_{draft_message_index}"):
        payload = _render_payload_fields(action_key, draft)

        render_action_button_marker(action_key)
        submit_label = "Run it" if in_chat else "Deploy"
        submit = st.form_submit_button(submit_label, type="primary", use_container_width=True)

        if submit:
            if in_chat:
                handle_expert_deploy(action_key, payload, draft_message_index)
                st.rerun()
            elif incident_id:
                success, result = execute_incident_action(
                    incident_id, action_key, payload, source="expert_detail"
                )
                if success:
                    st.session_state.pop(f"expert_action_form_{incident_id}", None)
                    st.rerun()
                else:
                    st.error(result)


def _render_payload_fields(action_key: str, draft: dict) -> dict:
    """Build action-specific form fields and return collected payload dict."""
    payload: dict = {}

    if action_key == "perm_block":
        payload["target_ip"] = st.text_input("Target IP / CIDR", value=draft.get("target_ip", ""))
        direction_options = ["Inbound", "Outbound", "Both"]
        payload["direction"] = st.selectbox(
            "Traffic Direction",
            options=direction_options,
            index=direction_options.index(draft.get("direction", "Both")),
        )
        action_options = ["DROP", "REJECT"]
        payload["action"] = st.selectbox(
            "Firewall Action",
            options=action_options,
            index=action_options.index(draft.get("action", "DROP")),
        )
        payload["timeout"] = st.number_input(
            "Timeout (Hours, 0 = Permanent)",
            min_value=0,
            value=int(draft.get("timeout", 0)),
        )

    elif action_key == "isolate_device":
        payload["target_mac"] = st.text_input("Target MAC", value=draft.get("target_mac", ""))
        payload["allow_management"] = st.checkbox(
            "Keep Management Ports Open (SSH/RDP)",
            value=draft.get("allow_management", True),
        )

    elif action_key == "sever_connection":
        payload["target_ip"] = st.text_input("Target IP", value=draft.get("target_ip", ""))
        protocol_options = ["TCP", "UDP", "Both"]
        payload["protocol"] = st.selectbox(
            "Protocol",
            options=protocol_options,
            index=protocol_options.index(draft.get("protocol", "TCP")),
        )
        payload["reset_packets"] = st.checkbox(
            "Inject TCP Reset",
            value=draft.get("reset_packets", True),
        )

    elif action_key == "port_lockdown":
        payload["target_ip"] = st.text_input("Target IP", value=draft.get("target_ip", ""))
        payload["port"] = st.number_input(
            "Port",
            min_value=1,
            max_value=65535,
            value=int(draft.get("port", 443)),
        )
        protocol_options = ["TCP", "UDP", "Both"]
        payload["protocol"] = st.selectbox(
            "Protocol",
            options=protocol_options,
            index=protocol_options.index(draft.get("protocol", "TCP")),
        )

    elif action_key == "throttle_connection":
        payload["target_ip"] = st.text_input("Target IP", value=draft.get("target_ip", ""))
        payload["max_kbps"] = st.number_input(
            "Max Bandwidth (kbps)",
            min_value=1,
            value=int(draft.get("max_kbps", 64)),
        )
        payload["duration_hours"] = st.number_input(
            "Duration (Hours)",
            min_value=1,
            value=int(draft.get("duration_hours", 4)),
        )

    elif action_key == "dns_sinkhole":
        payload["domain"] = st.text_input("Malicious Domain", value=draft.get("domain", ""))
        payload["sinkhole_ip"] = st.text_input(
            "Sinkhole IP",
            value=draft.get("sinkhole_ip", "127.0.0.1"),
        )

    elif action_key == "trust_device":
        payload["device_name"] = st.text_input("Device Name", value=draft.get("device_name", ""))
        payload["snooze_hours"] = st.number_input(
            "Trust Duration (Hours)",
            min_value=1,
            value=int(draft.get("snooze_hours", 24)),
        )

    elif action_key == "prompt_offline_scan":
        payload["device_name"] = st.text_input("Device Name", value=draft.get("device_name", ""))
        payload["monitor_hours"] = st.number_input(
            "Monitor Window (Hours)",
            min_value=24,
            max_value=48,
            value=int(draft.get("monitor_hours", 36)),
        )

    elif action_key == "require_credential_rotation":
        payload["affected_users"] = st.text_input(
            "Affected Users",
            value=str(draft.get("affected_users", "Admin")),
        )
        payload["revoke_sessions"] = st.checkbox(
            "Revoke Active Sessions",
            value=draft.get("revoke_sessions", True),
        )

    elif action_key == "mark_false_positive":
        payload["reason"] = st.text_input("Reason", value=draft.get("reason", ""))
        payload["suppress_hours"] = st.number_input(
            "Suppress Similar Alerts (Hours)",
            min_value=1,
            value=int(draft.get("suppress_hours", 72)),
        )

    elif action_key == "reimage_wipe_device":
        payload["target_mac"] = st.text_input("Target MAC", value=draft.get("target_mac", ""))
        payload["backup_required"] = st.checkbox(
            "Require Backup First",
            value=draft.get("backup_required", True),
        )

    elif action_key == "patch_remediate":
        payload["cve_id"] = st.text_input("CVE ID", value=draft.get("cve_id", ""))
        payload["patch_notes"] = st.text_area(
            "Patch Notes",
            value=draft.get("patch_notes", ""),
        )

    elif action_key == "generate_incident_report":
        payload["title"] = st.text_input("Report Title", value=draft.get("title", ""))
        payload["include_timeline"] = st.checkbox(
            "Include Timeline",
            value=draft.get("include_timeline", True),
        )
        payload["notes"] = st.text_area("Analyst Notes", value=draft.get("notes", ""))

    elif action_key == "freeze_incident_state":
        payload["retention_days"] = st.number_input(
            "Retention (Days)",
            min_value=1,
            value=int(draft.get("retention_days", 90)),
        )
        payload["include_memory_dump"] = st.checkbox(
            "Include Memory Dump",
            value=draft.get("include_memory_dump", True),
        )

    elif action_key == "export_raw_forensics":
        payload["format"] = st.selectbox(
            "Export Format",
            options=["ZIP", "TAR"],
            index=0 if draft.get("format") == "ZIP" else 1,
        )
        payload["include_network_captures"] = st.checkbox(
            "Include Network Captures",
            value=draft.get("include_network_captures", True),
        )

    elif action_key == "export_police_packet":
        payload["agency_contact"] = st.text_input(
            "Agency Contact",
            value=draft.get("agency_contact", ""),
        )
        payload["include_talking_points"] = st.checkbox(
            "Include Talking Points",
            value=draft.get("include_talking_points", True),
        )

    elif action_key == "fingerprint_device":
        payload["target_ip"] = st.text_input("Target IP", value=draft.get("target_ip", ""))
        payload["target_mac"] = st.text_input("Target MAC", value=draft.get("target_mac", ""))

    elif action_key == "ping_sweep":
        payload["subnet"] = st.text_input("Subnet", value=draft.get("subnet", "192.168.1.0/24"))
        payload["timeout_seconds"] = st.number_input(
            "Timeout (seconds)",
            min_value=1,
            value=int(draft.get("timeout_seconds", 2)),
        )

    return payload
