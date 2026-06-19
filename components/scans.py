"""Scan action buttons — trigger simulated threat detection flows."""

import streamlit as st


def render_scan_actions(show_label: bool = False):
    """Render the two scan trigger buttons used in both Standard and Expert mode."""
    scan_disabled = False

    if st.session_state.get("scan_complete_notice"):
        st.success(st.session_state.scan_complete_notice)
        st.session_state.scan_complete_notice = None

    if st.session_state.get("scan_error_notice"):
        st.warning(st.session_state.scan_error_notice)
        st.session_state.scan_error_notice = None

    if show_label:
        # Standard layout: [label | threat sweep | active connections]
        label_col, sweep_col, conn_col = st.columns(
            [0.11, 0.445, 0.445],
            vertical_alignment="center",
            gap="small",
        )
        with label_col:
            st.markdown(
                '<h3 class="standard-section-title standard-section-title--compact">Scans</h3>',
                unsafe_allow_html=True,
            )
        button_cols = (sweep_col, conn_col)
    else:
        # Expert layout: two equal-width buttons only.
        sweep_col, conn_col = st.columns(2, gap="small")
        button_cols = (sweep_col, conn_col)

    threat_sweep_label = (
        "Check my network for threats" if show_label else "Run AI Threat Sweep"
    )
    active_connections_label = (
        "See what's connected right now" if show_label else "Scan Active Connections"
    )

    # --- AI Threat Sweep: rotates through exfiltration / low-risk / ransomware scenarios ---
    with button_cols[0]:
        # CSS marker div lets app.css style the Streamlit button via sibling selectors.
        st.markdown(
            '<div class="standard-btn-marker standard-btn--threat-sweep"></div>',
            unsafe_allow_html=True,
        )
        if st.button(
            threat_sweep_label,
            type="primary",
            use_container_width=True,
            key="scan_ai_threat_sweep",
            disabled=scan_disabled,
        ):
            from incident_scenarios import trigger_scan

            trigger_scan("ai_threat_sweep")
            st.rerun()

    # --- Active Connections: rotates through brute force / lateral / C2 scenarios ---
    with button_cols[1]:
        st.markdown(
            '<div class="standard-btn-marker standard-btn--active-connections"></div>',
            unsafe_allow_html=True,
        )
        if st.button(
            active_connections_label,
            type="secondary",
            use_container_width=True,
            key="scan_active_connections",
            disabled=scan_disabled,
        ):
            from incident_scenarios import trigger_scan

            trigger_scan("active_connections")
            st.rerun()
