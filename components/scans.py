"""
Scan action buttons — trigger simulated threat detection flows.

Scans do NOT probe the live network. They call incident_scenarios.trigger_scan(),
which inserts a new incident + template telemetry into SQLite.
"""

import streamlit as st


def render_scan_actions(show_label: bool = False):
    """
    Render the two scan trigger buttons used in both Standard and Expert mode.

    Args:
        show_label: When True (Standard mode strip), show a "Scans" section title
                    in a third column. Expert mode uses two equal columns only.
    """
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

    # --- AI Threat Sweep: rotates through exfiltration / low-risk / ransomware scenarios ---
    with button_cols[0]:
        # CSS marker div lets app.css style the Streamlit button via sibling selectors.
        st.markdown(
            '<div class="standard-btn-marker standard-btn--threat-sweep"></div>',
            unsafe_allow_html=True,
        )
        if st.button(
            "Run AI Threat Sweep",
            type="primary",
            use_container_width=True,
            key="scan_ai_threat_sweep",
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
            "Scan Active Connections",
            type="secondary",
            use_container_width=True,
            key="scan_active_connections",
        ):
            from incident_scenarios import trigger_scan

            trigger_scan("active_connections")
            st.rerun()
