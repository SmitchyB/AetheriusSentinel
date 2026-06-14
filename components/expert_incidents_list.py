"""
Expert mode incidents table — filterable list with row → detail navigation.

Uses get_incidents_filtered() parameterized query (severity + status selectboxes).
Assignment 4.2 filter widget demo lives here.
"""

import streamlit as st

import db
from components.expert_navigation import navigate_to_incident_detail


def render_expert_incidents_list():
    """
    Render incidents panel on Expert overview with severity/status filters.

    Selecting a row calls navigate_to_incident_detail() and reruns into detail view.
    """
    st.markdown('<div class="standard-panel-card expert-incidents-panel"></div>', unsafe_allow_html=True)
    st.markdown(
        '<h3 class="standard-section-title standard-section-title--compact">Incidents</h3>',
        unsafe_allow_html=True,
    )

    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        severity = st.selectbox(
            "Severity",
            options=["All", "Critical", "High", "Medium", "Low"],
            key="expert_incident_severity_filter",
        )
    with filter_col2:
        status = st.selectbox(
            "Status",
            options=["All", "Active", "Investigating", "Mitigated", "False Positive", "Trusted"],
            key="expert_incident_status_filter",
        )

    try:
        incidents_df = db.get_incidents_filtered(
            severity=severity,
            status=status,
        )
    except Exception as error:
        st.error("Could not load incidents from the database.")
        st.exception(error)
        return

    if incidents_df.empty:
        st.info("No incidents match the current filters.")
        return

    event = st.dataframe(
        incidents_df,
        use_container_width=True,
        hide_index=True,
        height=220,
        on_select="rerun",
        selection_mode="single-row",
        key="expert_incidents_table",
    )

    selected_rows = event.selection.rows if event.selection else []
    if selected_rows:
        row = incidents_df.iloc[selected_rows[0]]
        incident_id = int(row["ID"])
        # Avoid rerun loop if already viewing this incident.
        if st.session_state.get("expert_incident_id") != incident_id:
            navigate_to_incident_detail(incident_id)
            st.rerun()
