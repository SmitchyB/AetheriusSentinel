"""
Shared incidents table for Standard and Expert modes.

Purpose
-------
Single implementation for the filterable incidents dataframe used on Standard
(homeowner) dashboard and Expert overview. Both modes query
``db.get_incidents_filtered()``; row-selection behavior diverges by ``mode``.

Navigation flow
---------------
- **Expert** (``mode="expert"``): row select → ``navigate_to_incident_detail`` →
  ``expert_view="incident_detail"`` (auto rerun).
- **Standard** (``mode="standard"``): row select → caption + optional
  ``Start investigation`` / ``Resume investigation`` → ``open_incident_chat``.

Session state dependencies
--------------------------
- ``incidents_table_revision`` — suffix in dataframe widget key to reset selection.
- ``expert_incident_id`` — Expert auto-navigation compares selected row ID.
- ``active_incident_id`` — Standard caption when investigation already open.
- Filter keys: ``incident_severity_filter``, ``incident_status_filter`` (Expert);
  ``standard_incident_severity_filter``, ``standard_incident_status_filter`` (Standard).

Streamlit widget keys
---------------------
- ``{mode}_incidents_table_{revision}`` — ``st.dataframe`` selection widget.
- ``incident_severity_filter``, ``incident_status_filter`` — Expert filters.
- ``standard_incident_severity_filter``, ``standard_incident_status_filter`` — Standard.
- ``start_incident_chat_{incident_id}`` — Standard investigation button.

CSS marker divs
---------------
- ``standard-incidents-row standard-incident-panel`` (Standard header).
- ``expert-incidents-panel`` (Expert header).
- ``standard-btn--start-chat`` via ``render_button_marker`` (Standard only).

db.py
-----
- ``DB_PATH.exists()``, ``get_incidents_filtered()``, ``get_incident_by_id()``,
  ``get_incident_chat_session_id()``.

ai_service.py
-------------
- **Not used** directly (chat opens via ``incident_scenarios``).
"""


import streamlit as st



import db

import incident_scenarios

from components.expert_navigation import navigate_to_incident_detail

from components.styled_buttons import UI_MARKERS, render_button_marker

from incident_scenarios import can_start_new_incident_conversation, is_terminal_status

from sentinel_actions import bump_incidents_table_revision



_STANDARD_STATUS_LABELS = {

    "Active": "Needs attention",

    "Investigating": "Under review",

    "Mitigated": "Resolved",

    "False Positive": "False alarm",

    "Trusted": "Trusted",

}





def _incidents_table_key(mode: str) -> str:
    """Build unique dataframe key including ``incidents_table_revision`` for widget reset."""
    revision = st.session_state.get("incidents_table_revision", 0)

    return f"{mode}_incidents_table_{revision}"





def _render_incidents_header(*, mode: str) -> None:
    """
    Render the Incidents section title and panel CSS marker.

    CSS: ``standard-incident-panel`` (standard) or ``expert-incidents-panel`` (expert).
    """

    panel_class = (

        "standard-incidents-row standard-incident-panel"

        if mode == "standard"

        else "expert-incidents-panel"

    )

    st.markdown(f'<div class="standard-panel-card {panel_class}"></div>', unsafe_allow_html=True)

    st.markdown(

        '<h3 class="standard-section-title standard-section-title--compact">Incidents</h3>',

        unsafe_allow_html=True,

    )





def _friendly_status_label(status: str) -> str:

    return _STANDARD_STATUS_LABELS.get(status, status)





def _standard_display_dataframe(incidents_df):

    """Subset and relabel columns for homeowner Standard mode table."""

    display_df = incidents_df[["Title", "Severity", "Status", "Device"]].copy()

    display_df["Status"] = display_df["Status"].map(

        lambda value: _friendly_status_label(str(value))

    )

    return display_df





def _standard_incident_filters():
    """
    Return severity/status for Standard mode; Open default until expander filters exist.

    Widget keys: ``standard_incident_severity_filter``, ``standard_incident_status_filter``.
    """

    filters_initialized = "standard_incident_severity_filter" in st.session_state



    with st.expander("Show all incidents", expanded=False):

        if not filters_initialized:

            st.caption("Set severity or status to include closed incidents.")

        filter_col1, filter_col2 = st.columns(2)

        with filter_col1:

            severity = st.selectbox(

                "Severity",

                options=["All", "Critical", "High", "Medium", "Low"],

                key="standard_incident_severity_filter",

            )

        with filter_col2:

            status = st.selectbox(

                "Status",

                options=[

                    "All",

                    "Open",

                    "Active",

                    "Investigating",

                    "Mitigated",

                    "False Positive",

                    "Trusted",

                ],

                index=1,

                key="standard_incident_status_filter",

            )



    if filters_initialized:

        return (

            st.session_state.get("standard_incident_severity_filter", "All"),

            st.session_state.get("standard_incident_status_filter", "Open"),

        )

    return "All", "Open"





def render_incidents_list(

    *,

    mode: str = "expert",

    height: int | None = 220,

    max_height: int | None = None,

):

    """
    Render the filterable incidents panel.

    Args:
        mode: ``"standard"`` or ``"expert"`` — controls panel styling and row actions.
        height: Pixel height for the dataframe widget. ``None`` sizes from row count.
        max_height: Optional cap for auto-sized standard-mode tables.

    db.py: ``get_incidents_filtered(severity, status)``; row actions use
    ``get_incident_by_id``, ``get_incident_chat_session_id``.

    Widget key: ``_incidents_table_key(mode)`` on ``st.dataframe``.
    """

    _render_incidents_header(mode=mode)



    if not db.DB_PATH.exists():

        st.error(

            f"Database not found at `{db.DB_PATH}`. "

            "Run `python seed.py` from the project root, then refresh."

        )

        return



    if mode == "standard":

        severity, status = _standard_incident_filters()

    else:

        filter_col1, filter_col2 = st.columns(2)

        with filter_col1:

            severity = st.selectbox(

                "Severity",

                options=["All", "Critical", "High", "Medium", "Low"],

                key="incident_severity_filter",

            )

        with filter_col2:

            status = st.selectbox(

                "Status",

                options=["All", "Active", "Investigating", "Mitigated", "False Positive", "Trusted"],

                key="incident_status_filter",

            )



    try:

        incidents_df = db.get_incidents_filtered(severity=severity, status=status)

    except Exception as error:

        st.error("Could not load incidents from the database.")

        st.exception(error)

        return



    filters_customized = mode == "standard" and "standard_incident_severity_filter" in st.session_state



    if incidents_df.empty:

        if mode == "standard" and not filters_customized and severity == "All" and status == "Open":

            st.info("No open incidents right now. Run a scan to check your network.")

        elif severity != "All" or status not in ("All", "Open"):

            st.info("No incidents match the current filters.")

        else:

            st.info("No incidents recorded yet. Run a scan to detect one.")

        return



    display_df = (

        _standard_display_dataframe(incidents_df) if mode == "standard" else incidents_df

    )



    dataframe_kwargs = {

        "use_container_width": True,

        "hide_index": True,

        "on_select": "rerun",

        "selection_mode": "single-row",

        "key": _incidents_table_key(mode),

    }

    if height is not None:

        dataframe_kwargs["height"] = height

    else:

        auto_height = max(160, 38 * (len(display_df) + 1) + 6)

        if max_height is not None:

            auto_height = min(auto_height, max_height)

        dataframe_kwargs["height"] = auto_height



    event = st.dataframe(display_df, **dataframe_kwargs)



    selected_rows = event.selection.rows if event.selection else []

    if not selected_rows:

        return



    row = incidents_df.iloc[selected_rows[0]]

    incident_id = int(row["ID"])

    row_status = row.get("Status", "Unknown")



    if mode == "expert":

        if st.session_state.get("expert_incident_id") != incident_id:

            navigate_to_incident_detail(incident_id)

            st.rerun()

        return



    status_label = _friendly_status_label(str(row_status))

    st.caption(f"Selected: **{row['Title']}** · Status: **{status_label}**")

    try:

        incident_row = db.get_incident_by_id(incident_id)

    except Exception:

        incident_row = None



    if incident_row and can_start_new_incident_conversation(

        incident_scenarios.build_active_incident_from_db(incident_row)

    ):

        active_incident_id = st.session_state.get("active_incident_id")

        if active_incident_id == incident_id:

            st.caption("Investigation open in Sentinel Chat above.")

        else:

            render_button_marker(UI_MARKERS["start_chat"])

            has_chat = bool(db.get_incident_chat_session_id(incident_id))

            if has_chat:

                button_label = "Resume investigation"

            elif row_status == "Active":

                button_label = "Start investigation"

            else:

                button_label = "Open analyst chat"

            if st.button(

                button_label,

                key=f"start_incident_chat_{incident_id}",

                type="primary",

                use_container_width=True,

            ):

                incident_scenarios.open_incident_chat(incident_id)

                st.rerun()

    elif incident_row and is_terminal_status(row_status):

        st.caption(

            "This incident is closed. Resume the investigation chat above to generate "

            "a report or police packet, or switch to Expert mode for full documentation tools."

        )





def render_expert_incidents_list():
    """Expert overview wrapper — ``render_incidents_list(mode="expert")``."""

    render_incidents_list(mode="expert")


