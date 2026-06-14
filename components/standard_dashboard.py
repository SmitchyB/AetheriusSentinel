"""
Standard mode dashboard — homeowner layout with scans, incidents, history, and chat.

This is the default view when Expert mode toggle is OFF in app.py.
"""

from pathlib import Path

import streamlit as st

import db
import incident_scenarios
from components.chat_history import render_chat_history
from incident_scenarios import can_start_new_incident_conversation, is_terminal_status
from components.scans import render_scan_actions
from components.sentinel_panel import render_sentinel_chat_input, render_sentinel_panel
from components.standard_layout_sizer import render_standard_layout_sizer
from components.styled_buttons import UI_MARKERS, render_button_marker


def load_standard_css():
    """Inject Standard-mode stylesheet (lighter homeowner theme)."""
    for css_path in (Path("Assets/standard.css"), Path("assets/standard.css")):
        if css_path.exists():
            st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)
            return


def _render_incident_list():
    """
    DB-backed incident table with row selection → start investigation button.

    Uses get_incidents_list() JOIN query (incidents + devices).
    """
    st.markdown('<div class="standard-panel-card standard-incident-panel"></div>', unsafe_allow_html=True)
    st.markdown(
        '<h3 class="standard-section-title standard-section-title--compact">Incidents</h3>',
        unsafe_allow_html=True,
    )

    if not db.DB_PATH.exists():
        st.error(
            f"Database not found at `{db.DB_PATH}`. "
            "Run `python seed.py` from the project root, then refresh."
        )
        return

    try:
        incidents_df = db.get_incidents_list()
    except Exception as error:
        st.error("Could not load incidents from the database.")
        st.exception(error)
        return

    if incidents_df.empty:
        st.info("No incidents recorded yet. Run a scan to detect one.")
        return

    display_df = incidents_df.copy()
    if "incident_id" in display_df.columns:
        display_df = display_df.drop(columns=["incident_id"])

    # Interactive table — selection triggers rerun with event.selection.rows populated.
    event = st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        height=110,
        on_select="rerun",
        selection_mode="single-row",
        key="standard_incidents_table",
    )

    selected_rows = event.selection.rows if event.selection else []
    if selected_rows:
        row_index = selected_rows[0]
        row = display_df.iloc[row_index]
        incident_id = int(row["ID"])
        status = row.get("Status", "Unknown")
        st.caption(f"Selected: **{row['Title']}** (ID {incident_id}) · Status: **{status}**")
        try:
            incident_row = db.get_incident_by_id(incident_id)
        except Exception:
            incident_row = None

        if incident_row and can_start_new_incident_conversation(
            incident_scenarios.build_active_incident_from_db(incident_row)
        ):
            active_incident_id = st.session_state.get("active_incident_id")
            active_session_id = st.session_state.get("active_session_id")
            if active_incident_id == incident_id and active_session_id:
                st.caption("Investigation open in Sentinel Chat below.")
            else:
                render_button_marker(UI_MARKERS["start_chat"])
                button_label = (
                    "Start investigation"
                    if status == "Active"
                    else "Open analyst chat"
                )
                if st.button(
                    button_label,
                    key=f"start_incident_chat_{incident_id}",
                    type="primary",
                    use_container_width=True,
                ):
                    incident_scenarios.open_incident_chat(incident_id)
                    st.rerun()
        elif incident_row and is_terminal_status(status):
            st.caption(
                "This incident is closed. Use Expert mode for post-incident documentation, "
                "or open a related session from Chat History."
            )


def render_standard_mode():
    """
    Compose the full Standard mode page: scan strip, incidents, history + chat split.

    Calls render_standard_layout_sizer() at the end to equalize scroll panel heights via JS.
    """
    st.markdown('<div class="standard-mode-root"></div>', unsafe_allow_html=True)

    with st.container(border=True):
        st.markdown('<div class="standard-panel-card standard-scan-strip"></div>', unsafe_allow_html=True)
        render_scan_actions(show_label=True)

    with st.container(border=True):
        _render_incident_list()

    st.markdown('<div class="standard-chat-split-row"></div>', unsafe_allow_html=True)
    history_col, chat_col = st.columns([1, 4], gap="medium", vertical_alignment="top")

    with history_col:
        with st.container(border=True):
            render_chat_history()

    with chat_col:
        with st.container(border=True):
            render_sentinel_panel()

    # Chat input aligned under the chat column (not under history).
    _, input_col = st.columns([1, 4], gap="medium")
    with input_col:
        render_sentinel_chat_input()

    render_standard_layout_sizer()
