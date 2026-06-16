"""
Expert mode overview dashboard — KPIs, ticker, hardware, filters, charts.

Purpose
-------
Primary Expert SOC screen (``expert_view == "overview"``): three KPI cards,
scan strip, security events ticker + connected hardware table, filterable
incidents table, severity/volume charts, and 24h network traffic line chart.

Navigation / call graph
-----------------------
``expert_router.render_expert_mode()`` → ``render_expert_overview()`` (default view).

Session state
-------------
- None written directly; ``expert_overview_new_chat`` button calls ``start_general_chat``.

Streamlit widget keys
---------------------
- ``expert_overview_new_chat`` — New Analyst Chat on overview.
- Filter/table keys delegated to ``incidents_list`` and ``scans``.

CSS marker divs
---------------
- KPI: ``expert-metric-card`` + ``metric-devices`` / ``metric-critical`` / ``metric-monthly``.
- Row wrappers: ``expert-top-row-wrapper``, ``expert-incidents-row``, ``expert-telemetry-row``.
- Panels: ``expert-scan-strip``, ``expert-security-events-panel``, ``expert-hardware-panel``,
  ``expert-network-panel``.

db.py
-----
- ``get_device_count()``, ``get_critical_incident_count()``, ``get_incidents_this_month_count()``
- ``get_connected_hardware()``, ``get_traffic_timeseries()``
- ``DB_PATH.exists()`` gate at top

ai_service.py
-------------
- **Not used** on overview (charts/KPIs are SQL aggregations only).
"""

import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

# Allow running/importing when Streamlit cwd differs from project root.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import db  # noqa: E402
from components.expert_charts import render_expert_charts_row
from components.expert_incidents_list import render_expert_incidents_list
from components.expert_security_ticker import render_expert_security_ticker
from components.expert_theme import TRAFFIC_CHART_COLORS
from components.scans import render_scan_actions

# Fixed table/ticker heights keep the top row visually aligned in CSS grid.
HARDWARE_TABLE_HEIGHT = 252
TOP_ROW_CONTENT_HEIGHT = HARDWARE_TABLE_HEIGHT
NETWORK_CHART_HEIGHT = 220


def _panel_card(css_class: str):
    """CSS anchor div for expert panel border/glow styling."""
    st.markdown(
        f'<div class="standard-panel-card {css_class}"></div>',
        unsafe_allow_html=True,
    )


def _render_network_traffic_chart():
    """
    Line chart of hourly connection counts and synthetic traffic volume.

    db.py: ``get_traffic_timeseries()`` — GROUP BY hour on incident_events.
    Volume kb values use protocol-based multipliers (demo data, not live SNMP).

    CSS: ``expert-telemetry-network`` row marker.
    """
    st.markdown('<div class="expert-telemetry-network"></div>', unsafe_allow_html=True)
    st.markdown(
        '<h3 class="standard-section-title standard-section-title--compact">Network Traffic (Last 24h)</h3>',
        unsafe_allow_html=True,
    )
    try:
        traffic_df = db.get_traffic_timeseries()
    except Exception as error:
        st.error("Could not load network traffic from the database.")
        st.exception(error)
        return

    if traffic_df.empty:
        st.info("No traffic telemetry in the database. Run `python seed.py` to load sample events.")
        return

    # Melt wide dataframe into long format for dual-series Altair line chart.
    chart_data = traffic_df.melt(
        id_vars=["Hour"],
        value_vars=["Connection Requests", "Traffic Volume (kb)"],
        var_name="Metric",
        value_name="Value",
    )
    chart = (
        alt.Chart(chart_data)
        .mark_line(point=True)
        .encode(
            x=alt.X("Hour:N", sort=None, title=""),
            y=alt.Y("Value:Q", title="Volume"),
            color=alt.Color(
                "Metric:N",
                scale=alt.Scale(
                    domain=["Connection Requests", "Traffic Volume (kb)"],
                    range=TRAFFIC_CHART_COLORS,
                ),
                legend=alt.Legend(title=None),
            ),
        )
        .properties(height=NETWORK_CHART_HEIGHT)
    )
    st.altair_chart(chart, use_container_width=True)


def _render_expert_kpi(title: str, value: str, marker_class: str, value_class: str):
    """
    Render one KPI card (COUNT query result formatted as zero-padded string).

    CSS: ``expert-metric-card {marker_class}``, ``expert-kpi__value--{value_class}``.
    """
    with st.container(border=True):
        st.markdown(
            f'<div class="standard-panel-card expert-metric-card {marker_class}"></div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            f"""
            <div class="expert-kpi">
                <div class="expert-kpi__title">{title}</div>
                <div class="expert-kpi__value expert-kpi__value--{value_class}">{value}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_expert_overview():
    """
    Compose the full Expert overview page — default ``expert_view`` when not in detail.

    Layout order: KPIs → scans → ticker+hardware → incidents table → charts → traffic.

    db.py: device/critical/monthly counts, ``get_connected_hardware``,
    ``get_traffic_timeseries``; child modules add more queries.

    Widget key: ``expert_overview_new_chat``.
    """
    if not db.DB_PATH.exists():
        st.error(
            f"Database not found at `{db.DB_PATH}`. "
            "Run `python seed.py` from the project root, then refresh."
        )
        return

    # --- Top KPI row (three separate COUNT queries) ---
    try:
        device_count = db.get_device_count()
    except Exception as error:
        st.error("Could not load device count from the database.")
        st.exception(error)
        device_count = 0

    try:
        critical_count = db.get_critical_incident_count()
    except Exception as error:
        st.error("Could not load critical incident count from the database.")
        st.exception(error)
        critical_count = 0

    try:
        incidents_this_month = db.get_incidents_this_month_count()
    except Exception as error:
        st.error("Could not load monthly incident count from the database.")
        st.exception(error)
        incidents_this_month = 0

    kpi1, kpi2, kpi3 = st.columns(3)
    with kpi1:
        _render_expert_kpi("Active Devices", f"{device_count:02d}", "metric-devices", "purple")
    with kpi2:
        _render_expert_kpi("Critical Alerts", f"{critical_count:02d}", "metric-critical", "red")
    with kpi3:
        _render_expert_kpi(
            "Incidents This Month",
            f"{incidents_this_month:02d}",
            "metric-monthly",
            "blue",
        )

    analyst_col, _spacer = st.columns([1.2, 4])
    with analyst_col:
        st.markdown('<div class="expert-btn-marker expert-btn--new-chat"></div>', unsafe_allow_html=True)
        if st.button(
            "New Analyst Chat",
            key="expert_overview_new_chat",
            type="primary",
            use_container_width=True,
            help="Start a general technical Q&A session",
        ):
            from sentinel_actions import start_general_chat

            start_general_chat()
            st.rerun()
    st.caption("General technical Q&A — not tied to an incident. Use incident detail for investigation chat.")

    with st.container(border=True):
        st.markdown('<div class="standard-panel-card expert-scan-strip"></div>', unsafe_allow_html=True)
        render_scan_actions(show_label=False)

    # --- Row 1: Security Events ticker | Connected Hardware table ---
    st.markdown('<div class="expert-top-row-wrapper"></div>', unsafe_allow_html=True)
    events_col, hardware_col = st.columns(2, gap="small")
    with events_col:
        with st.container(border=True):
            st.markdown(
                '<div class="standard-panel-card expert-top-row expert-security-events-panel"></div>',
                unsafe_allow_html=True,
            )
            render_expert_security_ticker(content_height=TOP_ROW_CONTENT_HEIGHT)
    with hardware_col:
        with st.container(border=True):
            st.markdown(
                '<div class="standard-panel-card expert-top-row expert-hardware-panel"></div>',
                unsafe_allow_html=True,
            )
            st.markdown(
                '<h3 class="standard-section-title standard-section-title--compact">Connected Hardware</h3>',
                unsafe_allow_html=True,
            )
            try:
                hardware_df = db.get_connected_hardware()
            except Exception as error:
                st.error("Could not load connected hardware from the database.")
                st.exception(error)
                hardware_df = pd.DataFrame()
            if hardware_df.empty:
                st.info("No devices in the database. Run `python seed.py` to load sample hardware.")
            else:
                st.dataframe(
                    hardware_df,
                    use_container_width=True,
                    hide_index=True,
                    height=TOP_ROW_CONTENT_HEIGHT,
                )

    # --- Row 2: Filterable incidents table ---
    with st.container(border=True):
        st.markdown('<div class="standard-panel-card expert-incidents-row"></div>', unsafe_allow_html=True)
        render_expert_incidents_list()

    # --- Row 3: Severity/volume charts + network traffic line chart ---
    st.markdown('<div class="expert-telemetry-row"></div>', unsafe_allow_html=True)
    render_expert_charts_row()
    with st.container(border=True):
        st.markdown('<div class="standard-panel-card expert-network-panel"></div>', unsafe_allow_html=True)
        _render_network_traffic_chart()
