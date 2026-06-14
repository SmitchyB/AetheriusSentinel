"""
Expert mode Altair charts — severity donut and 48h event volume bar chart.

Both charts read aggregated data from db.py (GROUP BY queries).
"""

import altair as alt
import streamlit as st

import db
from components.expert_theme import (
    SEVERITY_CHART_COLORS,
    SEVERITY_CHART_DOMAIN,
    THEME_CYAN,
)


def _panel_card(css_class: str):
    """Inject CSS layout marker div for chart panel styling hooks."""
    st.markdown(
        f'<div class="standard-panel-card {css_class}"></div>',
        unsafe_allow_html=True,
    )


def render_expert_charts_row():
    """
    Render side-by-side charts row on Expert overview dashboard.

    Left: incidents by severity (GROUP BY). Right: hourly event volume (48h window).
    """
    st.markdown('<div class="expert-charts-row expert-telemetry-charts"></div>', unsafe_allow_html=True)
    chart_col1, chart_col2 = st.columns(2, gap="medium")

    # --- Severity donut (assignment aggregation demo) ---
    with chart_col1:
        with st.container(border=True):
            _panel_card("expert-severity-chart-panel")
            st.markdown(
                '<h3 class="standard-section-title standard-section-title--compact">Incidents by Severity</h3>',
                unsafe_allow_html=True,
            )
            try:
                severity_df = db.get_incidents_by_severity_counts()
            except Exception as error:
                st.error("Could not load severity chart data.")
                st.exception(error)
                severity_df = None

            if severity_df is None:
                pass
            elif severity_df.empty:
                st.info("No incidents recorded yet.")
            else:
                chart = (
                    alt.Chart(severity_df)
                    .mark_arc(innerRadius=50)
                    .encode(
                        theta=alt.Theta("Count:Q"),
                        color=alt.Color(
                            "Severity:N",
                            scale=alt.Scale(
                                domain=SEVERITY_CHART_DOMAIN,
                                range=SEVERITY_CHART_COLORS,
                            ),
                            legend=alt.Legend(title=None),
                        ),
                        tooltip=["Severity", "Count"],
                    )
                    .properties(height=180)
                )
                st.altair_chart(chart, use_container_width=True)

    # --- Event volume bar chart ---
    with chart_col2:
        with st.container(border=True):
            _panel_card("expert-volume-chart-panel")
            st.markdown(
                '<h3 class="standard-section-title standard-section-title--compact">Event Volume (48h)</h3>',
                unsafe_allow_html=True,
            )
            try:
                volume_df = db.get_event_volume_timeseries(hours=48)
            except Exception as error:
                st.error("Could not load event volume chart data.")
                st.exception(error)
                volume_df = None

            if volume_df is None:
                pass
            elif volume_df.empty:
                st.info("No events in the last 48 hours.")
            else:
                chart = (
                    alt.Chart(volume_df)
                    .mark_bar(color=THEME_CYAN)
                    .encode(
                        x=alt.X("Hour:N", sort=None, title=""),
                        y=alt.Y("Events:Q", title="Events"),
                        tooltip=["Hour", "Events"],
                    )
                    .properties(height=180)
                )
                st.altair_chart(chart, use_container_width=True)
