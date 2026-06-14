"""
Expert mode security events ticker — scrolling feed of recent incident_events.

Data from get_security_events_ticker() (JOIN events + incidents). Rendered as
HTML/CSS marquee because Streamlit has no native ticker widget.
"""

import html

import streamlit as st

import db

# Map DB severity strings to CSS class suffixes for row accent colors.
_SEVERITY_CLASS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def _format_ticker_time(raw_time: str) -> str:
    """Normalize SQLite timestamp for compact ticker display."""
    text = str(raw_time).strip()
    if len(text) >= 16:
        return text[:16].replace("T", " ")
    return text


def render_expert_security_ticker(content_height: int = 252):
    """
    Render auto-scrolling security event rows in Expert overview top-left panel.

    Args:
        content_height: Viewport height in px — passed to CSS var --expert-ticker-h.
    """
    st.markdown(
        '<h3 class="standard-section-title standard-section-title--compact">Security Events</h3>',
        unsafe_allow_html=True,
    )

    try:
        events_df = db.get_security_events_ticker(limit=25)
    except Exception as error:
        st.error("Could not load security events from the database.")
        st.exception(error)
        return

    if events_df.empty:
        st.info("No security events in the database. Run `python seed.py` to load sample telemetry.")
        return

    # Build HTML rows — content duplicated in track for seamless CSS animation loop.
    ticker_items = []
    for _, row in events_df.iterrows():
        time_str = html.escape(_format_ticker_time(row.get("Time", "")))
        severity_raw = str(row.get("Severity", "")).strip()
        severity_key = _SEVERITY_CLASS.get(severity_raw.lower(), "medium")
        severity = html.escape(severity_raw)
        incident = html.escape(str(row.get("Incident", "")))
        summary = html.escape(str(row.get("Summary", "")))
        ticker_items.append(
            f'<div class="expert-ticker-row severity-{severity_key}">'
            f'<div class="expert-ticker-row__accent"></div>'
            f'<div class="expert-ticker-row__content">'
            f'<div class="expert-ticker-row__head">'
            f'<span class="expert-ticker-time">{time_str}</span>'
            f'<span class="expert-ticker-severity">{severity}</span>'
            f"</div>"
            f'<div class="expert-ticker-incident">{incident}</div>'
            f'<div class="expert-ticker-summary">{summary}</div>'
            f"</div>"
            f"</div>"
        )

    items_html = "".join(ticker_items)
    st.markdown(
        f"""
        <div class="expert-security-events-body">
            <div class="expert-events-ticker" style="--expert-ticker-h: {content_height}px;">
                <div class="expert-events-ticker-fade expert-events-ticker-fade--top"></div>
                <div class="expert-events-ticker-viewport">
                    <div class="expert-events-ticker-track">
                        {items_html}
                        {items_html}
                    </div>
                </div>
                <div class="expert-events-ticker-fade expert-events-ticker-fade--bottom"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
