"""
Shared theme colors for expert-mode Altair charts and panel accents.

Purpose
-------
Centralizes hex color constants so Altair charts (``expert_charts``,
``expert_overview`` network traffic) stay visually aligned with the Expert CSS
theme. **No render functions** — import-only module.

Consumers
---------
- ``expert_charts.render_expert_charts_row`` — severity donut + event volume bar.
- ``expert_overview._render_network_traffic_chart`` — dual-line traffic chart.

Session state / widget keys / CSS markers
-----------------------------------------
- None (pure constants).

db.py / ai_service.py
---------------------
- **Neither.**
"""

# Primary accent — used for event volume bars and general highlights.
THEME_CYAN = "#00A3FF"
THEME_PURPLE = "#8C00FF"
THEME_CYAN_BRIGHT = "#00e5ff"
THEME_ORANGE = "#ff8c42"

# Dual-series network traffic chart (connections vs volume kb).
TRAFFIC_CHART_COLORS = [THEME_CYAN, THEME_PURPLE]

# Donut chart domain order must match color list index-for-index (Altair scale).
SEVERITY_CHART_DOMAIN = ["Critical", "High", "Medium", "Low"]
SEVERITY_CHART_COLORS = [THEME_ORANGE, THEME_PURPLE, THEME_CYAN, THEME_CYAN_BRIGHT]
