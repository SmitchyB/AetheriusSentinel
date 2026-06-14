"""
Shared theme colors for expert-mode Altair charts and panel accents.

Centralized here so charts and CSS stay visually consistent.
"""

THEME_CYAN = "#00A3FF"
THEME_PURPLE = "#8C00FF"
THEME_CYAN_BRIGHT = "#00e5ff"
THEME_ORANGE = "#ff8c42"

# Dual-series network traffic chart (connections vs volume).
TRAFFIC_CHART_COLORS = [THEME_CYAN, THEME_PURPLE]

# Donut chart domain order must match color list index-for-index.
SEVERITY_CHART_DOMAIN = ["Critical", "High", "Medium", "Low"]
SEVERITY_CHART_COLORS = [THEME_ORANGE, THEME_PURPLE, THEME_CYAN, THEME_CYAN_BRIGHT]
