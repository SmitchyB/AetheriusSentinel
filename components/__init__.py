"""
UI component package for Aetherius Sentinel.

Overview
--------
Each module under ``components/`` renders one Streamlit panel, widget group, or
layout helper. Components are **presentation-only**: they call ``db.py`` for
SQLite reads/writes and delegate business logic to ``incident_scenarios.py``,
``sentinel_actions.py``, and ``action_catalog.py``. None of the modules here
import ``ai_service.py`` directly — LLM calls are triggered indirectly when
chat handlers (``handle_chat_prompt``, playbook generation) run from
``sentinel_panel`` or ``expert_chat_drawer``.

Entry points (from ``app.py``)
------------------------------
- **Standard mode:** ``standard_dashboard.render_standard_mode()`` composes
  scans, chat history, Sentinel Chat, and incidents table.
- **Expert mode:** ``expert_router.render_expert_mode()`` switches between
  ``expert_overview`` (SOC dashboard) and ``expert_incident_detail`` (single
  incident drill-down).

Shared conventions
------------------
- **CSS marker divs:** Empty ``<div class="...">`` elements injected via
  ``st.markdown(..., unsafe_allow_html=True)`` so ``Assets/*.css`` can style
  the *next* Streamlit widget using sibling/adjacent selectors (Streamlit does
  not expose custom button classes).
- **Session state:** Mode flags (``expert_mode``, ``expert_view``), chat
  (``messages``, ``active_session_id``, ``active_incident_id``), and UI chrome
  (``notifications_open``, ``side_panel_open``) are read/written across modules;
  see each module docstring for its keys.
- **Widget keys:** Must be unique app-wide. Components use prefixes
  (``expert_``, ``standard_``, ``history_card_``) and sometimes revision
  suffixes (``incidents_table_revision``) to avoid collisions on rerun.

Module index (by area)
----------------------
- Layout / theme: ``expert_dashboard``, ``expert_theme``, ``standard_layout_sizer``,
  ``styled_buttons``
- Mode toggles: ``expert_mode_toggle``, ``auto_defense_toggle``
- Standard homeowner UI: ``standard_dashboard``, ``chat_history``, ``sentinel_panel``,
  ``scans``, ``incidents_list``, ``sticky_action_bar``
- Expert SOC UI: ``expert_router``, ``expert_navigation``, ``expert_overview``,
  ``expert_incident_detail``, ``expert_incident_actions``, ``expert_charts``,
  ``expert_security_ticker``, ``expert_notifications``, ``expert_chat_drawer``,
  ``expert_action_form``
- Legacy / utility: ``incident_ui``, ``db_coverage``, ``header_health_badge``
"""
