"""
Database coverage notes — documents what is DB-backed vs session-only / simulated.

Purpose
-------
Optional developer/grader panel listing integration gaps: which UI features persist
to SQLite vs which are in-memory demos. **Not wired into ``app.py``** by default;
call ``render_db_coverage_notes()`` from a debug expander if needed.

Session state dependencies
--------------------------
- Reads ``active_session_id`` when Expert mode is on (notes unpersisted analyst chat).
- Uses ``incident_scenarios.is_expert_mode()`` for mode check.

Streamlit widget keys
---------------------
- None (markdown bullets only; optional ``st.expander`` when ``compact=True``).

CSS marker divs
---------------
- None.

db.py
-----
- ``db.DB_PATH.exists()`` — drives "missing database" vs "data persists" messaging.

ai_service.py
-------------
- Not imported; notes mention free-form AI chat placeholder until LLM integration
  (actual calls live in ``ai_service`` via ``sentinel_actions`` / ``incident_scenarios``).
"""

import streamlit as st

import db
from incident_scenarios import is_expert_mode


def render_db_coverage_notes(compact: bool = False):
    """
    Show gaps where the UI still relies on in-memory state, not the DB.

    Args:
        compact: If True, wrap notes in a collapsed expander instead of a heading.

    Session state read:
        ``active_session_id`` (Expert mode, for unpersisted chat note).

    db.py:
        Checks ``DB_PATH`` existence only; no aggregation queries.
    """
    gaps = []

    if not db.DB_PATH.exists():
        gaps.insert(0, f"Database file missing at `{db.DB_PATH}` — run `python seed.py`.")
    else:
        gaps.append("Incidents, actions, recommendations, and chat messages persist in SQLite.")
        gaps.append("Playbook progress is derived from `incident_actions` rows.")
        gaps.append("Free-form AI chat still returns a placeholder until LLM integration.")
        gaps.append("Defense actions are simulated — no live firewall/EDR API yet.")
        gaps.append("Auto Defense toggle is UI-only until policy engine is built.")

    if is_expert_mode() and not st.session_state.get("active_session_id"):
        gaps.append("Expert analyst chat without an active session is not persisted.")

    if compact:
        with st.expander("Database coverage notes", expanded=False):
            for note in gaps:
                st.markdown(f"- {note}")
    else:
        st.markdown("**Database coverage**")
        for note in gaps:
            st.markdown(f"- {note}")
