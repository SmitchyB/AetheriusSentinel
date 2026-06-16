"""
Expert mode incidents table — re-exports shared ``incidents_list`` for compatibility.

Purpose
-------
Thin compatibility shim so older imports like
``from components.expert_incidents_list import render_expert_incidents_list``
keep working. The real implementation lives in ``incidents_list.py`` with
``mode="expert"``.

Navigation
----------
``expert_overview`` → ``render_expert_incidents_list()`` → ``render_incidents_list(mode="expert")``.
Row selection auto-navigates to incident detail via ``navigate_to_incident_detail``.

db.py
-----
Delegated to ``incidents_list``: ``db.get_incidents_filtered()``, etc.

ai_service.py
-------------
- **Not used** (no chat on table row select in Expert mode).
"""

from components.incidents_list import render_expert_incidents_list

__all__ = ["render_expert_incidents_list"]
