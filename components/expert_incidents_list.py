"""Expert mode incidents table — re-exports shared ``incidents_list`` for compatibility."""

from components.incidents_list import render_expert_incidents_list

__all__ = ["render_expert_incidents_list"]
