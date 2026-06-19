# Database Access Layer Notes

Design notes for `db.py`, the single module through which the app reads and writes SQLite.

## Connecting to the database
The layer uses the built-in `sqlite3` library to open a connection via `sqlite3.connect(DB_PATH)`, and sets `conn.row_factory = sqlite3.Row` so columns are accessed by name rather than numeric index. This keeps query results self-documenting and robust to column-order changes.

## Why pandas for query results
Read-heavy functions use `pd.read_sql_query()` instead of manually iterating raw cursor tuples. It executes the query and returns a clean DataFrame, which Streamlit renders directly into UI tables with minimal glue code.

## Parameterized queries and injection safety
Functions such as `get_incidents_by_severity(severity_level)` use `?` placeholders in the SQL string and bind values via `params=(severity_level,)`. For a cybersecurity application, preventing SQL injection is essential: parameterization ensures UI-supplied input is always treated as data, never as executable SQL.

## The key query for the AI feature
`get_ai_incident_context(incident_id)` is the most important query for AI grounding. It `JOIN`s the incident with its device, then uses `GROUP_CONCAT` to compress all related telemetry into a single evidence string. This gives the LLM factual database evidence to summarize rather than room to hallucinate network events.

## Setup notes
`pandas` is a required dependency (a missing install surfaces as `ModuleNotFoundError: No module named 'pandas'`). It is pinned in `requirements.txt` so the environment is reproducible via `pip install -r requirements.txt`.