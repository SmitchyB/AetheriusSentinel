# Streamlit Prototype Notes

Assignment 4.2 documentation for the Aetherius Sentinel Streamlit interface.

---

## Question 1

**What database-backed information does your Streamlit app display?**

The app displays data from the SQLite database at `data/project.db`, retrieved through functions in `db.py`:

- **Devices** — inventory (`get_connected_hardware()`, `get_all_devices()`)
- **Incidents** — title, severity, status, timestamps (`get_incidents_list()`, `get_incidents_filtered()`, `get_incident_by_id()`)
- **Security events** — telemetry rows per incident (`get_incident_events()`, `get_security_events_ticker()`)
- **Aggregations** — device counts, critical incident counts, monthly incident counts, severity breakdowns, event volume, and traffic timeseries
- **Recommendations and actions** — playbooks and completed response steps (`get_recommendations_for_incident()`, `get_incident_actions_list()`)
- **Chat history** — persisted analyst sessions (`get_session_history()`, `get_messages_for_session()`)

Standard mode emphasizes the incident list and chat workflow; Expert mode adds dashboards, filters, charts, and incident detail panels.

---

## Question 2

**What user-controlled filter or selection did you implement?**

In **Expert mode**, the incidents panel uses two `st.selectbox` widgets:

- **Severity** — All, Critical, High, Medium, Low
- **Status** — All, Active, Investigating, Mitigated, False Positive, Trusted

These call `db.get_incidents_filtered(severity=..., status=...)`, which builds a parameterized SQL query.

In **Standard mode**, the incidents table supports **single-row selection** via `st.dataframe(..., on_select="rerun")`, which drives the “Start investigation” / “Open analyst chat” actions for the chosen incident.

---

## Question 3

**Which JOIN query result is displayed in your app, and why is it useful?**

Several JOIN results appear in the UI. A primary example is **`get_incidents_list()`** / **`get_incidents_filtered()`**, which joins `incidents` with `devices` to show each incident alongside the affected device name and IP.

This is useful because security analysts need asset context—not just an alert title—to decide containment scope. The **security events ticker** (`get_security_events_ticker()`) joins `incident_events` with `incidents` so each log line includes severity and incident title. For the future AI feature, **`get_ai_incident_context(incident_id)`** joins incidents, devices, and events (with `GROUP_CONCAT` on payloads) into one evidence row.

---

## Question 4

**Which aggregation or summary result is displayed in your app?**

Expert mode shows multiple aggregation results:

- **KPI cards** — `get_device_count()`, `get_critical_incident_count()`, `get_incidents_this_month_count()` (COUNT queries)
- **Incidents by severity chart** — `get_incidents_by_severity_counts()` (`GROUP BY severity`)
- **Event volume timeseries** — `get_event_volume_timeseries(hours=48)` (hourly `COUNT(*)`)
- **Network traffic chart** — `get_traffic_timeseries()` (hourly counts and summed traffic volume from `incident_events`)

The severity chart is the clearest GROUP BY demonstration for graders: it summarizes how many incidents exist at each severity level.

---

## Question 5

**What data does your detail view retrieve?**

In **Expert mode**, selecting an incident opens the detail view (`components/expert_incident_detail.py`), which loads:

- **`get_incident_by_id(incident_id)`** — full incident row with device fields and primary indicator
- **`get_incident_events(incident_id)`** — chronological security events for that incident
- **`get_ai_incident_context(incident_id)`** — joined evidence bundle (incident + device + concatenated event logs) labeled “AI Analyst Evidence”
- **`get_recommendations_for_incident()`** and **`get_incident_actions_list()`** — playbook text and response history

Standard mode does not use this full detail page; it links the selected incident into the chat workflow instead.

---

## Question 6

**Where is the AI feature integrated, and what database-resident data does it use?**

The AI feature is live in two places:

1. **Sentinel Chat** (Standard panel and Expert drawer) — before each Ollama call, the app appends a **database evidence** chat message built from `ai_service.format_request_evidence_markdown()` (incident context via `assemble_context()` or dashboard context via `assemble_general_context()`). The AI reply appears in a separate message after a two-phase rerun (`process_pending_chat_ai()`).
2. **Expert incident detail — “AI Analyst Evidence”** — shows a **current database snapshot** (`get_ai_incident_context()`, indicators) plus **Evidence by AI request** parsed from persisted chat messages.

Additional evidence for prompts comes from `get_incident_events()`, `get_recommendations_for_incident()`, `get_incident_actions_list()`, and `incident_indicators`.

---

## Question 7

**What is one improvement you plan to make before the final project submission?**

Add inline citations in AI summaries that link back to specific `incident_events` row IDs, and surface those citations in the Expert detail timeline when the user clicks a recommendation line.

---


