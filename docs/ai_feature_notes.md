# AI Feature Notes — Assignment 5.2

Documentation for the database-backed AI integration in **Aetherius Sentinel**.

---

## AI Feature Summary

**Feature name:** Sentinel Post-Investigation Incident Analyst

**Primary task:** Summarization + recommendation based on retrieved database records.

After a simulated threat scan creates an incident and automated investigation completes, the application:

1. Retrieves incident evidence from SQLite via `db.py`
2. Displays that evidence in the Streamlit UI
3. Sends formatted evidence to a **local Ollama** model (`ai_service.py`)
4. Displays structured AI output **separately** from the source data
5. Persists validated playbook recommendations back to the `recommendations` table

The database remains the **source of truth**. The AI assists the user; it does not invent facts or modify records without explicit application logic.

---

## Architecture

```text
User (Streamlit)
      ↓
app.py + components/
      ↓
incident_scenarios.trigger_scan()  OR  open incident detail
      ↓
db.py  —  parameterized SQL queries
      ↓
Retrieved database evidence (DataFrames / dicts)
      ↓
ai_service.py  —  assemble_context() → prompt → Ollama
      ↓
Validated structured output (AnalysisResult)
      ↓
UI: evidence tables + AI recommendations panel
```

**Module roles**

| File | Role |
|------|------|
| `app.py` | Streamlit entry; wires Standard/Expert layouts |
| `db.py` | All SQL; evidence retrieval functions |
| `ai_service.py` | AI helper module (equivalent to assignment `ai.py`) |
| `incident_scenarios.py` | Scan flow, auto-investigation, calls `analyze_incident` |
| `components/expert_incident_detail.py` | Displays **AI Analyst Evidence** + **AI Recommendations** |
| `components/expert_incident_actions.py` | Renders playbook and authority notices from DB |

---

## Database Evidence Used

For one selected `incident_id`, evidence is drawn from:

| Table | Fields / purpose |
|-------|------------------|
| `incidents` | Title, severity, status, timestamps, monitoring gates |
| `devices` | Device name, type, IP, MAC, owner |
| `incident_events` | Telemetry timeline (source/dest IP, protocol, payload summary) |
| `indicators` + `incident_indicators` | IOCs and confidence scores |
| `incident_actions` | Automated investigation + user response steps |
| `recommendations` | Existing playbook state |
| `incident_updates` | Monitoring/recheck alerts |
| `chat_messages` | Recent analyst conversation on the incident |

---

## Evidence Retrieval (`db.py`)

**Display layer (Expert incident detail):**

- `get_ai_incident_context(incident_id)` — JOIN `incidents` + `devices` + `incident_events`; `GROUP_CONCAT` on event payloads for a compact evidence row shown in the **AI Analyst Evidence** dataframe.

**Full analysis bundle (`ai_service.assemble_context`):**

- `get_incident_by_id(incident_id)`
- `get_ai_incident_context(incident_id)`
- `get_incident_events(incident_id)`
- `get_incident_actions_list(incident_id)`
- `get_incident_indicators(incident_id)`
- `get_recommendations_for_incident(incident_id)`
- `get_active_playbook_recommendation(incident_id)`
- `get_updates_for_incident(incident_id)`
- `get_all_messages_for_incident(incident_id, limit=40)`
- `get_incidents_for_device(device_id, limit=8)` — prior history on same device

All user-supplied IDs bind with `?` placeholders (parameterized queries).

---

## AI Helper (`ai_service.py`)

### Main entry point

`analyze_incident(incident_id)` — called by `incident_scenarios.run_post_investigation_ai_analysis()` after automated investigation.

**Flow:**

1. `check_ai_status()` — verifies Ollama is reachable and model is installed
2. `assemble_context(incident_id)` — bundles DB facts into a dict
3. `_format_context_block(context)` — converts dict to readable text for the prompt
4. System + user messages sent to Ollama via `_chat()` (POST `/api/chat`)
5. `_extract_json()` parses response; `_validate_playbook_keys()` filters against `action_catalog.ACTIONS`
6. Returns `AnalysisResult` with `analysis`, `playbook_action_keys`, `authority_recommended`, `general_recommendations`

### Prompt boundaries

The system prompt instructs the model to:

- Use **only** provided database evidence
- Not invent attack details or resolution steps
- Return JSON with analysis + ordered playbook keys from the catalog
- Not claim real firewall/network changes (prototype is simulated)

### Other AI capabilities (same evidence pattern)

- `answer_chat()` — scoped Q&A (general dashboard vs single incident)
- `generate_incident_report()` — documentation summary from DB evidence
- `generate_resume_briefing()` — session resume from chat + incident state
- `analyze_incident_update()` — re-analysis after monitoring alerts
- `verify_resolution_action()` — caution before non-recommended shortcuts

---

## Streamlit UI: Evidence vs AI Output

**Sentinel Chat** (`components/sentinel_panel.py` + `sentinel_actions.py`):

| Step | Behavior |
|------|----------|
| User message or button | Free-text chat, Get started, next-step guidance, incident report, update re-check |
| Evidence message | `append_evidence_message()` retrieves DB facts via `format_request_evidence_markdown()` and shows **Database evidence used** in chat |
| AI processing | Two-phase rerun: evidence visible first, then spinner while `process_pending_chat_ai()` calls Ollama |
| AI output | Separate assistant message after evidence; in-chat warning to verify against source records |

Evidence messages persist in `chat_messages` with the `[sentinel-evidence]` prefix for incident history.

**Expert mode → Incident detail** (`components/expert_incident_detail.py`):

| Section | Source | Type |
|---------|--------|------|
| **AI Recommendations** | `recommendations` table (written after AI analysis) | AI-generated, validated |
| **Actions Taken** | `incident_actions` table | Database records |
| **AI Analyst Evidence — snapshot** | `get_ai_incident_context()`, `get_incident_indicators()` | Current DB evidence |
| **Evidence by AI request** | Parsed from incident chat log | Per-request evidence blocks |
| **Security Events** | `get_incident_events()` | Raw DB evidence (not AI) |

**Standard mode — scan flow:**

1. User clicks **Run AI Threat Sweep**
2. `trigger_scan()` creates incident + runs auto-investigation
3. Spinner: *"Sentinel is analyzing incident evidence..."*
4. `run_post_investigation_ai_analysis()` → Ollama → playbook saved to DB
5. User opens incident chat; bootstrap shows **evidence message** then cached AI summary + Get started

**Empty / invalid handling:**

- Missing incident → `st.error("Incident ID … not found.")`
- Empty evidence dataframe → `st.warning("No evidence found for this incident.")`
- Ollama offline → detailed error message; no silent fake playbook

**User-facing disclaimer:** In-chat `st.warning` after each evidence block + README AI Disclaimer.

---

## Configuration and Secrets

This project uses **local Ollama** — no cloud API key is required.

Optional environment variables (`.env` in project root; **do not commit**):

```text
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b
AI_ENABLED=true
AI_REQUEST_TIMEOUT=120
PROTOTYPE_MONITOR_MINUTES=3
```

- Values read via `os.getenv()` in `ai_service.py` and `temporal_state.py`
- `python-dotenv` loads `.env` at import time when installed
- `.env` is listed in `.gitignore`

---

## Boundaries and Restrictions

The AI feature **does not**:

- Invent facts absent from database evidence
- Modify the database directly (app code persists recommendations after validation)
- Expose unrelated records (scoped to one `incident_id`)
- Claim real network changes were applied
- Act as final authority (user verifies against displayed evidence)

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Hallucinated attack details | Prompt restricts to evidence; raw events/IOCs shown in UI |
| Incomplete telemetry | Prompt asks model to list missing information; conservative playbook keys |
| Invalid playbook keys | `_validate_playbook_keys()` filters against `action_catalog` |
| User trusts AI without checking | Evidence shown in chat before each AI reply; incident detail lists per-request history |
| Ollama unavailable | `check_ai_status()` + explicit error UI (no silent template playbook) |

---

## Planned Evaluation Cases

1. **Normal** — Full incident with events, IOCs, investigation actions, and AI playbook
2. **Incomplete data** — Incident with minimal events and no indicators
3. **Ambiguous** — Lateral scan scenario without exfiltration evidence (should not recommend sever_connection)
4. **Out of scope** — User asks chat to invent a resolution not in DB (scope rules refuse)
5. **Ollama offline** — Scan completes but AI analysis shows actionable error

---

## Assignment 5.2 Checklist

- [x] Working Streamlit application (`streamlit run app.py`)
- [x] Database-backed record selection (incident list, scan, Expert detail)
- [x] Evidence retrieval via `db.py` (`get_ai_incident_context`, `assemble_context` helpers)
- [x] Database evidence displayed before/alongside AI output
- [x] AI feature uses retrieved evidence (`ai_service.analyze_incident`)
- [x] Structured AI output (summary + playbook + authority flag)
- [x] User-facing warning to verify against source records (README + UI patterns)
- [x] Handling for missing/empty evidence
- [x] No hardcoded API keys (local Ollama + env vars)
- [ ] Video walkthrough (submit separately)

---

## Related Documentation

- `README.md` — setup, run instructions, AI disclaimer
- `docs/streamlit_prototype_notes.md` — Assignment 4.2 UI notes
- `docs/db_access_notes.md` — Assignment 4.1 database layer
