# Aetherius Sentinel: AI Home Cybersecurity Incident Analyst

## Project Description

Aetherius Sentinel is a database-backed cybersecurity incident analyst prototype for the modern smart home. It stores network devices, security incidents, telemetry events, response actions, and analyst chat history in SQLite, and exposes that data through a Streamlit interface in two modes: **Standard** (plain-language, homeowner-focused) and **Expert** (SOC-style dashboard for network admins).

**A local Ollama integration (`llama3.1:8b`) powers post-investigation analysis, guided chat, resume/summarize, and incident report generation.** The AI reads evidence retrieved from the database—not user-typed text—and returns summaries and playbook recommendations. Defense actions (isolate device, block IP, etc.) are simulated and recorded in the database only; they do not change a real network.

## Intended Users

- **Primary user:** Homeowners (non-technical) — Standard mode
- **Secondary user:** Home network admins (advanced) — Expert mode

## Highlights

- **Layered architecture** — UI (`app.py` + `components/`) → orchestration (`incident_scenarios.py`, `sentinel_actions.py`) → AI helper (`ai_service.py`) → data access (`db.py`) → SQLite. No raw SQL outside `db.py`.
- **Evidence-grounded AI** — a local LLM (Ollama) reads facts retrieved from the database, not user-typed prose; every AI reply is preceded by the database evidence that produced it.
- **Two distinct UX modes** from one data layer — plain-language Standard mode for homeowners and a SOC-style Expert dashboard for admins.
- **Defensive SQL** — all user-driven queries are parameterized; schema migrations are idempotent and run on every connection.
- **Honest failure modes** — when Ollama is offline or returns invalid output, the app surfaces a real error instead of a silent fake playbook.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.13 |
| UI | Streamlit |
| Data | SQLite (`sqlite3`) + pandas |
| AI | Local LLM via [Ollama](https://ollama.com) (`llama3.1:8b`) |
| Config | `python-dotenv` (`.env`) |

## How It Works (60 seconds)

1. A simulated **scan** creates an incident in SQLite.
2. **Automated investigation** (`fingerprint_device`, `ping_sweep`) records events and IOCs.
3. **Ollama reads the database evidence** for that incident and writes a recommended playbook.
4. The user is **guided through containment/eradication** via chat and a sticky action bar.
5. A **report** is generated from database evidence, and future sessions can resume or summarize.

## AI Disclaimer

**Sentinel uses a local LLM via Ollama** (default model: `llama3.1:8b`). No cloud API key is required. **Playbooks are AI-generated only** — Ollama must be running with the configured model installed.

- After a scan creates an incident, automated investigation runs, then **Ollama analyzes full DB evidence** and writes a recommended playbook.
- If Ollama is offline, misconfigured, or returns invalid JSON, the app shows a **detailed error** (no silent template playbook).
- Free-form chat stays enabled while the **sticky action bar** shows the next recommended step plus Trust / False alarm / Skip to documentation shortcuts.
- Non-recommended resolution actions may require **AI verification** before execute on higher-severity incidents.
- Response actions remain **simulated**—the AI recommends and narrates; it does not change a real network.
- **Always verify** summaries and recommendations against raw database tables (incidents, events, actions) shown in the app.
- **Sentinel Chat** inserts a **database evidence** message before each AI reply so you can see what was retrieved for that specific question or action.

---

## Setup and Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Rebuild the database

```bash
python seed.py
```

Creates `data/project.db` from `schema.sql` and loads sample devices, incidents, and telemetry.

### 3. Configure AI access (local Ollama)

1. Install [Ollama](https://ollama.com) and pull the model:

```bash
ollama pull llama3.1:8b
```

2. Keep Ollama running while using Sentinel.

3. Optional — create a `.env` file in the project root:

```text
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b
AI_ENABLED=true
AI_REQUEST_TIMEOUT=120
PROTOTYPE_MONITOR_MINUTES=3
```

**Do not commit or submit your real `.env` file.**

| Variable | Default | Purpose |
|----------|---------|---------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama HTTP API |
| `OLLAMA_MODEL` | `llama3.1:8b` | Model used for analysis and chat |
| `AI_ENABLED` | `true` | Set `false` to disable all AI calls |
| `AI_REQUEST_TIMEOUT` | `120` | Seconds before an Ollama request times out |
| `PROTOTYPE_MONITOR_MINUTES` | `3` | Demo compression for enhanced monitoring windows |

### 4. Run the app

```bash
streamlit run app.py
```

Open the local URL shown in the terminal (typically `http://localhost:8501`).

### 5. Demonstrate the AI feature

**Quick path (Expert mode):**

1. Turn **Expert mode** on in the header.
2. Click **Run AI Threat Sweep** on the overview dashboard.
3. Wait for automated investigation and AI analysis (spinner: *Sentinel is analyzing incident evidence…*).
4. Open the new incident detail view and confirm:
   - **AI Analyst Evidence** — database evidence dataframe (`get_ai_incident_context`)
   - **Security Events** — raw telemetry from `incident_events`
   - **AI Recommendations** — summary and playbook from Ollama (stored in `recommendations`)

**Standard mode** follows the same AI pipeline after a scan; the guided chat and sticky action bar consume the AI-generated playbook.

### What the AI feature does

| Step | What happens |
|------|----------------|
| Select / create incident | Scan or pick from incidents table |
| Retrieve evidence | `db.py` parameterized queries + `ai_service.assemble_context()` |
| Display evidence | Chat: per-request **Database evidence used** message; Expert detail: snapshot + **Evidence by AI request** history |
| Send to model | `ai_service.analyze_incident()` / `answer_chat()` → local Ollama |
| Display AI output | Chat assistant reply and **AI Recommendations** panel (separate from evidence) |

See `docs/ai_feature_notes.md` for architecture, prompt boundaries, risks, and the Assignment 5.2 checklist.

---

## Setup and Installation (full)

### Test the database access layer

```bash
python db.py
```

You should see sample output for devices, incidents, and session history.

### Alerts (two tiers)

The header **Alerts** bell shows:

1. **New alerts** — unacknowledged `Active` incidents from scans.
2. **Incident updates** — in-progress cases needing attention (e.g. **monitoring complete**). Clicking an update re-runs investigation, summarizes changes with AI, and unlocks the next playbook step.

### Incident lifecycle (AI-assisted)

1. **Detection** — Manual scan creates an incident in SQLite.
2. **Auto-investigation** — `fingerprint_device` and `ping_sweep` run automatically; events and IOCs are stored.
3. **AI analysis** — Ollama reads DB evidence and writes the recommended playbook.
4. **Guided response** — Chat and action bar walk through containment and eradication.
5. **Documentation** — **Generate incident report** produces an AI-written summary from DB evidence.
6. **Resume** — New chat sessions offer **Summarize past sessions** or **Where we left off**.

---

## Using the Application

### Header controls (both modes)

| Control | Purpose |
|--------|---------|
| **Health badge** | Overall status derived from open incident severities in the database |
| **Expert mode toggle** | Switch between Standard and Expert layouts |
| **Auto Defense** | UI toggle only; no automated policy engine wired up yet |
| **Alerts bell** | Lists open incidents from the database |
| **☰ (Expert only)** | Opens the Sentinel Analyst chat drawer |

### Standard mode (default)

1. **Scans** — **Run AI Threat Sweep** or **Scan Active Connections** (simulated; not live network probes).
2. **Incidents** — Table of all incidents. Click a row to select one.
3. **Start investigation / Open analyst chat** — Chat session linked to that incident; actions write to `incident_actions`.
4. **Chat History** — Resume past sessions from `chat_messages`.
5. **Sentinel Chat** — Guided workflow plus Ollama-backed Q&A when running.

### Expert mode

1. **Overview dashboard** — KPIs, security events ticker, hardware inventory, filterable incidents, charts, traffic timeseries.
2. **Incident detail** — Summary, **AI Recommendations**, actions taken, **AI Analyst Evidence**, security events, response buttons.
3. **Analyst chat drawer (☰)** — Incident-linked chat with Ollama-backed Q&A.

---

## Project Structure

```text
Aetherius Sentinel/
  README.md
  requirements.txt
  app.py                  # Streamlit entry point (wiring + mode routing only)
  db.py                   # Database access layer (all SQL lives here)
  ai_service.py           # AI helper module (prompts, Ollama calls, validation)
  incident_scenarios.py   # Scan flow, auto-investigation, AI analysis orchestration
  sentinel_actions.py     # Chat orchestration, intent detection, message persistence
  action_catalog.py       # Registry of response actions + playbook generation
  scenario_telemetry.py   # Scripted incident-event and IOC templates
  temporal_state.py       # Monitoring windows / demo time-compression gates
  chat_sessions.py        # Loads a DB chat session into Streamlit state
  seed.py                 # Builds data/project.db from schema.sql + sample data
  seed_narrative.py       # Seeds synchronized chat transcripts + action history
  schema.sql              # Database schema (tables, constraints, indexes)
  data/
    project.db            # Created by seed.py
  components/             # ~27 UI modules; call db.py, no raw SQL in app.py
                          #   expert_*    Expert (SOC) dashboard panels
                          #   standard_*  Standard (homeowner) layout
                          #   shared      chat_history, scans, sentinel_panel, etc.
  docs/
    ai_feature_notes.md          # AI database integration design (5.2)
    streamlit_prototype_notes.md # Streamlit prototype design notes (4.2)
    db_access_notes.md           # Python database access layer notes (4.1)
    schema_reflection.md         # Data-model design rationale
    schema_verification.md       # Schema validation checks
    query_portfolio.md           # SQL query portfolio (annotated)
    queries.sql                  # Raw SQL portfolio source
```

Architecture:

```text
User → Streamlit (app.py + components/)
         → incident_scenarios.py / sentinel_actions.py   (orchestration)
             → ai_service.py → Ollama (local LLM)
             ↘ db.py → SQL → data/project.db
```

---

## Assignment Checklists

### Streamlit prototype (4.2)

- Database-backed tables and KPIs
- User-controlled filters (Expert: severity / status)
- JOIN results (incidents with devices, events with incidents)
- Aggregation / GROUP BY (severity counts, event volume, traffic timeseries)
- Detail view (Expert incident detail + AI evidence preview)

See `docs/streamlit_prototype_notes.md`.

### AI database integration (5.2)

- [x] Working Streamlit application
- [x] Database-backed record selection
- [x] Evidence retrieval via `db.py`
- [x] Database evidence displayed alongside AI output
- [x] AI feature uses retrieved evidence (`ai_service.py`)
- [x] Structured AI output + verification disclaimer
- [x] Missing/empty evidence handling
- [x] No hardcoded API keys (local Ollama + `.env`)
- [ ] Video walkthrough (submit separately)

See `docs/ai_feature_notes.md`.

---

## Known Limitations

- **Local AI only** — requires Ollama running; shows errors when unavailable (no fake playbooks)
- **No live network monitoring** — telemetry from `seed.py` and scenario templates when scans run
- **Simulated response actions** — results are text records in SQLite, not firewall or EDR changes
- **Auto Defense toggle** — visual state only
- Mitigation suggestions must be verified against raw database evidence; the app does not replace human judgment

---

## Documentation

- `docs/ai_feature_notes.md` — AI database integration: architecture, prompt boundaries, risks
- `docs/streamlit_prototype_notes.md` — Streamlit prototype design notes (data displayed, filters, joins, aggregations)
- `docs/db_access_notes.md` — Python database access layer (connection handling, parameterized queries)
- `docs/schema_reflection.md` — Data-model design rationale
- `docs/schema_verification.md` — Schema validation checks
- `docs/query_portfolio.md` — Annotated SQL query portfolio
- `docs/queries.sql` — Raw SQL portfolio source

> Course context: this project was built for a database course; the per-assignment
> checklists above map features to those deliverables. The code and architecture are
> written to stand on their own as a portfolio piece.
