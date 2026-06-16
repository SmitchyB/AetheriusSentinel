# Aetherius Sentinel: AI Home Cybersecurity Incident Analyst

## Project Description

Aetherius Sentinel is a database-backed cybersecurity incident analyst prototype for the modern smart home. It stores network devices, security incidents, telemetry events, response actions, and analyst chat history in SQLite, and exposes that data through a Streamlit interface in two modes: **Standard** (plain-language, homeowner-focused) and **Expert** (SOC-style dashboard for network admins).

The long-term goal is an AI analyst that summarizes incidents, recommends playbooks, and explains evidence using database-resident telemetry. **A local Ollama integration (`llama3.1:8b`) powers post-investigation analysis, guided chat, resume/summarize, and incident report generation.** Defense actions (isolate device, block IP, etc.) are simulated and recorded in the database only—they do not change a real network.

## Intended Users

- **Primary user:** Homeowners (non-technical) — Standard mode
- **Secondary user:** Home network admins (advanced) — Expert mode

## AI Disclaimer

**Sentinel uses a local LLM via Ollama** (default model: `llama3.1:8b`). No cloud API key is required. **Playbooks are AI-generated only** — Ollama must be running with the configured model installed.

- After a scan creates an incident, automated investigation runs, then **Ollama analyzes full DB evidence** and writes a recommended playbook.
- If Ollama is offline, misconfigured, or returns invalid JSON, the app shows a **detailed error** (no silent template playbook).
- Free-form chat stays enabled while the **sticky action bar** shows the next recommended step plus Trust / False alarm / Skip to documentation shortcuts.
- Non-recommended resolution actions may require **AI verification** before execute on higher-severity incidents.
- Response actions remain **simulated**—the AI recommends and narrates; it does not change a real network.
- Always verify summaries and recommendations against raw database tables (incidents, events, actions) shown in the app.

### Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API base URL |
| `OLLAMA_MODEL` | `llama3.1:8b` | Model used for analysis and chat |
| `AI_ENABLED` | `true` | Set `false` to disable all AI calls |
| `AI_REQUEST_TIMEOUT` | `120` | Seconds before an Ollama request times out |
| `PROTOTYPE_MONITOR_MINUTES` | `3` | Demo compression for enhanced monitoring windows |

---

## Setup and Installation

### 1. Install dependencies

Activate your virtual environment, then install required packages:

```bash
pip install -r requirements.txt
```

### 2. Build and seed the database

Create the SQLite database, apply the schema, and load sample data:

```bash
python seed.py
```

The database is written to: `data/project.db`

If `data/project.db` is missing, the app will show an error until you run this command.

### 3. Test the database access layer

Verify Python can connect and run queries:

```bash
python db.py
```

You should see sample output for devices, incidents, and session history.

### 4. Install and configure Ollama (AI analyst)

1. Install [Ollama](https://ollama.com) and pull the model:

```bash
ollama pull llama3.1:8b
```

2. Keep Ollama running while using Sentinel (desktop app or background service).

3. Optional: copy environment defaults:

```bash
copy .env.example .env
```

Settings in `.env`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama HTTP API |
| `OLLAMA_MODEL` | `llama3.1:8b` | Model tag |
| `AI_ENABLED` | `true` | Set `false` to force template fallbacks |
| `AI_REQUEST_TIMEOUT` | `120` | Seconds per AI request |
| `PROTOTYPE_MONITOR_MINUTES` | `3` | Real wait before monitoring-gated steps unlock (narrative still shows e.g. 36h) |

**Do not commit `.env` to version control.**

### Alerts (two tiers)

The header **Alerts** bell shows:

1. **New alerts** — unacknowledged `Active` incidents from scans.
2. **Incident updates** — in-progress cases needing attention (e.g. **monitoring complete**). Clicking an update re-runs investigation, summarizes changes with AI, and unlocks the next playbook step.

### 5. Run the Streamlit prototype

```bash
streamlit run app.py
```

Open the local URL shown in the terminal (typically `http://localhost:8501`).

### Incident lifecycle (AI-assisted)

1. **Detection** — Manual scan (or future passive ingest) creates an incident.
2. **Auto-investigation** — `fingerprint_device` and `ping_sweep` run automatically; events and IOCs are stored in SQLite.
3. **AI analysis** — Ollama reads DB evidence and writes the recommended playbook (automatic after scan).
4. **Guided response** — Chat walks through containment and eradication with action buttons; free-form Q&A is supported.
5. **Documentation** — Skip remaining steps if needed, then **Generate incident report** produces an AI-written summary.
6. **Resume** — New chat sessions offer **Summarize past sessions** or **Where we left off**.

---

## Using the Application

### Header controls (both modes)

| Control | Purpose |
|--------|---------|
| **Health badge** | Overall status derived from open incident severities in the database |
| **Expert mode toggle** | Switch between Standard and Expert layouts |
| **Auto Defense** | UI toggle only; no automated policy engine is wired up yet |
| **Alerts bell** | Lists open incidents from the database |
| **☰ (Expert only)** | Opens the Sentinel Analyst chat drawer |

### Standard mode (default)

Designed for homeowners. On launch, Expert mode is **off**.

1. **Scans** — **Run AI Threat Sweep** or **Scan Active Connections** picks a demo scenario, creates a new incident in the database, and opens a guided chat flow. (These are simulated scans, not live network probes.)
2. **Incidents** — Table of all incidents (joined with device names). Click a row to select one.
3. **Start investigation / Open analyst chat** — Begins a chat session linked to that incident. Playbook steps appear as chat buttons; completing actions writes to `incident_actions` in the database.
4. **Chat History** — Resume past sessions loaded from `chat_messages`.
5. **Sentinel Chat** — Guided incident workflow plus free-form questions answered by the local Ollama analyst (when running).

### Expert mode

Designed for network admins. Turn **Expert mode** on in the header.

1. **Overview dashboard**
   - KPI cards: device count, critical open incidents, incidents this month (aggregations from the database)
   - **Security Events** ticker — recent events joined with incident context
   - **Connected Hardware** — full device inventory
   - **Incidents** — filterable table (severity and status `selectbox` widgets)
   - **Charts** — incidents by severity, event volume over time (GROUP BY results)
   - **Network Traffic** — hourly aggregation from `incident_events`
2. **Incident detail** — Click a row in the incidents table to open detail view:
   - Summary, security events, **AI Analyst Evidence** (DB context used to ground the model)
   - Recommendations, actions taken, response action buttons
3. **Analyst chat drawer (☰)** — Side panel for incident-linked chat with Ollama-backed Q&A.

To return to the overview from incident detail, use the back/navigation control in that view.

---

## Project Structure

```text
Aetherius Sentinel/
  README.md
  requirements.txt
  ai_service.py       # Ollama integration (analysis, chat, reports)
  app.py              # Streamlit entry point
  db.py               # Database access layer (all SQL lives here)
  schema.sql
  seed.py
  data/
    project.db        # Created by seed.py (not required in repo if rebuild instructions are followed)
  components/         # UI modules; call db.py, no raw SQL in app.py
  docs/
    db_access_notes.md
    streamlit_prototype_notes.md
    query_portfolio.md
```

Architecture:

```text
User → Streamlit (app.py + components/) → ai_service.py → Ollama
                                      ↘ db.py → SQL → data/project.db
```

---

## Assignment Checklist (Streamlit prototype)

This prototype satisfies the course Streamlit database assignment when demonstrated with Expert mode enabled for filters, JOINs, aggregations, and detail view:

- Database-backed tables and KPIs
- User-controlled filters (Expert: severity / status)
- JOIN results (e.g. incidents with devices, events with incidents)
- Aggregation / GROUP BY (severity counts, event volume, traffic timeseries)
- Detail view (Expert incident detail + AI evidence preview)
- AI analyst via local Ollama (analysis, chat, reports; template fallback when offline)

See `docs/streamlit_prototype_notes.md` for a written walkthrough of each item.

---

## Known Limitations

- **Local AI only** — requires Ollama running; falls back to templates when unavailable
- **No live network monitoring** — telemetry comes from `seed.py` and scenario templates when scans run
- **Simulated response actions** — results are text records in SQLite, not firewall or EDR changes
- **Auto Defense toggle** — visual state only
- Mitigation suggestions must be verified against raw database evidence; the app does not replace human judgment

---

## Documentation

- `docs/db_access_notes.md` — Python database access layer (Assignment 4.1)
- `docs/streamlit_prototype_notes.md` — Streamlit prototype design notes (Assignment 4.2)
- `docs/query_portfolio.md` — SQL query portfolio
