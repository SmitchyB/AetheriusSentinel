# Aetherius Sentinel: AI Home Cybersecurity Incident Analyst

## Project Description

Aetherius Sentinel is a database-backed cybersecurity incident analyst prototype for the modern smart home. It stores network devices, security incidents, telemetry events, response actions, and analyst chat history in SQLite, and exposes that data through a Streamlit interface in two modes: **Standard** (plain-language, homeowner-focused) and **Expert** (SOC-style dashboard for network admins).

The long-term goal is an AI analyst that summarizes incidents, recommends playbooks, and explains evidence using database-resident telemetry. **That AI layer is not implemented yet.** Chat responses, scan narratives, and playbook text are template-driven or placeholder messages today. Defense actions (isolate device, block IP, etc.) are simulated and recorded in the database only—they do not change a real network.

## Intended Users

- **Primary user:** Homeowners (non-technical) — Standard mode
- **Secondary user:** Home network admins (advanced) — Expert mode

## AI Disclaimer

**No LLM or AI API is connected in this prototype.**

- Free-form chat returns a fixed placeholder message, not a model-generated answer.
- The **AI Analyst Evidence** table and `get_ai_incident_context()` in `db.py` prepare database evidence for a *future* AI feature; they do not call an AI service.
- Scan buttons simulate new incidents from seeded scenario templates; they do not run live network or AI analysis.
- Do not configure or submit API keys expecting AI behavior—the `.env` / `AI_API_KEY` step below is reserved for a later phase of the project.

Always verify any summary or recommendation against the raw database tables (incidents, events, actions) shown in the app.

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

### 4. Run the Streamlit prototype

```bash
streamlit run app.py
```

Open the local URL shown in the terminal (typically `http://localhost:8501`).

### 5. Future AI configuration (not active yet)

When AI integration is added in a later assignment, you will create a `.env` file in the project root:

```bash
AI_API_KEY=your_key_here
```

**Do not commit real API keys or `.env` to version control.** This step is documented for the final project direction only; the current app does not read or use `AI_API_KEY`.

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
5. **Sentinel Chat** — Guided incident workflow plus a text box for free-form questions. **Free-form input returns a placeholder reply only**—there is no AI backend.

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
   - Summary, security events, **AI Analyst Evidence** (DB context for future AI—display only today)
   - Recommendations, actions taken, response action buttons
3. **Analyst chat drawer (☰)** — Side panel for incident-linked chat; same placeholder behavior for unstructured prompts.

To return to the overview from incident detail, use the back/navigation control in that view.

---

## Project Structure

```text
Aetherius Sentinel/
  README.md
  requirements.txt
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
User → Streamlit (app.py + components/) → db.py → SQL → data/project.db
```

---

## Assignment Checklist (Streamlit prototype)

This prototype satisfies the course Streamlit database assignment when demonstrated with Expert mode enabled for filters, JOINs, aggregations, and detail view:

- Database-backed tables and KPIs
- User-controlled filters (Expert: severity / status)
- JOIN results (e.g. incidents with devices, events with incidents)
- Aggregation / GROUP BY (severity counts, event volume, traffic timeseries)
- Detail view (Expert incident detail + AI evidence preview)
- Future AI placeholder (chat placeholder + evidence query; no model calls)

See `docs/streamlit_prototype_notes.md` for a written walkthrough of each item.

---

## Known Limitations

- **No AI/LLM integration** — placeholders and templates only
- **No live network monitoring** — telemetry comes from `seed.py` and scenario templates when scans run
- **Simulated response actions** — results are text records in SQLite, not firewall or EDR changes
- **Auto Defense toggle** — visual state only
- Mitigation suggestions must be verified against raw database evidence; the app does not replace human judgment

---

## Documentation

- `docs/db_access_notes.md` — Python database access layer (Assignment 4.1)
- `docs/streamlit_prototype_notes.md` — Streamlit prototype design notes (Assignment 4.2)
- `docs/query_portfolio.md` — SQL query portfolio
