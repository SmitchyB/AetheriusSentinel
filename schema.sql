-- Enable foreign key constraints in SQLite
PRAGMA foreign_keys = ON;
-- Drop child tables first to prevent foreign key constraint violations
DROP TABLE IF EXISTS chat_messages;
DROP TABLE IF EXISTS incident_actions;
DROP TABLE IF EXISTS incident_updates;
DROP TABLE IF EXISTS incident_indicators;
DROP TABLE IF EXISTS recommendations;
DROP TABLE IF EXISTS incident_events;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS indicators;
DROP TABLE IF EXISTS devices;

--Create device table (Parent)
CREATE TABLE devices (
    device_id INTEGER PRIMARY KEY,
    mac_address TEXT UNIQUE NOT NULL,
    device_name TEXT,
    device_type TEXT CHECK(device_type IN ('IoT', 'Mobile', 'Workstation', 'Server', 'Gateway', 'Console', 'Network', 'Media', 'Other')),
    internal_ip TEXT,
    owner_name TEXT
);

--Create incidents table (Child of devices, Parent to incident_events and recommendations)
CREATE TABLE incidents (
    incident_id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
    status TEXT CHECK(status IN ('Active', 'Investigating', 'Mitigated', 'False Positive', 'Trusted')),
    created_at TEXT NOT NULL,
    acknowledged_at TEXT,
    monitor_until TEXT,
    authority_recommended INTEGER DEFAULT 0,
    chat_session_id TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);
CREATE INDEX idx_incidents_chat_session ON incidents(chat_session_id);

--Create incident_events table (child of incidents)
CREATE TABLE incident_events (
    event_id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    payload_summary TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

--Create indicators table (Parent to junction table incident_indicators)
CREATE TABLE indicators (
    indicator_id INTEGER PRIMARY KEY,
    indicator_value TEXT NOT NULL,
    indicator_type TEXT,
    threat_actor_group TEXT,
    confidence_score INTEGER
);

--Create incident_indicators table(Many-to-many junction table between incidents and indicators)
CREATE TABLE incident_indicators (
    incident_id INTEGER NOT NULL,
    indicator_id INTEGER NOT NULL,
    PRIMARY KEY (incident_id, indicator_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
    FOREIGN KEY (indicator_id) REFERENCES indicators(indicator_id)
);

--Create chat_messages table (conversation threads, optionally linked to incidents)
CREATE TABLE chat_messages (
    message_id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL,
    incident_id INTEGER,
    role TEXT NOT NULL CHECK(role IN ('user', 'assistant', 'system')),
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);
CREATE INDEX idx_chat_messages_session ON chat_messages(session_id);
CREATE INDEX idx_chat_messages_incident ON chat_messages(incident_id);

--Create recommendations table (Child of incidents)
CREATE TABLE recommendations (
    recommendation_id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL,
    recommendation_text TEXT NOT NULL,
    is_ai_generated INTEGER CHECK(is_ai_generated IN (0, 1)),
    recommendation_type TEXT NOT NULL DEFAULT 'general'
        CHECK(recommendation_type IN ('general', 'playbook', 'authority_notice')),
    playbook_actions_json TEXT,
    display_order INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

-- Actions taken on incidents (auto investigation + manual response)
CREATE TABLE incident_actions (
    action_id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL,
    action_key TEXT NOT NULL,
    action_category TEXT NOT NULL
        CHECK(action_category IN ('investigation', 'containment', 'eradication', 'post_incident')),
    status TEXT NOT NULL DEFAULT 'completed'
        CHECK(status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    payload_json TEXT,
    result_summary TEXT,
    is_automated INTEGER DEFAULT 0,
    is_recommended INTEGER DEFAULT 0,
    playbook_order INTEGER,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);
CREATE INDEX idx_incident_actions_incident ON incident_actions(incident_id);

-- Pending update alerts for in-progress incidents (monitoring complete, etc.)
CREATE TABLE incident_updates (
    update_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    update_type TEXT NOT NULL,
    title TEXT NOT NULL,
    summary_text TEXT,
    payload_json TEXT,
    created_at TEXT NOT NULL,
    acknowledged_at TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);
CREATE INDEX idx_incident_updates_incident ON incident_updates(incident_id);
CREATE INDEX idx_incident_updates_pending ON incident_updates(incident_id, acknowledged_at);
