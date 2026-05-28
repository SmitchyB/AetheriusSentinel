-- Enable foreign key constraints in SQLite
PRAGMA foreign_keys = ON;
-- Drop child tables first to prevent foreign key constraint violations
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
    status TEXT CHECK(status IN ('Active', 'Investigating', 'Mitigated', 'False Positive')),
    created_at TEXT NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

--Create incident_events table (child of incidents)
Create TABLE incident_events (
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

--Create recommendations table (Child of incidents)
CREATE TABLE recommendations (
    recommendation_id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL,
    recommendation_text TEXT NOT NULL,
    is_ai_generated INTEGER CHECK(is_ai_generated IN (0, 1)),
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);