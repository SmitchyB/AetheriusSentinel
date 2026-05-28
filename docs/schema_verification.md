# Schema Verification

## Query 1: Total Devices
This query verifies that the primary hardware assets were successfully seeded into the database. 
## SQL:
SELECT COUNT(*) AS total_devices 
FROM devices;
## Output: 
total_devices: 5

------------------------------------------------------------------------------------------------------------------------------------------------------

## Query 2: Seeded Incidents
This query verifies that the core security alerts were generated and correctly assigned severity levels.
## SQL:
SELECT title, severity, status 
FROM incidents;
## Output:
Title: External Port Scan Detected --- Severity: Medium --- Status: Investigating
Title: Repeated Unauthorized Login Attempts --- Severity: High --- Status: Active
Title: Suspicious Outbound Traffic Surge --- Severity: Critical --- Status: Mitigated

------------------------------------------------------------------------------------------------------------------------------------------------------

## Query 3: Event Counts per Incident
This query checks the foreign key relationship between incidents and their raw telemetry logs, ensuring each incident has associated events.
## SQL:
SELECT incident_id, COUNT(*) AS event_count 
FROM incident_events 
GROUP BY incident_id;
## Output
incident_id: 1 event_count: 3
incident_id: 2 event_count: 3
incident_id: 3 event_count: 2