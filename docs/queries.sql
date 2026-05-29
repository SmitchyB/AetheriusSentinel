-- Assignment 3.1 Queries

SELECT COUNT(*) AS total_devices FROM devices;

SELECT title, severity, status FROM incidents;

SELECT incident_id, COUNT(*) AS event_count 

FROM incident_events 

GROUP BY incident_id;

-- Assignment 3.2 Queries

-- Query 1: Basic SELECT
-- Retrieves the core hardware inventory.
SELECT device_id, mac_address, device_name, device_type 
FROM devices;

-- Query 2: Filtered WHERE Query
-- Filters the incidents table to isolate only the highest-priority threats.
SELECT incident_id, title, severity, status 
FROM incidents 
WHERE severity = 'Critical' OR severity = 'High';

-- Query 3: ORDER BY or LIMIT Query
-- Sorts the most recent network telemetry logs chronologically to build a timeline.
SELECT event_id, timestamp, source_ip, payload_summary 
FROM incident_events 
ORDER BY timestamp DESC 
LIMIT 5;

-- Query 4: JOIN Query #1
-- Connects incidents to the actual physical hardware.
SELECT 
    incidents.incident_id, 
    incidents.title, 
    devices.device_name, 
    devices.internal_ip 
FROM incidents 
JOIN devices 
    ON incidents.device_id = devices.device_id;

-- Query 5: JOIN Query #2
-- Maps incidents to specific known threat actor indicators through the junction table.
SELECT 
    incidents.title, 
    indicators.indicator_value, 
    indicators.threat_actor_group 
FROM incidents 
JOIN incident_indicators 
    ON incidents.incident_id = incident_indicators.incident_id 
JOIN indicators 
    ON incident_indicators.indicator_id = indicators.indicator_id;

-- Query 6: Aggregation Query
-- Uses an aggregate function to sum up critical data.
SELECT COUNT(*) AS total_critical_incidents 
FROM incidents 
WHERE severity = 'Critical';

-- Query 7: GROUP BY Query
-- Groups and summarizes records to give a high-level overview of the network's health.
SELECT severity, COUNT(*) AS incident_count 
FROM incidents 
GROUP BY severity;

-- Query 8: AI-Support Retrieval Query
-- Pulls the exact context (incident details, the affected device, and raw event logs) for the AI prompt.
SELECT 
    incidents.incident_id, 
    incidents.title, 
    incidents.severity, 
    devices.device_name, 
    GROUP_CONCAT(incident_events.payload_summary, ' | ') AS event_logs
FROM incidents
JOIN devices 
    ON incidents.device_id = devices.device_id
LEFT JOIN incident_events 
    ON incidents.incident_id = incident_events.incident_id
WHERE incidents.incident_id = 1
GROUP BY 
    incidents.incident_id, 
    incidents.title, 
    incidents.severity, 
    devices.device_name;