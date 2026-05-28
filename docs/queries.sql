SELECT COUNT(*) AS total_devices FROM devices;

SELECT title, severity, status FROM incidents;

SELECT incident_id, COUNT(*) AS event_count 

FROM incident_events 

GROUP BY incident_id;