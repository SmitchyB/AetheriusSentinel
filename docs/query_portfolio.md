# Aetherius Sentinel: Query Portfolio

## Query 1: Basic SELECT
### Purpose
This query retrieves the core hardware inventory to verify that devices are properly logged with their network assignments and types.
### SQL
SELECT device_id, mac_address, device_name, device_type 
FROM devices;
### Output
device_id ------ mac_address: ------ device_name ---------- device_type
    1     --- 00:1A:2B:3C:4D:5E -- Main Home Gateway -------- Gateway
    2     --- AA:BB:CC:DD:EE:FF - Brett's Workstation ------ Workstation
    3     --- 11:22:33:44:55:66 -- Living Room Roku ---------- Media
    4     --- 77:88:99:AA:BB:CC - Front Door Smart Lock ------- IoT
    5     --- DD:EE:FF:00:11:22 ---- PlayStation 5 ---------- Console
### Explanation
This result shows all the physical assets monitored by Aetherius Sentinel. This data is critical for the AI feature, as it needs to know what type of device (e.g., IoT vs. Console) is associated with an incident to provide accurate mitigation steps.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Query 2: Filtered WHERE Query
### Purpose
This query filters the incidents table to isolate only the highest-priority threats that require immediate attention.
### SQL:
SELECT incident_id, title, severity, status 
FROM incidents 
WHERE severity = 'Critical' OR severity = 'High';
### Output:
incident_id ------------------ title ----------------------- severity ------- status
    2       ------ Repeated Unauthorized Login Attempts ------ High --------- Active
    3       ------ Suspicious Outbound Traffic Surger   ---- Critical ------ Mitigated
### Explanation
This result successfully filters out low-level noise and returns only High and Critical incidents. In the final Streamlit application, this query logic will power the UI filters, allowing users to instantly drill down into the most severe active alerts.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Query 3: ORDER BY or LIMIT Query
### Purpose
This query sorts the most recent network telemetry logs chronologically to build an active threat timeline.
### SQL:
SELECT event_id, timestamp, source_ip, payload_summary 
FROM incident_events 
ORDER BY timestamp DESC 
LIMIT 5;
### Output:
event_id -------- timestamp ----------source_ip --------------------payload_summary
6        --- 2026-05-28 08:45:20 --- 203.0.113.88 --- Failed authentication attempt - Lockout Triggered
5        --- 2026-05-28 08:45:15 --- 203.0.113.88 --- Failed authentication attempt - Invalid Creds
4        --- 2026-05-28 08:45:10 --- 203.0.113.88 --- Failed authentication attempt - Invalid Creds
3        --- 2026-05-28 02:15:03 --- 198.51.100.45 --- SYN packet to port 443 (HTTPS)
2        --- 2026-05-28 02:15:02 --- 198.51.100.45 --- SYN packet to port 80 (HTTP)
### Explanation
By organizing the raw telemetry data from newest to oldest, this query supports the Streamlit application's ability to show the most recent and relevant network traffic first, ensuring older mitigated issues do not bury active attacks.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Query 4: JOIN Query #1
### Purpose
This query demonstrates the foreign key relationship between the incidents table and the devices table, merging the high-level security alert with the specific hardware asset under attack.
### SQL
SELECT 
    incidents.incident_id, 
    incidents.title, 
    devices.device_name, 
    devices.internal_ip 
FROM incidents 
JOIN devices 
    ON incidents.device_id = devices.device_id;
### Output
incident_id ------------ title -------------------------- device_name ------------internal_ip 
1          --- External Port Scan Detected ------------ Main Home Gateway ------- 192.168.1.1
2          --- Repeated Unauthorized Login Attempts --- Front Door Smart Lock --- 192.168.1.20
3          --- Suspicious Outbound Traffic Surge ------ Brett's Workstation ----- 192.168.1.10 
### Explanation
This relationship is the backbone of the interface. The AI feature and the homeowner do not just need to know that an attack happened; they need to know exactly which device is compromised so they can take immediate physical or network isolation steps.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Query 5: JOIN Query #2
### Purpose
This query maps security incidents to specific known threat actor indicators through the incident_indicators junction table.

### SQL
SELECT 
    incidents.title, 
    indicators.indicator_value, 
    indicators.threat_actor_group 
FROM incidents 
JOIN incident_indicators 
    ON incidents.incident_id = incident_indicators.incident_id 
JOIN indicators 
    ON incident_indicators.indicator_id = indicators.indicator_id;
### Output
title --------------------------------- indicator_value --- threat_actor_group
External Port Scan Detected	------------ 198.51.100.45 ----- Unknown Scanner
Repeated Unauthorized Login Attempts --- 203.0.113.88 ---- Mirai Botnet Variant
Suspicious Outbound Traffic Surge ------185.199.108.153 -- Data Exfiltration Node
### Explanation
This proves the many-to-many relationship works. By connecting an incident to a known threat intel feed (like a Mirai Botnet IP), the AI analyst can provide highly specific contextual warnings rather than generic security advice.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Query 6: Aggregation Query
### Purpose
This query uses an aggregate function to sum up the most critical data requiring immediate intervention.
### SQL
SELECT COUNT(*) AS total_critical_incidents 
FROM incidents 
WHERE severity = 'Critical';
### Output
total_critical_incidents
1
### Explanation
Aggregation is vital for the dashboard metrics. This query allows the Streamlit frontend to display a quick warning banner summarizing the total number of critical threats without overwhelming the user with raw data rows.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Query 7: GROUP BY Query
### Purpose
This query groups and summarizes records to give a high-level overview of the network's health by severity tier.
### SQL
SELECT severity, COUNT(*) AS incident_count 
FROM incidents 
GROUP BY severity;
### Output
severity --- incident_count
Critical --- 1
High     --- 1
Medium   --- 1
### Explanation
This grouped data is formatted perfectly to feed directly into a Streamlit bar chart or pie chart, giving the user a visual breakdown of their home network's overall threat landscape at a glance.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Query 8: AI-Support Retrieval Query
### Purpose
This query pulls the exact, comprehensive context file (incident details, the affected device, and a concatenated string of raw event logs) that will be sent to the LLM.
### SQL
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
### Output
incident_id ---------- title ----------------- severity ----- device_name ------- event_logs
1           --- External Port Scan Detected --- Medium --- Main Home Gateway --- SYN packet to port 22 (SSH) | SYN packet to port 80 (HTTP) | SYN packet to port 443(HTTPS)
### Explanation
This is the foundational query for the final project's AI integration. By retrieving a single row that contains the alert, the device, and a compressed timeline of raw payload events, the Python backend can pass a structured, factual evidence file to the AI model, ensuring the generated summary is strictly grounded in database truth.