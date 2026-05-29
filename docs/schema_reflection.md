# Schema Reflection

## 1. What changes, if any, did you make from your ERDC Proposal?
I expanded the `CHECK` constraints on `devices.device_type` to include categories like 'Media', 'Console', and 'IoT'. This prevents the database from accepting unrecognized hardware types and helps the AI better differentiate standard gaming traffic from vulnerable IoT device traffic.

## 2. Which constraints did you include, and why?
I included strict `CHECK` constraints on severity levels (Low, Medium, High, Critical) and incident statuses to prevent invalid data states. I also enforced `UNIQUE` constraints on hardware `mac_address` and `indicator_value` to prevent duplicate asset cloning. Finally, `PRAGMA foreign_keys = ON;` is enforced to maintain strict relational integrity across all tables.

## 3. How does your seed data support future SQL queries?
The Python seed script generates over 20 interconnected records across the core tables, including a many-to-many relationship mapping incidents to specific threat indicators. This provides enough realistic depth to successfully test complex `JOIN` queries, timeline aggregations, and the massive AI evidence retrieval query.

## 4. Which table or field will be most important for your planned AI feature?
The `incident_events.payload_summary` field and the `indicators` table will be the most critical. The AI feature requires highly factual, granular network telemetry (like "SYN packet to port 22") to generate an accurate incident summary and mitigation plan without hallucinating.

## 5. What part of your schema may need revision later?
The raw network traffic logs stored inside `incident_events` will accumulate rapidly in a real-world scenario. Because this project utilizes SQLite, heavy transactional writes mixed with complex multi-table queries could create read/write locks. I may need to implement a data archiving strategy or an indexed view later if performance drops.