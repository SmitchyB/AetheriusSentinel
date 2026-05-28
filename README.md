# Aetherius Sentinel: AI Home Cybersecurity Incident Analyst

## Project Description
Aetherius Sentinel is a database-backed AI application built with Python, SQLite, and Streamlit. It serves as a comprehensive cybersecurity incident analyst for the modern smart home, translating complex network telemetry into plain-language summaries and actionable safety recommendations.

## Intended Users
* **Primary User:** Homeowners (Non-Technical)
* **Secondary User:** Home Network Admins (Advanced)

## Setup and Installation

### 1. Install Dependencies
Activate your virtual environment, then install the required packages:
pip install -r requirements.txt

### 2. Build and Seed the Database
To create the SQLite project database, run the schema, and load the seed network telemetry data, run:
python seed.py
The database will be generated at: data/project.db

### 3. Test the Database Access Layer
To verify Python can successfully connect and execute queries against the seeded database:
python db.py

### 4. AI Configuration
To enable the AI analysis features, create a .env file in the project root directory and add your API key:
AI_API_KEY=your_key_here
Warning: Do not commit or submit your real .env file to version control.

### 5. Run the Streamlit Application
Launch the interactive dashboard:
streamlit run app.py

### Known Limitations
The AI summaries and mitigation suggestions must be verified against the displayed raw database evidence. The application does not automatically resolve network incidents, block traffic, or replace human judgment.
Buckle in, because you're about to witness greatness in the making, Dr. B.