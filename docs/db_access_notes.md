# Database Access Layer Notes

## 1. How does your Python code connect to the database?
The script uses the built-in `sqlite3` library to establish a connection via `sqlite3.connect(DB_PATH)`. I also implemented `conn.row_factory = sqlite3.Row`, which allows Python to access the database columns by their names rather than just numerical indexes, making the code much more robust.

## 2. How does the `pandas` library help with database access?
Instead of manually looping through raw SQL cursor tuples, `pandas` allows me to use `pd.read_sql_query()`. This executes the query and instantly formats the result into a clean DataFrame. This is crucial because Streamlit is highly optimized to render `pandas` DataFrames directly into UI tables.

## 3. Explain how your parameterized query works and why it is important.
In functions like `get_incidents_by_severity(severity_level)`, I used the `?` placeholder in the SQL string and passed the variable in via `params=(severity_level,)`. Because Aetherius Sentinel is a cybersecurity application, preventing SQL injection is paramount. Parameterization ensures that user inputs from the UI are treated strictly as data, never as executable code.

## 4. Which of these queries will be most important for your AI feature?
The `get_ai_incident_context(incident_id)` function is the most critical. It executes a complex `JOIN` to pull the specific incident, identifies the compromised hardware, and uses `GROUP_CONCAT` to compress all related telemetry logs into a single string. This guarantees the LLM receives factual database evidence rather than hallucinating network events.

## 5. What errors or challenges did you encounter during this assignment?
When I first ran the script, Python threw a `ModuleNotFoundError: No module named 'pandas'`. I resolved this by installing the library in my virtual environment via `pip install pandas` and subsequently updating my `requirements.txt` file to ensure the application remains fully portable for deployment.