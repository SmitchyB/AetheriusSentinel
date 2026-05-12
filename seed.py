import sqlite3
from pathlib import Path

DATABASE_PATH = Path("data/starter.db")
SCHEMA_PATH = Path("schema.sql")

def initialize_database() -> None:
    DATABASE_PATH.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DATABASE_PATH) as conn:
        schema_sql = SCHEMA_PATH.read_text()
        conn.executescript(schema_sql)
        conn.executemany(
            "INSERT INTO sample_items (id, name, status) VALUES (?, ?, ?)",
            [(1, "Example A", "New"), (2, "Example B", "In Progress"), (3, "Example C", "Complete")]
        )
        conn.commit()

if __name__ == "__main__":
    initialize_database()
    print(f"Database created at: {DATABASE_PATH}")