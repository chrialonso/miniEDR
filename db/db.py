import sqlite3
import os

PROJECT_ROOT: str = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(PROJECT_ROOT, "edr.db")
SCHEMA_PATH: str = os.path.join(PROJECT_ROOT, "schema.sql")

def init_db():
    with open(SCHEMA_PATH) as file:
        schema = file.read()

    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(schema)

def db_connect() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)

def schema_is_valid() -> bool:
    if not os.path.exists(DB_PATH):
        return False

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("select count(*) from sqlite_master where type = 'table' and name in ('process_create', 'state')")
        return cur.fetchone()[0] == 2

def ensure_schema() -> bool:
    print("[Database] Checking database schema...")
    if not schema_is_valid():
        print("[Database] Schema missing or invalid, initializing database...")
        try:
            init_db()
            print("[Database] Database initialized")
            return True
        except Exception as e:
            print(f"[Database] [Error] Could not initialize database: {e}")
            return False
    else:
        print("[Database] Found valid schema, proceeding")
        return True
