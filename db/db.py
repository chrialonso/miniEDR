import sqlite3
import os
from ui.log_queue import post_log

DB_DIR: str = os.path.dirname(os.path.abspath(__file__))
DB_PATH: str = os.path.join(DB_DIR, "edr.db")
SCHEMA_PATH: str = os.path.join(DB_DIR, "schema.sql")

def init_db():
    with open(SCHEMA_PATH) as file:
        schema = file.read()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(schema)

def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn 

def schema_is_valid() -> bool:
    if not os.path.exists(DB_PATH):
        return False

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("select count(*) from sqlite_master where type = 'table' and name in ('process_create', 'network_connect', 'state', 'alerts')")
        return cur.fetchone()[0] == 4

def ensure_schema() -> bool:
    post_log("[Database] Checking database schema...")
    if not schema_is_valid():
        post_log("[Database] Schema missing or invalid, initializing database...")
        try:
            init_db()
            post_log("[Database] Database initialized")
            return True
        except Exception as e:
            post_log(f"[Database] [Error] Could not initialize database: {e}")
            return False
    else:
        post_log("[Database] Found valid schema, proceeding")
        return True

def get_db_size(db_path: str) -> int:
    try:
        return os.path.getsize(db_path)
    except (FileNotFoundError, OSError):
        return 0
