import sqlite3
from datetime import datetime, timezone, timedelta
from db.db import DB_PATH
from ui.log_queue import post_log

def purge_old_events(conn: sqlite3.Connection, retention_days: int = 30) -> None:
    cutoff = (datetime.now(timezone.utc) - timedelta(days = retention_days)).isoformat()

    try:
        cursor = conn.execute("""delete from process_create where timestamp < ?""", (cutoff,))
        process_deleted = cursor.rowcount

        cursor = conn.execute("""delete from network_connect where timestamp < ?""", (cutoff,))
        network_deleted = cursor.rowcount

        conn.commit()
        post_log(f"[Retention] Purged {process_deleted} process records and {network_deleted} network records older than {retention_days} days")
    except Exception as e:
        post_log(f"[Retention] [Error] Could not delete events from database: {e}")

def vacuum_database() -> None:
    post_log("[Retention] Running vacuum...")
    try:
        with sqlite3.connect(DB_PATH) as conn:    
            conn.execute("vacuum")
            post_log("[Retention] Vacuum complete")
    except Exception as e:
        post_log(f"[Retention] [Error] Vacuum failed: {e}")
