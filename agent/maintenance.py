from db.retention import purge_old_events, vacuum_database
from db.db import db_connect
from agent.parser import DONE_DIR, BAD_DIR
import os
from datetime import datetime, timezone, timedelta
import sqlite3

def purge_old_spool_files(dir, retention_days: int = 7) -> None:
    if not os.path.exists(dir):
        return None

    cutoff = (datetime.now(timezone.utc) - timedelta(days = retention_days)).timestamp()

    spool_files = os.listdir(dir)
    removed_files: int = 0
    try:
        for spool_file in spool_files:
            file_path: str = os.path.join(dir, spool_file)
            file_timestamp = os.path.getmtime(file_path)
            if file_timestamp < cutoff:
                os.remove(file_path)
                removed_files += 1
        print(f"[Maintenance] Removed {removed_files} old files in {dir}")
    except Exception as e:
        print(f"[Maintenance] [Error] Could not remove files in {dir}: {e}")

def run_maintenance(run_vacuum: bool = False) -> None:
    print("[Maintenance] Starting up")
    
    purge_old_spool_files(DONE_DIR)
    purge_old_spool_files(BAD_DIR, retention_days = 30)

    conn: sqlite3.Connection | None = None

    try:
        conn = db_connect()
        print("[Maintenance] Connection to database established")

        purge_old_events(conn)
        if run_vacuum:
            # vacuum_database opens its own connection because VACUUM
            # cannot run inside a transaction
            vacuum_database()
    except Exception as e:
        print(f"[Maintenance] [Error] Could not connect to database: {e}")
        return None
    finally:
        if conn:
            conn.close()

    print("[Maintenance] Done")
