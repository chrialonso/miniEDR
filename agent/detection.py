from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING
from db.db import db_connect
import sqlite3

if TYPE_CHECKING:
    from agent.parser import EventRecord

def get_datetime_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

@dataclass
class Alert:
    rule_name: str
    severity: str
    message: str
    event_record: "EventRecord"
    timestamp: str = field(default_factory=get_datetime_iso)

def test_alerts(conn: sqlite3.Connection) -> Optional[Alert]:
    rows = conn.execute("""select parent_image, timestamp from process_create""").fetchall()
    found: bool = False 

    for i, (image, time) in enumerate(rows, start = 1):
        if image.endswith("svchost.exe"):
            if found is False:
                print("[Detector] [Alert] Found instances of svchost.exe")
                found = True
            print(f"Line: {i}\nTime: {time}\nImage: {image}\n")
    
def run_detector():
    try:
        conn: sqlite3.Connection = db_connect()
        print("[Detector] Connection to database established")
    except sqlite3.Error as e:
        print(f"[Detector] [Error] Failed to connect to database: {e}")
        return

    try:
        test_alerts(conn)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
