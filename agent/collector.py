import win32evtlog
import os
from datetime import datetime, timezone
import json
from dataclasses import dataclass, asdict
from typing import Optional
import sqlite3
from db.db import db_connect

SYSMON_LOG: str = "Microsoft-Windows-Sysmon/Operational"
COLLECTOR_DIR: str = os.path.dirname(os.path.abspath(__file__)) 
SPOOL_DIR: str = os.path.join(COLLECTOR_DIR, "spool")

#Data that was collected by the collector go here to be later 
#taken by the parser
INBOX_DIR: str = os.path.join(SPOOL_DIR, "inbox")

#Sysmon event ID 1 and 3 for process creation and network connection events
EVENT_IDS: list[int] = [1,3]

#Tracks the highest EventRecordID that has been collected
#so that the collector run won't get old events
EVENT_RECORD_ID_STATE: str = "stored_event_record_id"

@dataclass
class SpoolRecord:
    event_id: int
    event_record_id: Optional[int]
    time_retrieved: str
    xml: str
    channel: str = SYSMON_LOG

    def to_json(self):
        return json.dumps(asdict(self), ensure_ascii = False)

def ensure_dirs() -> None:
    os.makedirs(INBOX_DIR, exist_ok = True)

def build_query(event_id: int, last_record_id: int) -> str:
    return f"*[System[(EventID={event_id}) and (EventRecordID > {last_record_id})]]"

def extract_event_record_id(xml: str) -> Optional[int]:
    start_tag: str = "<EventRecordID>"
    end_tag: str = "</EventRecordID>"

    start: int = xml.find(start_tag)
    if start == -1:
        return None
    start += len(start_tag)

    end = xml.find(end_tag, start)
    if end == -1:
        return None

    try:
        return int(xml[start:end].strip())
    except ValueError:
        return None

def xml_to_spool_record(event: str, event_id: int) -> SpoolRecord:
    time_retrieved = get_datetime_iso()
    event_record_id = extract_event_record_id(event)

    return SpoolRecord(event_id = event_id,
                       event_record_id = event_record_id,
                       time_retrieved = time_retrieved,
                       xml = event)

def get_datetime_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec = "seconds")

def get_timestamp_for_filename() -> str:
    filename_timestamp: str = datetime.now(timezone.utc).strftime('%Y-%m-%d-%H-%M-%S')
    return filename_timestamp

def generate_jsonl_filename(event_id) -> str:
    filename = f"eid_{event_id}_{get_timestamp_for_filename()}.jsonl"
    return filename

# Parser may read jsonl files before collector is done writing them
# Appending '.tmp' to the filename ensures that they never get seen until it's done being written
# In the parsing phase, files not ending with '.jsonl' get ignored
def atomic_write_jsonl(inbox_file_path: str, event_records: list[SpoolRecord]):
    tmp_filename: str = inbox_file_path + ".tmp"

    with open(tmp_filename, "w", encoding = "utf-8") as file:
        for event in event_records:
            file.write(event.to_json() + "\n")

    os.replace(tmp_filename, inbox_file_path)

def state_set(key: str, value: str, conn: sqlite3.Connection) -> None:
    conn.execute("insert into state(key, value) values(?, ?) on conflict(key) do update set value = excluded.value", (key, value))
    conn.commit()


def state_get(key: str, default: str, conn: sqlite3.Connection) -> str:
    row = conn.execute("select value from state where key = ?", (key,)).fetchone()
    if row:
        return row[0]
    else:
        return default

def collect_new_sysmon_events(event_id: int, conn: sqlite3.Connection, max_events: int = 10) -> tuple[list[SpoolRecord], int, int]:
    last_stored_event_record_id = int(state_get(EVENT_RECORD_ID_STATE+f"_{event_id}", "0", conn))
    query: str = build_query(event_id, last_stored_event_record_id)
    handle_query = win32evtlog.EvtQuery(SYSMON_LOG, win32evtlog.EvtQueryForwardDirection, query)

    records: list[SpoolRecord] = []

    max_event_record_id: int = last_stored_event_record_id

    while len(records) < max_events:
        event = win32evtlog.EvtNext(handle_query, 1)
        if not event:
            break 
        evt = event[0]
        xml = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
        rec = xml_to_spool_record(xml, event_id)
        if rec.event_record_id is not None:
            max_event_record_id = max(max_event_record_id, rec.event_record_id)
        records.append(rec)

    return records, max_event_record_id, last_stored_event_record_id

def run_collector():
    print("[Collector] Starting up")
    print("[Collector] Ensuring directories exist...")
    ensure_dirs()

    conn: sqlite3.Connection | None = None

    try:
        conn = db_connect()
        print("[Collector] Connection to database established")
    except Exception as e:
        print("[Collector] [Error] Unable to connect to database")
        return

    print("[Collector] Getting events...")

    try:
        for event_id in EVENT_IDS:
            records, max_event_record_id, last_stored_event_record_id = collect_new_sysmon_events(event_id, conn)
            if not records:
                print(f"[Collector] No events found for event ID {event_id} since last_record_id = {last_stored_event_record_id}")
                continue 

            print(f"[Collector] Retrieved {len(records)} events!")
            print("[Collector] Generating filename...")
            filename: str = generate_jsonl_filename(event_id)

            inbox_file_path: str = os.path.join(INBOX_DIR, filename)

            if max_event_record_id > last_stored_event_record_id:
                try:
                    print(f"[Collector] Wrote to {inbox_file_path}")
                    atomic_write_jsonl(inbox_file_path, records)
                    state_set(EVENT_RECORD_ID_STATE+f"_{event_id}", str(max_event_record_id), conn)
                except Exception as e:
                    print(f"[Collector] [Error] {e}")

            print(f"[Collector] Checkpoint: {last_stored_event_record_id} -> {max_event_record_id}")

    except Exception as e:
        print(f"[Collector] [Error] {e}")
        print("[Collector] [Error] If this error is 'Access Denied', run as administrator")
    finally:
        if conn:
            conn.close()
