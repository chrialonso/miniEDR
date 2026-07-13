import os
from datetime import datetime, timezone
import json
from dataclasses import dataclass, asdict
from typing import Optional
import sqlite3
from db.db import db_connect
from ui.log_queue import post_log

SYSMON_LOG: str = "Microsoft-Windows-Sysmon/Operational"
COLLECTOR_DIR: str = os.path.dirname(os.path.abspath(__file__)) 
SPOOL_DIR: str = os.path.join(COLLECTOR_DIR, "spool")

# Data that was collected by the collector go here to be later 
# taken by the parser
INBOX_DIR: str = os.path.join(SPOOL_DIR, "inbox")

# Sysmon event ID 1 = ProcessCreate, event ID 3 = NetworkConnect
EVENT_IDS: list[int] = [1,3]

# Tracks the highest EventRecordID that has been collected
# so that the collector run won't get old events
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
    # Xpath query filters to only events newer than the last seen records
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

def collect_new_sysmon_events(event_id: int, conn: sqlite3.Connection, win32evtlog, max_events: int = 1000) -> tuple[list[SpoolRecord], int, int, int]:
    last_stored_event_record_id = int(state_get(EVENT_RECORD_ID_STATE+f"_{event_id}", "0", conn))
    query: str = build_query(event_id, last_stored_event_record_id)
    handle_query = win32evtlog.EvtQuery(SYSMON_LOG, win32evtlog.EvtQueryForwardDirection, query)

    records: list[SpoolRecord] = []

    max_event_record_id: int = last_stored_event_record_id

    try:
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

    finally:
        # Always close the query handle even if an exception occurs mid loop to avoid leaking windows event log handles
        # ignoring because pyright cannot see PyEVT_HANDLE's methods
        post_log("[Collector] Closing query handle")
        handle_query.Close() #type: ignore

    none_id_count: int = 0
    for r in records:
        if r.event_record_id is None:
            none_id_count += 1
    if none_id_count > 0:
        post_log(f"[Collector] [Warning] {none_id_count}/{len(records)} records had no extractable EventRecordID")

    return records, max_event_record_id, last_stored_event_record_id, none_id_count

def run_collector() -> bool:
    try:
        import win32evtlog
    except ImportError:
        post_log("[Collector] [Error] win32evtlog is not available. Is pywin32 installed?")
        return False

    post_log("[Collector] Starting up")
    post_log("[Collector] Ensuring directories exist...")
    ensure_dirs()

    conn: sqlite3.Connection | None = None

    try:
        conn = db_connect()
        post_log("[Collector] Connection to database established")
    except Exception as e:
        post_log("[Collector] [Error] Unable to connect to database")
        return False

    post_log("[Collector] Getting events...")

    try:
        for event_id in EVENT_IDS:
            records, max_event_record_id, last_stored_event_record_id, none_id_count = collect_new_sysmon_events(event_id, conn, win32evtlog)
            if not records:
                post_log(f"[Collector] No events found for event ID {event_id} since last_record_id = {last_stored_event_record_id}")
                continue 

            post_log(f"[Collector] Retrieved {len(records)} events!")
            post_log("[Collector] Generating filename...")
            filename: str = generate_jsonl_filename(event_id)

            inbox_file_path: str = os.path.join(INBOX_DIR, filename)

            if max_event_record_id > last_stored_event_record_id:
                try:
                    post_log(f"[Collector] Wrote to {inbox_file_path}")
                    atomic_write_jsonl(inbox_file_path, records)
                    state_set(EVENT_RECORD_ID_STATE+f"_{event_id}", str(max_event_record_id), conn)
                    post_log(f"[Collector] Checkpoint: {last_stored_event_record_id} -> {max_event_record_id}")
                except Exception as e:
                    post_log(f"[Collector] [Error] {e}")
                    return False
            elif none_id_count == len(records):
                post_log(f"[Collector] [Error] Collected {len(records)} events for EventID {event_id} but could not extract any EventRecordID. Checkpoint stuck at {last_stored_event_record_id}. Skipping batch.")

    except Exception as e:
        if "Access is denied" in str(e):
            post_log("[Collector] [Error] Access is denied! Run miniEDR as administrator")
            return False
        else:
            post_log(f"[Collector] [Error] {e}")
            return False
    finally:
        if conn:
            conn.close()

    return True
