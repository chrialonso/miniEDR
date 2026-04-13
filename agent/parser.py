import os
import shutil
from agent.collector import SPOOL_DIR, INBOX_DIR, SpoolRecord
import xml.etree.ElementTree as et
import sqlite3
from dataclasses import dataclass
from typing import Optional
import json
from db.db import db_connect

#Parser takes files from inbox and moves them to processing.
#If the parser crashes, files that were not finished parsing stay in
#processing so when the parser starts up again, it will resume parsing
PROCESSING_DIR: str = os.path.join(SPOOL_DIR, "processing")

#Files that were successfully parsed go here to be saved and 
#looked at later for forensic review
DONE_DIR: str = os.path.join(SPOOL_DIR, "done")

#Files that failed to be parsed are sent here to be saved and
#looked at later for what went wrong
BAD_DIR: str = os.path.join(SPOOL_DIR, "bad")

NAMESPACE: dict[str, str] = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

@dataclass
class EventRecord:
    channel: Optional[str]
    event_record_id: int
    time_retrieved: Optional[str]
    process_id: Optional[int]
    parent_process_id: Optional[int]
    image: Optional[str]
    original_file_name: Optional[str]
    command_line: Optional[str]
    process_user: Optional[str]
    logon_id: Optional[str]
    integrity_level: Optional[str]
    hashes: Optional[str]
    parent_image: Optional[str]
    parent_command_line: Optional[str]

def ensure_dirs():
    os.makedirs(DONE_DIR, exist_ok = True)
    os.makedirs(BAD_DIR, exist_ok = True)
    os.makedirs(PROCESSING_DIR, exist_ok = True)

def list_inbox_jsonl() -> list[str]:
    files: list[str] = os.listdir(INBOX_DIR)
    jsonl_files: list[str] = []
    for file in files:
        if file.endswith(".jsonl"):
            jsonl_files.append(file)

    return jsonl_files

def move_file(src_dir: str, dst_dir: str, filename) -> str:
    src: str = os.path.join(src_dir, filename)
    dst: str = os.path.join(dst_dir, filename)
    shutil.move(src, dst)

    return dst

def insert_process(conn: sqlite3.Connection, event_records: list[EventRecord]) -> None:
    for event in event_records:
        conn.execute("""insert or ignore into process_create(
                    channel, record_id, timestamp, process_id,
                    parent_process_id, image, original_file_name, command_line,
                    process_user, logon_id, integrity_level, hashes, parent_image,
                    parent_command_line)
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (event.channel, event.event_record_id, event.time_retrieved,
                    event.process_id, event.parent_process_id, event.image,
                    event.original_file_name, event.command_line, event.process_user, event.logon_id,
                    event.integrity_level, event.hashes, event.parent_image,
                    event.parent_command_line))
    conn.commit()

def get_records_from_spool(path: str) -> list[SpoolRecord]:
    records: list[SpoolRecord] = []
    with open(path, "r", encoding = "utf-8") as file:
        for line_no, line in enumerate(file, start = 1):
            line = line.strip()
            if not line:
                continue

            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[Parser] [Error] Line {line_no}: JSON Decode error: {e}")
                continue

            records.append(SpoolRecord(
                event_id = rec.get("event_id"),
                event_record_id = rec.get("event_record_id"),
                time_retrieved = rec.get("time_retrieved"),
                xml= rec.get("xml"),
                channel = rec.get("channel")))

    return records

def get_event_data(root, names: list[str]) -> dict[str, Optional[str]]:
    result: dict[str, Optional[str]] = {name: None for name in names}
    for data in root.findall('e:EventData/e:Data', NAMESPACE):
        name = data.get('Name')
        if name in result:
            result[name] = data.text
    return result

def xml_to_event_record(records: list[SpoolRecord]) -> list[EventRecord]:
    event_records: list[EventRecord] = []

    for record in records:
        try:
            root = et.fromstring(record.xml)        

            #pre parsed fields
            if record.event_record_id is None:
                #TODO log files that did not have event_record_id instead of skipping
                print(f"[Parser] [Error] Skipping record with missing event_record_id")
                continue

            event_record_id: int = record.event_record_id
            channel: str = record.channel
  
            time_created = root.find('e:System/e:TimeCreated', namespaces = NAMESPACE)
            timestamp = time_created.get('SystemTime') if time_created is not None else None

            names: list[str] = ['ProcessId', 'ParentProcessId', 'Image','OriginalFileName', 'CommandLine', 'User', 'LogonId', 'IntegrityLevel', 'Hashes', 'ParentImage', 'ParentCommandLine']
            ed: dict[str, Optional[str]] = get_event_data(root, names)

            parent_process_id = int(ed['ParentProcessId']) if ed['ParentProcessId'] else None
            process_id = int(ed['ProcessId']) if ed['ProcessId'] else None
            image = ed['Image']
            command_line = ed['CommandLine']
            original_file_name = ed['OriginalFileName']
            process_user = ed['User']
            logon_id = ed['LogonId']
            integrity_level = ed['IntegrityLevel'] if ed['IntegrityLevel'] else None
            hashes = ed['Hashes']    

            parent_image = ed['ParentImage']
            parent_command_line = ed['ParentCommandLine']

            event_record: EventRecord = EventRecord(
                             channel = channel,
                             event_record_id = event_record_id,
                             time_retrieved = timestamp,
                             process_id = process_id,
                             parent_process_id = parent_process_id,
                             image = image,
                             original_file_name = original_file_name,
                             command_line = command_line,
                             process_user = process_user,
                             logon_id = logon_id,
                             integrity_level = integrity_level,
                             hashes = hashes,
                             parent_image = parent_image,
                             parent_command_line = parent_command_line)

            event_records.append(event_record)
        except Exception as e:
            print(f"[Parser] [Error] Unable to parse XML: {e}")
            continue

    return event_records

def move_inbox_files_to_processing(inbox_files: list[str], src_dir: str, dst_dir: str):
    for file in inbox_files:
        try:
            processing_path: str = move_file(src_dir, dst_dir, file)
            print(f"[Parser] Processing {processing_path}")
        except Exception as e:
            print(f"[Parser] [Error] Could not move {file} to processing, will retry next run: {e}")

def parse_processing_files(conn: sqlite3.Connection, processing_files: list[str]) -> list[EventRecord]:
    event_records: list[EventRecord] = []

    print(f"[Parser] Parsing files...")

    for file in processing_files:
        filepath: str = os.path.join(PROCESSING_DIR, file)
        try:
            spool_records: list[SpoolRecord] = get_records_from_spool(filepath)
            records: list[EventRecord] = xml_to_event_record(spool_records)

            if not records:
                #TODO fixing issue in xml_to_event_record will make this check simpler
                print(f"[Parser] [Error] No valid events parsed from {file}, records may have had missing event_record_id")
                try:
                    bad_path: str = move_file(PROCESSING_DIR, BAD_DIR, file)
                    print(f"[Parser] [Error] Moved {file} to {bad_path}")
                except Exception as e:
                    print(f"[Parser] [Error] Also failed to move {file} to bad path: {e}")
                continue

        except Exception as e:
            print(f"[Parser] [Error] Failed to parse: {file}: {e}")
            bad_path: str = move_file(PROCESSING_DIR, BAD_DIR, file)
            print(f"[Parser] [Error] Moved {file} to {bad_path}")
            continue

        try:
            insert_process(conn, records)
            move_file(PROCESSING_DIR, DONE_DIR, file)
            event_records.extend(records)
        except Exception as e:
            print(f"[Parser] [Error] Failed to insert {file} into database: {e}")

    return event_records 

def run_parser() -> list[EventRecord] | None:
    print("[Parser] Starting up")

    conn: sqlite3.Connection | None = None

    try:
        conn = db_connect()
        print("[Parser] Connection to database established")
    except sqlite3.Error as e:
        print(f"[Parser] Failed to connect to database: {e}")
        return None

    try:
        print("[Parser] Ensuring dirs")
        ensure_dirs()

        inbox_files: list[str] = list_inbox_jsonl()
        print(f"[Parser] Moving {len(inbox_files)} files from inbox directory to processing directory")
        move_inbox_files_to_processing(inbox_files, INBOX_DIR, PROCESSING_DIR)

        processing_files: list[str] = sorted(f for f in os.listdir(PROCESSING_DIR) if f.endswith(".jsonl"))

        event_records = parse_processing_files(conn, processing_files)

        return event_records
    except Exception as e:
        print(f"[Parser] [Error] Unexpected error: {e}")
        return None
    finally:
        if conn:
            conn.close()

