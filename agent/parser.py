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
class ProcessCreate:
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

@dataclass
class NetworkConnect:
    channel: Optional[str]
    event_record_id: int
    time_retrieved: Optional[str]
    process_id: Optional[int]
    image: Optional[str]
    process_user: Optional[str]
    protocol: Optional[str]
    initiated: Optional[str]
    source_ip: Optional[str]
    source_port: Optional[str]
    destination_ip: Optional[str]
    destination_hostname: Optional[str]
    destination_port: Optional[str]

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

    return sorted(jsonl_files)

def move_file(src_dir: str, dst_dir: str, filename) -> str:
    src: str = os.path.join(src_dir, filename)
    dst: str = os.path.join(dst_dir, filename)
    shutil.move(src, dst)

    return dst

def insert_process(conn: sqlite3.Connection, event_records: list[ProcessCreate]) -> None:
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

def insert_network(conn: sqlite3.Connection, network_records: list[NetworkConnect]) -> None:
    for record in network_records:
        conn.execute("""insert or ignore into network_connect(
                     channel, record_id, timestamp, process_id, image, process_user,
                     protocol, initiated, source_ip, source_port, destination_ip, destination_hostname,
                     destination_port)
                     values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                     (record.channel, record.event_record_id, record.time_retrieved, record.process_id,
                      record.image, record.process_user, record.protocol, record.initiated, record.source_ip,
                      record.source_port, record.destination_ip, record.destination_hostname, record.destination_port))

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

def xml_to_event_records(records: list[SpoolRecord]) -> tuple[list[ProcessCreate], list[NetworkConnect]]:
    process_records: list[ProcessCreate] = []
    network_records: list[NetworkConnect] = []

    for record in records:
        try:
            if record.event_id == 1:
                parsed_process_create_record: ProcessCreate | None = parse_process_create(record)
                if parsed_process_create_record is None:
                    continue
                
                process_records.append(parsed_process_create_record)

            elif record.event_id == 3:
                parsed_network_connect_record: NetworkConnect | None = parse_network_connect(record)
                if parsed_network_connect_record is None:
                    continue

                network_records.append(parsed_network_connect_record)

        except Exception as e:
            print(f"[Parser] [Error] Unable to parse XML: {e}")
            continue

    return process_records, network_records

def parse_process_create(record: SpoolRecord) -> ProcessCreate | None:
    root = et.fromstring(record.xml) 

    #pre parsed fields
    if record.event_record_id is None:
        #TODO log files that did not have event_record_id instead of skipping
        print(f"[Parser] [Error] Skipping record with missing event_record_id")
        return None

    event_record_id: int = record.event_record_id
    channel: str = record.channel

    time_created = root.find('e:System/e:TimeCreated', namespaces = NAMESPACE)
    timestamp = time_created.get('SystemTime') if time_created is not None else None

    names: list[str] = ['ProcessId', 'ParentProcessId', 'Image','OriginalFileName',
                        'CommandLine', 'User', 'LogonId', 'IntegrityLevel', 'Hashes',
                        'ParentImage', 'ParentCommandLine']

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

    process_record: ProcessCreate = ProcessCreate(
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

    return process_record

def parse_network_connect(record: SpoolRecord) -> NetworkConnect | None:
    root = et.fromstring(record.xml)

    #pre parsed fields
    if record.event_record_id is None:
        #TODO log files that did not have event_record_id instead of skipping
        print(f"[Parser] [Error] Skipping record with missing event_record_id")
        return None

    event_record_id: int = record.event_record_id
    channel: str = record.channel

    time_created = root.find('e:System/e:TimeCreated', namespaces = NAMESPACE)
    timestamp = time_created.get('SystemTime') if time_created is not None else None

    names: list[str] = ['ProcessId', 'Image', 'User', 'Protocol', 'Initiated', 'SourceIp',
                        'SourcePort', 'DestinationIp', 'DestinationHostname', 'DestinationPort']

    ed: dict[str, Optional[str]] = get_event_data(root, names)
    process_id = int(ed['ProcessId']) if ed['ProcessId'] else None
    image = ed['Image']
    process_user = ed['User']
    protocol = ed['Protocol']
    initiated = ed['Initiated']
    source_ip = ed['SourceIp']
    source_port = ed['SourcePort']
    destination_ip = ed['DestinationIp']
    destination_hostname = ed['DestinationHostname']
    destination_port = ed['DestinationPort']

    network_record = NetworkConnect(channel = channel,
                                    event_record_id = event_record_id,
                                    time_retrieved = timestamp,
                                    process_id = process_id,
                                    image = image,
                                    process_user = process_user,
                                    protocol = protocol,
                                    initiated = initiated,
                                    source_ip = source_ip,
                                    source_port = source_port,
                                    destination_ip = destination_ip,
                                    destination_hostname = destination_hostname,
                                    destination_port = destination_port)
    return network_record

def move_inbox_files_to_processing(inbox_files: list[str], src_dir: str, dst_dir: str):
    for file in inbox_files:
        try:
            processing_path: str = move_file(src_dir, dst_dir, file)
            print(f"[Parser] Processing {processing_path}")
        except Exception as e:
            print(f"[Parser] [Error] Could not move {file} to processing, will retry next run: {e}")

def parse_processing_files(conn: sqlite3.Connection, processing_files: list[str]) -> tuple[list[ProcessCreate], list[NetworkConnect]]:
    process_records: list[ProcessCreate] = []
    network_records: list[NetworkConnect] = []

    print(f"[Parser] Parsing files...")

    for file in processing_files:
        filepath: str = os.path.join(PROCESSING_DIR, file)
        try:
            spool_records: list[SpoolRecord] = get_records_from_spool(filepath)
            file_process_records, file_network_records = xml_to_event_records(spool_records)

            if not file_process_records and not file_network_records:
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
            if file_process_records:
                insert_process(conn, file_process_records)

            if file_network_records:
                insert_network(conn, file_network_records)

            move_file(PROCESSING_DIR, DONE_DIR, file)
            process_records.extend(file_process_records)
            network_records.extend(file_network_records)
        except Exception as e:
            print(f"[Parser] [Error] Failed to insert {file} into database: {e}")
            move_file(PROCESSING_DIR, BAD_DIR, file)

    return process_records, network_records

def run_parser() -> tuple[list[ProcessCreate], list[NetworkConnect]] | None:
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

