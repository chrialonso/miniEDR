from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING
from db.db import db_connect
from enum import Enum
import sqlite3

if TYPE_CHECKING:
    from agent.parser import EventRecord

def get_datetime_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self):
        return self.name.lower()

@dataclass
class Alert:
    rule_name: str
    severity: Severity
    mitre: str
    message: str
    event_record: "EventRecord"
    timestamp: str = field(default_factory=get_datetime_iso)

class PowershellRules(Enum):
    ENCODED_COMMAND = "powershell_encoded_command"
    DEFENDER_EXCLUSION = "powershell_defender_exclusion"
    DISABLE_DEFENDER_AV = "powershell_disable_defender_av"

def powershell_encoding(record: "EventRecord") -> Optional[Alert]:
    # ATT&CK: T1059.001
    # Sigma: Suspicious Execution of Powershell with Base64 

    if not record.image:
        return None

    image = record.image.lower()
    if not (image.endswith('powershell.exe') or image.endswith('pwsh.exe')):
        return None

    if not record.command_line:
        return None

    cli = record.command_line.lower()
    
    #filter_encoding: exclude legitimate use of -Encoding parameter
    if ' -encoding ' in cli:
        return None

    #filter_azure: exclude Azure Guest configuration
    azure_paths = {r'c:\packages\plugins\microsoft.guestconfiguration.configurationforwindows',
                   r'gc_worker.exe'}

    if record.parent_image:
        parent = record.parent_image.lower()
        for path in azure_paths:
            if path in parent:
                return None

    encoded_flags = {' -e ', ' -en ', ' -enc ', ' -enco', ' -ec '}

    #selection: check for encoded flags
    for flag in encoded_flags:
        if flag in cli:
            return Alert(
                    rule_name = PowershellRules.ENCODED_COMMAND.value,
                    mitre = "T1059.001",
                    severity = Severity.MEDIUM,
                    message = "Powershell launched with an encoded command. "
                                "Possible obfuscation or defence evasion."
                                f" Command: {record.command_line}",
                    event_record = record)
    return None

def powershell_defender_exclusion(record: "EventRecord") -> Optional[Alert]:
    # ATT&CK: T1562.001
    # Sigma: Powershell Defender Exclusion

    if not record.command_line:
        return None

    cli = record.command_line.lower()

    preferences = {'add-mppreference', 'set-mppreference'}
    selection1 = False
    for pref in preferences:
        if pref in cli:
            selection1 = True

    exclusion_paths = {'-exclusionpath', '-exclusionextension', '-exclusionprocess', '-exclusionipaddress'}
    selection2 = False
    for path in exclusion_paths:
        if path in cli:
            selection2 = True

    if selection1 and selection2:
        return Alert(
                rule_name = PowershellRules.DEFENDER_EXCLUSION.value,
                severity = Severity.MEDIUM,
                mitre = "T1562.001",
                message = "Powershell launched with requests to exclude items from antivirus scanning." 
                          f" Command: {record.command_line}",
                event_record = record)    
    return None

def powershell_disable_defender_av(record: "EventRecord") -> Optional[Alert]:
    # ATT&CK: T1562.001
    # Sigma: Disable Windows Defender AV Security Monitoring

    if not record.image:
        return None

    if not record.command_line:
        return None

    image = record.image.lower()
    original = (record.original_file_name or "").lower()
    cli = record.command_line.lower()

    selection_pwsh_binary = (image.endswith('powershell.exe') or image.endswith('pwsh.exe')
                             or original == 'powershell.exe' or original == 'pwsh.dll')
    selection_pwsh_cli = ('-disablebehaviormonitoring $true' in cli or '-disableruntimemonitoring $true' in cli)
    selection_sc_binary = (image.endswith('sc.exe') or original == 'sc.exe')
    selection_sc_tamper_cmd_stop = ('stop' in cli and 'windefend' in cli)
    selection_sc_tamper_cmd_delete = ('delete' in cli and 'windefend' in cli)
    selection_sc_tamper_cmd_disabled = ('config' in cli and 'windefend' in cli and 'start=disabled' in cli)

    if (selection_pwsh_binary and selection_pwsh_cli) or (
                selection_sc_binary and (
                selection_sc_tamper_cmd_disabled or
                selection_sc_tamper_cmd_delete or
                selection_sc_tamper_cmd_stop)):
        return Alert(
                rule_name = PowershellRules.DISABLE_DEFENDER_AV.value,
                severity = Severity.HIGH,
                mitre = "T1562.001",
                message = "Attempts to disable Windows Defender with powershell detected.",
                event_record = record)
    
    return None

RULES = [powershell_encoding, powershell_defender_exclusion, powershell_disable_defender_av]

def run_rules(record: "EventRecord") -> list[Alert]:
    alerts: list[Alert] = []
    for rule in RULES:
        alert = rule(record)
        if alert:
            print("[Detector] [ALERT] Suspicious activity detected")
            alerts.append(alert)

    return alerts

def run_detection(records: list["EventRecord"]) -> list[Alert]:
    alerts: list[Alert] = []

    #run detection rules here while event records are still in memory
    for record in records:
        alert = run_rules(record)
        alerts.extend(alert)

    return alerts

def insert_alerts(conn: sqlite3.Connection, alerts: list[Alert]) -> None:
    for alert in alerts:
        conn.execute("""insert into alerts(rule_name, mitre, message, severity,
                     timestamp, channel, record_id)
                     values(?, ?, ?, ?, ?, ?, ?)""",
                     (alert.rule_name, alert.mitre, alert.message, str(alert.severity), alert.timestamp,
                      alert.event_record.channel, alert.event_record.event_record_id))
    conn.commit()
 
def run_detector(records: list["EventRecord"]) -> None:
    print("[Detector] Starting up")

    conn: sqlite3.Connection | None = None

    try:
        conn = db_connect()
        print("[Detector] Connection to database established")
    except sqlite3.Error as e:
        print(f"[Detector] [Error] Failed to connect to database: {e}")
        return

    try:
        alerts: list[Alert] = run_detection(records)
        insert_alerts(conn, alerts)
    except Exception as e:
        print(f"[Detector] [Error] Failed during detection or alert insertion: {e}")
    finally:
        if conn:
            conn.close()
