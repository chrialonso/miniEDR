from dataclasses import  dataclass, field, asdict
from typing import Optional, TYPE_CHECKING, Callable
from agent.parser import EventRecords, SysmonEvent
from db.db import db_connect
from enum import Enum
import sqlite3
import os
import logging
import json
from db.logger import log_alert
from ui.log_queue import post_log

CRYPTO_POOLS_FILE: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crypto_pools.txt")

EVENT_TYPE_NAMES: dict[int, str] = {1: "process_create",
                                    3: "network_connect",}

# TYPE_CHECKING guard avoids a circular import at runtime while still allowing
# the type checker to resolve ProcessCreate and NetworkConnect from parser.py
# as well as log_alert from logger
if TYPE_CHECKING:
    from agent.parser import ProcessCreate, NetworkConnect

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
    event_record: SysmonEvent
    timestamp: str = field(default_factory=get_datetime_iso)

    def event_to_json(self) -> str:
        return json.dumps(asdict(self.event_record), ensure_ascii = False)

class ProcessCreateRules(Enum):
    CRYPTO_MINING = "proc_create_susp_crypto_mining"

class PowershellRules(Enum):
    ENCODED_COMMAND = "powershell_encoded_command"
    DEFENDER_EXCLUSION = "powershell_defender_exclusion"
    DISABLE_DEFENDER_AV = "powershell_disable_defender_av"

class NetworkRules(Enum):
    NOTEPAD_CONNECTION = "network_notepad_connection"
    CRYPTO_MINING = "network_crypto_connection"
    NGROK_DOMAIN_CONNECTION = "network_ngrok_domain_connection"
    NGROK_TUNNEL_COMM = "network_ngrok_tunnel_communication"

class OfficeRules(Enum):
    OFFICE_SUS_CHILD_PROCESSES = "office_sus_child_process"

# === Sysmon EventID 1 Process Creation Rules ===

    # --- Start of Powershell rules ---

def powershell_encoding(record: "ProcessCreate") -> Optional[Alert]:
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
    azure_paths: set[str] = {r'c:\packages\plugins\microsoft.guestconfiguration.configurationforwindows',
                   r'gc_worker.exe'}

    if record.parent_image:
        parent = record.parent_image.lower()
        for path in azure_paths:
            if path in parent:
                return None

    encoded_flags: set[str] = {' -e ', ' -en ', ' -enc ', ' -enco', ' -ec '}

    #selection: check for encoded flags
    for flag in encoded_flags:
        if flag in cli:
            return Alert(
                    rule_name = PowershellRules.ENCODED_COMMAND.value,
                    mitre = "T1059.001",
                    severity = Severity.MEDIUM,
                    message = "Powershell launched with an encoded command. "
                                "Possible obfuscation or defence evasion.",
                    event_record = record)
    return None

def powershell_defender_exclusion(record: "ProcessCreate") -> Optional[Alert]:
    # ATT&CK: T1562.001
    # Sigma: Powershell Defender Exclusion

    if not record.command_line:
        return None

    cli = record.command_line.lower()

    preferences: set[str] = {'add-mppreference', 'set-mppreference'}
    selection1 = False
    for pref in preferences:
        if pref in cli:
            selection1 = True

    exclusion_paths: set[str] = {'-exclusionpath', '-exclusionextension', '-exclusionprocess', '-exclusionipaddress'}
    selection2 = False
    for path in exclusion_paths:
        if path in cli:
            selection2 = True

    if selection1 and selection2:
        return Alert(
                rule_name = PowershellRules.DEFENDER_EXCLUSION.value,
                severity = Severity.MEDIUM,
                mitre = "T1562.001",
                message = "Powershell launched with requests to exclude items from antivirus scanning.",
                event_record = record)    
    return None

def powershell_disable_defender_av(record: "ProcessCreate") -> Optional[Alert]:
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

    # --- Start of Office rules ---

def office_sus_child_process(record: "ProcessCreate") -> Optional[Alert]:
    # ATT&CK: T1047, T1204.002, T1218.010
    # Sigma: Suspicious Microsoft Office Child Process

    if not record.parent_image:
        return None

    parent_image_endswith: tuple[str, ...] = ("\\eqnedt32.exe", "\\excel.exe", "\\msaccess.exe", "\\mspub.exe", "\\onenote.exe", "\\powerpnt.exe",
                           "\\visio.exe", "\\winword.exe", "\\wordpad.exe", "\\wordview.exe")
    parent_image = record.parent_image.lower()

    selection_parent: bool = parent_image.endswith(parent_image_endswith)

    # return here if selection_parent is false
    if not selection_parent:
        return None

    if record.original_file_name:
        original_file_name = record.original_file_name.lower()
    else:
        original_file_name = ""

    det_original_filename: set[str] = {"bitsadmin.exe", "certoc.exe", "certutil.exe", "cmd.exe", "cmstp.exe", "cscript.exe", "curl.exe",
               "hh.exe", "ieexec.exe", "installutil.exe", "javaw.exe", "microsoft.workflow.compiler.exe", "msdt.exe", "mshta.exe",
               "msiexec.exe", "msxsl.exe", "odbcconf.exe", "pcalua.exe", "powershell.exe","regasm.exe","regsvcs.exe", "regsvr32.exe",
               "rundll32.exe", "schtasks.exe", "scriptrunner.exe", "wmic.exe",
               "workfolders.exe", "wscript.exe"}

    selection_child_process_1: bool = original_file_name in det_original_filename

    if record.image:
        image = record.image.lower()
    else:
        image = ""

    image_endswith: tuple[str, ...] = ("\\appvlp.exe", "\\bash.exe", "\\bitsadmin.exe", "\\certoc.exe", "\\certutil.exe",
              "\\cmd.exe", "\\cmstp.exe", "\\control.exe", "\\cscript.exe", "\\curl.exe", "\\forfiles.exe", "\\hh.exe", "\\ieexec.exe", "\\installutil.exe",
              "\\javaw.exe", "\\mftrace.exe", "\\microsoft.workflow.compiler.exe", "\\msbuild.exe", "\\msdt.exe", "\\mshta.exe", "\\msidb.exe", "\\msiexec.exe",
              "\\msxsl.exe", "\\odbcconf.exe", "\\pcalua.exe", "\\powershell.exe", "\\pwsh.exe", "\\regasm.exe", "\\regsvcs.exe", "\\regsvr32.exe", "\\rundll32.exe",
              "\\schtasks.exe", "\\scrcons.exe", "\\scriptrunner.exe", "\\sh.exe", "\\svchost.exe", "\\verclsid.exe", "\\wmic.exe", "\\workfolders.exe", "\\wscript.exe")

    selection_child_process_2: bool = image.endswith(image_endswith)

    child_susp_paths: set[str] = {"\\appdata\\", "\\users\\public\\", "\\programdata\\",
                                  "\\windows\\tasks\\", "\\windows\\temp\\", "\\windows\\system32\\tasks\\"}

    selection_child_susp_paths = False
    for susp_paths in child_susp_paths:
        if susp_paths in image:
            selection_child_susp_paths = True
            break

    # selection_parent is guaranteed to be true by this point, don't need to check for it again
    if selection_child_process_1 or selection_child_process_2 or selection_child_susp_paths:
        return Alert(
                rule_name = OfficeRules.OFFICE_SUS_CHILD_PROCESSES.value,
                severity = Severity.HIGH,
                mitre = "T1047, T1204.002, T1218.010",
                message = "A suspicious process spawned from one of the Microsoft Office suite products.",
                event_record = record)

def crypto_mining_activity(record: "ProcessCreate") -> Optional[Alert]:
    # ATT&CK: T1496
    # Sigma: Potential Crypto Mining Activity

    if not record.command_line:
        return None

    selection_command_line: set[str] = {" --cpu-priority=", "--donate-level=0", " -o pool.", " --nicehash", " --algo=rx/0 ", "stratum+tcp://",
                                  "stratum+udp://",
                                  # base64 encoded: --donate-level=
                                  "ls1kb25hdgutbgv2zww9",
                                  "0tzg9uyxrllwxldmvsp",
                                  "tlwrvbmf0zs1szxzlbd",
                                  # base64 encoded: stratum+tcp:// and stratum+udp://
                                  "c3ryyxr1bst0y3a6ly",
                                  "n0cmf0dw0rdgnwoi8v",
                                  "zdhjhdhvtk3rjcdovl",
                                  "c3ryyxr1bst1zha6ly",
                                  "n0cmf0dw0rdwrwoi8v",
                                  "zdhjhdhvtk3vkcdovl"}

    filter_command_line: set[str] ={" pool.c ", " pool.o ", "gcc -"}

    command_line = record.command_line.lower()

    selection = False
    for s in selection_command_line:
        if s in command_line:
            selection = True
            break

    filtered = False
    for f in filter_command_line:
        if f in command_line:
            filtered = True
            break

    if selection and not filtered:
        return Alert(rule_name = ProcessCreateRules.CRYPTO_MINING.value,
                     severity = Severity.HIGH,
                     mitre = "T1496",
                     message = "Command line parameters or strings used by crypto miners detected.",
                     event_record = record)

# === Sysmon EventID 3 Network Connection Rules === 

    # --- Start of network rules ---

def network_notepad_connection(record: "NetworkConnect") -> Optional[Alert]:
    # ATT&CK: T1055
    # Sigma: Network Connection Initiated Via Notepad.EXE

    if not record.image:
        return None 

    image = record.image.lower()

    if not image.endswith('notepad.exe'):
        return None

    if record.destination_port == "9100":
        return None

    return Alert(rule_name = NetworkRules.NOTEPAD_CONNECTION.value,
                 severity = Severity.HIGH,
                 mitre = "T1055",
                 message = "Notepad initated a network connection",
                 event_record = record)

def load_crypto_pools(path: str) -> set[str]:
    if not os.path.exists(path):
        post_log(f"[Detector] [Warning] Crypto pools file not found at {path}")
        return set()

    pools = set ()
    with open(path, 'r', encoding = 'utf-8') as file:
        for line in file:
            line = line.strip().lower()

            if line: 
                pools.add(line)

    return pools

def network_crypto_mining(crypto_pools: set[str]):
    def network_crypto_mining(record: "NetworkConnect") -> Optional[Alert]:
        # ATT&CK: T1496
        # Sigma: Network Communication With Crypto Mining Pool

        if not record.destination_hostname:
            return None

        dest_hostname = record.destination_hostname.lower()
        
        if dest_hostname not in crypto_pools:
            return None

        return Alert(rule_name = NetworkRules.CRYPTO_MINING.value,
                     severity = Severity.HIGH,
                     mitre = "T1496",
                     message = "Network connection to crypto mining pools",
                     event_record = record)

    return network_crypto_mining

def network_domain_ngrok(record: "NetworkConnect") -> Optional[Alert]:
    # ATT&CK: T1567, T1572, T1102
    # Sigma: Process Initiated Network Connection To Ngrok Domain

    if not record.destination_hostname:
        return None

    if record.initiated == "false":
        return None

    dest_hostname = record.destination_hostname.lower()
    ngrok_domains: set[str] = {".ngrok-free.app", ".ngrok-free.dev", ".ngrok.app", ".ngrok.dev", ".ngrok.io"}

    for domain in ngrok_domains:
        if dest_hostname.endswith(domain):
            return Alert(rule_name = NetworkRules.NGROK_DOMAIN_CONNECTION.value,
                 severity = Severity.HIGH,
                 mitre = "T1567, T1572, T1102",
                 message = "Executable initiated a network connection to 'ngrok' domains",
                 event_record = record)
    return None

def network_ngrok_tunnel(record: "NetworkConnect") -> Optional[Alert]:
    #ATT&CK: T1567, T1568.002, T1572, T1090, T1102, S0508
    #Sigma: Communication To Ngrok Tunneling Service Initiated

    if not record.destination_hostname:
        return None

    dest_hostname = record.destination_hostname.lower()

    ngrok_tunnels: set[str] = {"tunnel.us.ngrok.com", "tunnel.eu.ngrok.com", "tunnel.ap.ngrok.com", "tunnel.au.ngrok.com",
                               "tunnel.sa.ngrok.com", "tunnel.jp.ngrok.com", "tunnel.in.ngrok.com"}

    for tunnel in ngrok_tunnels:
        if tunnel in dest_hostname:
            return Alert(rule_name = NetworkRules.NGROK_TUNNEL_COMM.value,
                         severity = Severity.HIGH,
                         mitre = "T1567, T1568.002, T1572, T1090, T1102, S0508",
                         message = "Executable initiated a network connection to 'ngrok' tunneling domains",
                         event_record = record)

    return None
    
# --- End of Rules ---

PROCESS_RULES = [powershell_encoding, powershell_defender_exclusion, powershell_disable_defender_av]
def run_process_rules(record: "ProcessCreate") -> list[Alert]:
    alerts: list[Alert] = []
    for rule in PROCESS_RULES:
        alert = rule(record)
        if alert:
            post_log("[Detector] [ALERT] Suspicious process activity detected")
            alerts.append(alert)

    return alerts

BASE_NETWORK_RULES = [network_notepad_connection, network_domain_ngrok, network_ngrok_tunnel]
def run_network_rules(record: "NetworkConnect", network_rules: list[Callable[["NetworkConnect"], Optional[Alert]]]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in network_rules:
        alert = rule(record)
        if alert:
            post_log("[Detector] [ALERT] Suspicious network activity detected")
            alerts.append(alert)

    return alerts

def run_detection(event_records: EventRecords, network_rules: list[Callable[["NetworkConnect"], Optional[Alert]]]) -> list[Alert]:
    alerts: list[Alert] = []

    #run detection rules here while event records are still in memory
    for p_records in event_records.process_create:
        p_alert = run_process_rules(p_records)
        alerts.extend(p_alert)

    for n_records in event_records.network_connect:
        n_alert = run_network_rules(n_records, network_rules)
        alerts.extend(n_alert)

    return alerts

def insert_alerts(conn: sqlite3.Connection, alerts: list[Alert], logger) -> None:
    for alert in alerts:
        event_type: str | None = EVENT_TYPE_NAMES.get(alert.event_record.event_id)
        conn.execute("""insert into alerts(rule_name, mitre, message, severity,
                     timestamp, channel, record_id, event_type, event_record)
                     values(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                     (alert.rule_name, alert.mitre, alert.message, str(alert.severity), alert.timestamp,
                      alert.event_record.channel, alert.event_record.event_record_id, event_type, alert.event_to_json()))

        log_alert(alert, logger)

    conn.commit()
 
def run_detector(event_records: EventRecords, logger: logging.Logger) -> None:
    post_log("[Detector] Starting up")

    # Load the crypto pool blocklist once per detector run, bake it into
    # the mining rule via closure rather than reading the file per record
    crypto_pools: set[str] = load_crypto_pools(CRYPTO_POOLS_FILE)
    network_rules = BASE_NETWORK_RULES + [network_crypto_mining(crypto_pools)]

    conn: sqlite3.Connection | None = None

    total = len(event_records.process_create) + len(event_records.network_connect)

    try:
        conn = db_connect()
        post_log("[Detector] Connection to database established")
    except sqlite3.Error as e:
        post_log(f"[Detector] [Error] Failed to connect to database: {e}")
        return

    try:
        alerts: list[Alert] = run_detection(event_records, network_rules)
        if not alerts:
            post_log(f"[Detector] No alerts in {total} records")

        insert_alerts(conn, alerts, logger)
    except Exception as e:
        post_log(f"[Detector] [Error] Failed during detection or alert insertion: {e}")
    finally:
        if conn:
            conn.close()
            post_log(f"[Detector] Connection to database closed")
