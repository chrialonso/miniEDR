from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING, Callable
from db.db import db_connect
from enum import Enum
import sqlite3
import os

CRYPTO_POOLS_FILE: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crypto_pools.txt")

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
    event_record: 'ProcessCreate | NetworkConnect'
    timestamp: str = field(default_factory=get_datetime_iso)

class PowershellRules(Enum):
    ENCODED_COMMAND = "powershell_encoded_command"
    DEFENDER_EXCLUSION = "powershell_defender_exclusion"
    DISABLE_DEFENDER_AV = "powershell_disable_defender_av"

class NetworkRules(Enum):
    NOTEPAD_CONNECTION = "network_notepad_connection"
    CRYPTO_MINING = "network_crypto_connection"
    NGROK_DOMAIN_CONNECTION = "network_ngrok_domain_connection"
    NGROK_TUNNEL_COMM = "network_ngrok_tunnel_communication"

# --- Sysmon EventID 1 Detection Rules ---

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

def powershell_defender_exclusion(record: "ProcessCreate") -> Optional[Alert]:
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

# --- Sysmon EventID 3 Network Connection Rules --- 

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
        print(f"[Detector] [Warning] Crypto pools file not found at {path}")
        return set()

    pools = set ()
    with open(path, 'r', encoding = 'utf-8') as file:
        for line in file:
            line = line.strip().lower()

            if line: 
                pools.add(line)

    return pools

def make_crypto_mining_rule(crypto_pools: set[str]):
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
            print("[Detector] [ALERT] Suspicious process activity detected")
            alerts.append(alert)

    return alerts

NETWORK_RULES = [network_notepad_connection, network_domain_ngrok, network_ngrok_tunnel]
def run_network_rules(record: "NetworkConnect", network_rules: list[Callable[["NetworkConnect"], Optional[Alert]]]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in network_rules:
        alert = rule(record)
        if alert:
            print("[Detector] [ALERT] Suspicious network activity detected")
            alerts.append(alert)

    return alerts

def run_detection(records: tuple[list["ProcessCreate"], list['NetworkConnect']], network_rules: list[Callable[["NetworkConnect"], Optional[Alert]]]) -> list[Alert]:
    process_records, network_records = records
    alerts: list[Alert] = []

    #run detection rules here while event records are still in memory
    for p_records in process_records:
        p_alert = run_process_rules(p_records)
        alerts.extend(p_alert)

    for n_records in network_records:
        n_alert = run_network_rules(n_records, network_rules)
        alerts.extend(n_alert)

    return alerts

def insert_alerts(conn: sqlite3.Connection, alerts: list[Alert]) -> None:
    for alert in alerts:
        conn.execute("""insert into alerts(rule_name, mitre, message, severity,
                     timestamp, channel, record_id)
                     values(?, ?, ?, ?, ?, ?, ?)""",
                     (alert.rule_name, alert.mitre, alert.message, str(alert.severity), alert.timestamp,
                      alert.event_record.channel, alert.event_record.event_record_id))
    conn.commit()
 
def run_detector(records: tuple[list["ProcessCreate"], list["NetworkConnect"]]) -> None:
    print("[Detector] Starting up")
    crypto_pools: set[str] = load_crypto_pools(CRYPTO_POOLS_FILE)
    network_rules = NETWORK_RULES + [make_crypto_mining_rule(crypto_pools)]

    conn: sqlite3.Connection | None = None

    process_create, network_connect = records
    total = len(process_create) + len(network_connect)

    try:
        conn = db_connect()
        print("[Detector] Connection to database established")
    except sqlite3.Error as e:
        print(f"[Detector] [Error] Failed to connect to database: {e}")
        return

    try:
        alerts: list[Alert] = run_detection(records, network_rules)
        if not alerts:
            print(f"[Detector] No alerts in {total} records")

        insert_alerts(conn, alerts)
    except Exception as e:
        print(f"[Detector] [Error] Failed during detection or alert insertion: {e}")
    finally:
        if conn:
            conn.close()
            print(f"[Detector] Connection to database closed")
