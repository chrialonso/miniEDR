import logging
import json
from datetime import datetime, timezone
import os
from typing import TYPE_CHECKING
from dataclasses import asdict

if TYPE_CHECKING:
    from agent.detector import Alert

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
ALERT_LOG_PATH: str = os.path.join(LOGS_DIR, "Alerts.log")
ALERT_JSONL_PATH: str = os.path.join(LOGS_DIR, "Alerts.jsonl")

class JsonFormatter(logging.Formatter):
    def format(self, record) -> str:
        levelname: str = record.levelname
        message: str = record.getMessage()
        timestamp: str = datetime.fromtimestamp(record.created, tz = timezone.utc).isoformat(timespec = "seconds")
        rule_name = getattr(record, "rule_name", None)
        severity = getattr(record, "severity", None)
        mitre = getattr(record, "mitre", None)
        event = getattr(record, "event", None)
        
        d = {"level": levelname, "timestamp": timestamp, "message": message,
             "rule_name": rule_name,"severity": severity, "mitre": mitre, "event": event}

        return json.dumps(d, ensure_ascii = False)

def setup_logger() -> logging.Logger: 
    os.makedirs(LOGS_DIR, exist_ok = True)

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        log_handler = logging.FileHandler(ALERT_LOG_PATH)
        jsonl_handler = logging.FileHandler(ALERT_JSONL_PATH)

        jsonl_handler.setFormatter(JsonFormatter()) 
        logger.addHandler(jsonl_handler)
       
        log_formatter = logging.Formatter("Rule name: %(rule_name)s | Severity: %(severity)s | MITRE: %(mitre)s\n"
                                      "Message: %(message)s\n"
                                      "Event:\n%(event_log_string)s\n"
                                      "----------------------------------------\n")
        log_handler.setFormatter(log_formatter)
        logger.addHandler(log_handler)

    return logger

def log_alert(alert: 'Alert', logger: logging.Logger) -> None:
    logger.warning(alert.message, extra = {"rule_name": alert.rule_name,
                                           "severity": str(alert.severity),
                                           "mitre": alert.mitre,
                                           "event": asdict(alert.event_record),
                                           "event_log_string": alert.event_record.to_log()})
