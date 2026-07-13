from dataclasses import dataclass
from datetime import datetime
import threading

@dataclass(frozen = True)
class RunStats:
    process_create: int = 0
    network_connect: int = 0
    timestamp: datetime | None = None
    last_maintenance: datetime | None = None

_run_stats_lock = threading.Lock()
_run_stats = RunStats()

def set_run_stats(process_create: int, network_connect: int, last_maintenance: datetime) -> None:
    global _run_stats
    with _run_stats_lock:
        _run_stats = RunStats(process_create, network_connect, datetime.now(), last_maintenance)

def get_run_stats() -> RunStats:
    with _run_stats_lock:
        return _run_stats
