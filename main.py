from agent.maintenance import run_maintenance
from db.db import ensure_schema
from agent.collector import run_collector
from agent.parser import run_parser, ProcessCreate, NetworkConnect
from agent.detector import run_detector
import threading
import signal
import logging

from db.logger import setup_logger

LOOP_INTERVAL: int = 30

def main():
    stop_event = threading.Event()

    def handle_shutdown(signum, frame):
        print("[Main] Received stop signal")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_shutdown) # CTRL + C
    signal.signal(signal.SIGTERM, handle_shutdown)

    logger: logging.Logger = setup_logger()

    if not ensure_schema():
        print("[Main] [Error] Could not initialize database, exiting.")
        return

    # Tracks how many loop iterations have run so we know when to trigger periodic
    # maintenance. 30 seconds per loop, 2880 loops is about every 24 hours
    run_count = 0 
    while not stop_event.is_set():
        run_collector()
        records: tuple[list[ProcessCreate], list[NetworkConnect]] | None = run_parser()

        if records is None:
            print("[Main] [Error] Parser failed, skipping detection")
        elif records[0] or records[1]:
            run_detector(records, logger)

        run_count += 1
        if run_count >= 2880:
            run_maintenance(run_vacuum = True)
            run_count = 0

        # Poll in short increments rather than a single long sleep so that a 
        # SIGINT/ SIGTERM is acted on quickly instead of waiting up to LOOP_INTERVAL seconds
        for _ in range(LOOP_INTERVAL * 2):
            if stop_event.is_set():
                break
            stop_event.wait(timeout=0.5)

    print("[Main] Shutdown complete!")

if __name__ == "__main__":
    main()
