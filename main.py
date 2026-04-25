from db.db import ensure_schema
from agent.collector import run_collector
from agent.parser import run_parser, ProcessCreate, NetworkConnect
from agent.detector import run_detector

def main():
    if not ensure_schema():
        print("[Main] [Error] Could not initialize database, exiting.")
        return

    run_collector()
    records: tuple[list[ProcessCreate], list[NetworkConnect]] | None = run_parser()

    if records is None:
        print("[Main] [Error] Parser failed, skipping detection")
        return

    run_detector(records)

if __name__ == "__main__":
    main()
