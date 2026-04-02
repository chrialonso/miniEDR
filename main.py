from db.db import ensure_schema
from agent.collector import run_collector
from agent.parser import run_parser
from agent.detection import run_detector

def main():
    if not ensure_schema():
        print("[Main] [Error] Could not initialize database, exiting.")
        return

    run_collector()
    run_parser()
    run_detector()

if __name__ == "__main__":
    main()
