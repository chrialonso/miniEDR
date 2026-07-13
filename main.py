from ui.app import EDRApp
from db.db import ensure_schema
from ui.log_queue import post_log
import sys

def main() -> None:
    if not ensure_schema():
        post_log("[Main] [Fatal] Could not initialize database, exiting.")
        sys.exit(1)

    app = EDRApp()
    app.run()

if __name__ == "__main__":
    main()
