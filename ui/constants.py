LOOP_INTERVAL: int = 15

MAINTENANCE_INTERVAL_SECONDS: int = 3600 * 24

ITEMS = ["Dashboard", "Alerts", "Logs", "Components"]

VIEW_IDS = {"Dashboard": "view_dashboard",
            "Alerts": "view_alerts",
            "Logs": "view_logs",
            "Components": "view_components"}

FOOTER_ITEMS = [("q: ", "Quit"),
                ("TAB: ", "Next Pane"),
                ("SHIFT + TAB", " Last Pane"),
                ("ENTER: ", "Select"),
                ("x: ", "Toggle Agent"),
                ("^p: ", "Palette")]

SEVERITY_COLORS = {"low": "yellow",
                   "medium": "#FF8C00",
                   "high": "red",
                   "critical": "bold red"}

PIPELINE_ITEMS = ["Collector", "Parser", "Detector", "Maintenance"]

PIPELINE_DESCRIPTIONS = {"Collector": "Reads Sysmon events from Windows Event Log and writes them to the spool inbox",
                         "Parser": "Parses spool files, extracts fields from XML, and inserts records into the database",
                         "Detector": "Runs detection rules against parsed records and writes alerts to the database",
                         "Maintenance": "Purges old events from the database and runs periodic vacuum to reclaim space"}


