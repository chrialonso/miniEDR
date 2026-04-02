## Overview

The pipeline works in three stages:
- **Collector** — queries the Windows Event Log for new Sysmon events and writes them to a spool directory
- **Parser** — reads from the spool, parses the XML, and inserts structured records into SQLite
- **Detection** — runs rules against parsed records to generate alerts (WIP)
