from textual.app import ComposeResult
from textual.widgets import RichLog, DataTable, Static, Label
from textual.containers import Vertical, Horizontal
from rich.text import Text
from db.logger import ALERT_LOG_PATH, ALERT_JSONL_PATH
from db.db import db_connect
from ui.constants import SEVERITY_COLORS
from ui.log_queue import post_log
import json

class AlertsView(Static):
    def compose(self) -> ComposeResult:
        with Vertical(id = "alerts_frame"):
            yield DataTable(id = "alerts_table")

            with Vertical(id = "alerts_detail_frame"):
                yield RichLog(id = "alert_detail", wrap = True, highlight = True, markup = False)

        with Vertical(id = "alerts_path_frame"):
            with Horizontal(classes = "alerts_path_row"):
                yield Label("◈ Alerts.log", classes = "alerts-path-label")
                yield Label("-", id = "alerts_txt_label", classes = "alerts-path-value")

            with Horizontal(classes = "alerts_path_row"):
                yield Label("◈ Alerts.jsonl", classes = "alerts-path-label")
                yield Label("-", id = "alerts_jsonl_label", classes = "alerts-path-value")

    def on_mount(self) -> None:
        table = self.query_one("#alerts_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("ID", "Rule", "Severity", "MITRE", "Timestamp")
        self.query_one("#alert_detail", RichLog).write("Select an alert to see details")

        self.query_one("#alerts_txt_label", Label).update(ALERT_LOG_PATH)
        self.query_one("#alerts_jsonl_label", Label).update(ALERT_JSONL_PATH)

        self._max_loaded_id: int = 0

    def load_alerts(self) -> None:
        table = self.query_one("#alerts_table", DataTable)
        conn = None

        try:
            conn = db_connect()
            count = conn.execute("select count(*) from alerts").fetchone()
            self.app.update_alert_count(count[0]) #type: ignore

            # skip table redraw if nothing has changed since the last poll.
            # This prevents scroll position reset/flickering the table every 15 seconds.
            if self._max_loaded_id > 0:
                new_check = conn.execute("select 1 from alerts where id > ? limit 1", (self._max_loaded_id,)).fetchone()
                if not new_check:
                    return

            rows = conn.execute("select id, rule_name, severity, mitre, timestamp from alerts order by id desc limit 1000").fetchall()

            saved_row: int = table.cursor_row if table.row_count > 0 else 0
            table.clear()

            new_max_id = self._max_loaded_id

            for row in rows:
                alert_id, rule_name, severity, mitre, timestamp = row

                color = SEVERITY_COLORS.get(severity, "#FFFFFF")

                table.add_row(Text(str(alert_id), style = "#FFFFFF"),
                              Text(rule_name, style = "#FFFFFF"),
                              Text(severity, style = color),
                              Text(mitre, style = "#FF9000"),
                              Text(timestamp, style = "#FFFFFF"),
                              key = str(alert_id))

                if alert_id > new_max_id:
                    new_max_id = alert_id
                    
            self._max_loaded_id = new_max_id

            if table.row_count > 0:
                table.move_cursor(row = min(saved_row, table.row_count - 1))

        except Exception as e:
            post_log(f"[UI] [Error] Failed to load alerts: {e}")
        finally:
            if conn:
                conn.close()
 
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        detail = self.query_one("#alert_detail", RichLog)
        detail.clear()
        conn = None

        try:
            conn = db_connect()
            row = conn.execute("select id, rule_name, mitre, message, severity, timestamp, event_type, event_record from alerts where id = ?", (event.row_key.value,)).fetchone()

            if row:
                alert_id, rule_name, mitre, message, severity, timestamp, event_type, event_record = row
                color = SEVERITY_COLORS.get(severity, "#FFFFFF")
                event_data = json.loads(event_record) if event_record else {}
                
                text = Text()
                text.append(f"ID:           {alert_id}\n", style = "#FFFFFF")
                text.append(f"Rule:         {rule_name}\n", style = "#FFFFFF")
                text.append(f"MITRE:        {mitre}\n", style = "#FF9000")
                text.append(f"Severity:     {severity.capitalize()}\n", style = color)
                text.append(f"Time:         {timestamp}\n", style = "#FFFFFF")
                text.append(f"Message:      {message}\n", style = "#FFFFFF")

                if event_type == "process_create":
                    _render_process_create(text, event_data)
                elif event_type == "network_connect":
                    _render_network_connect(text, event_data)

                detail.write(text, scroll_end = False)
        except Exception as e:
            detail.write(f"Error loading detail: {e}")
        finally:
            if conn:
                conn.close()

def _render_process_create(text: Text, d: dict) -> None:
    text.append("\n— Process Event —\n", style="bold #FFFFFF")
    text.append(f"  User:             {d.get('process_user')}\n", style="#FFFFFF")
    text.append(f"  PID:              {d.get('process_id')}\n", style="#FFFFFF")
    text.append(f"  Parent Image:     {d.get('parent_image')}\n", style="#FFFFFF")
    text.append(f"  Image:            {d.get('image')}\n", style="#FFFFFF")
    text.append(f"  Parent CLI:       {d.get('parent_command_line')}\n", style="#FFFFFF")
    text.append(f"  Command Line:     {d.get('command_line')}\n", style="#FFFFFF")
    text.append(f"  Integrity:        {d.get('integrity_level')}\n", style="#FFFFFF")
    text.append(f"  Hashes:           {d.get('hashes')}\n", style="#FFFFFF")

def _render_network_connect(text: Text, d: dict) -> None:
    text.append("\n— Network Event —\n", style="bold #FFFFFF")
    text.append(f"  Image:            {d.get('image')}\n", style="#FFFFFF")
    text.append(f"  User:             {d.get('process_user')}\n", style="#FFFFFF")
    text.append(f"  Protocol:         {d.get('protocol')}\n", style="#FFFFFF")
    text.append(f"  Source:           {d.get('source_ip')}:{d.get('source_port')}\n", style="#FFFFFF")
    text.append(f"  Destination:      {d.get('destination_ip')}:{d.get('destination_port')}\n", style="#FFFFFF")
    text.append(f"  Hostname:         {d.get('destination_hostname')}\n", style="#FFFFFF")
    text.append(f"  Initiated:        {d.get('initiated')}\n", style="#FFFFFF")
