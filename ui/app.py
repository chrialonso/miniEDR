import threading
import logging
import queue
import psutil
import os
from collections import deque
from datetime import datetime
from textual.app import App, ComposeResult
from textual.widgets import Label
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from rich.text import Text
from ui.log_queue import log_queue, post_log 
from agent.collector import run_collector
from agent.parser import run_parser, EventRecords
from agent.detector import run_detector
from agent.maintenance import run_maintenance
from db.logger import setup_logger
from db.db import db_connect, get_db_size, DB_PATH
from agent.agent_state import AgentState
from ui.run_stats import get_run_stats, set_run_stats
from ui.constants import LOOP_INTERVAL, MAINTENANCE_INTERVAL_SECONDS, ITEMS, VIEW_IDS, FOOTER_ITEMS, PIPELINE_ITEMS
from ui.views import DashboardView, AlertsView, ComponentView, LogsView
from dataclasses import replace

class FocusableVertical(Vertical):
    can_focus = True

    def on_mount(self) -> None:
        self.app._set_panel_title_hkey("#FFFFFF") #type: ignore

    def on_descendant_focus(self) -> None:
        self.styles.border_bottom = ("solid", "#FFFFFF")
        self.app._set_panel_title_hkey("#FF9000") #type: ignore
        self.app._set_content_title_hkey("#FFFFFF") #type: ignore

    def on_descendant_blur(self) -> None:
        self.styles.border_bottom = ("solid", "#FF9000")
        self.app._set_panel_title_hkey("#FFFFFF") #type: ignore
        self.app._set_content_title_hkey("#FF9000") #type: ignore

class EDRApp(App):
    CSS_PATH = "styles/app.tcss"

    BINDINGS = [("q", "quit", "Quit"),
                ("Q", "quit", "Quit"),
                ("tab", "focus_next", "Next Pane"),
                ("d", "focus_next", "Next Pane"),
                ("a", "focus_previous", "Prev Pane"),
                ("x", "toggle_agent", "Toggle Agent")]

    selected_item = reactive(0)
    agent_state = reactive(AgentState())
    uptime_start: dict[str, datetime] = {}

    def compose(self) -> ComposeResult:
        with Horizontal(id = "title_row"):
            yield Label("miniEDR", id = "title_text")
            yield Label("v1.0", id = "title_version")

        with Vertical(id = "main_frame"):
            with Horizontal(id = "content_frame"):

                with Vertical(id = "sidebar_frame"):
                    with Vertical(id = "sidebar_wrapper"):
                        yield Label("◈ Navigation", classes = "panel-title")
                        with FocusableVertical(id = "sidebar"):
                            for item in ITEMS:
                                yield Label(item, classes = "nav-item")

                    with Vertical(id = "status_wrapper"):
                        yield Label("◈ Status", classes = "panel-title")
                        with Vertical(id = "status_frame"):
                            with Vertical(id = "status_content"):

                                yield Label("◆ Pipeline ", classes = "section-header")
                                for component in PIPELINE_ITEMS:
                                    yield Label(component, classes = "status-items")
                            with Vertical(id = "status_alert_content_frame"):

                                yield Label("◆ Telemetry ", classes = "section-header")
                                with Horizontal(classes = "status-row"):
                                    yield Label("Alerts", classes = "status-label")
                                    yield Label("0", id = "status_alert_count", classes = "status-val")

                with FocusableVertical(id = "content"):
                    yield Label("Dashboard Item", id = "content_panel_title")
                    yield DashboardView(id = "view_dashboard")
                    yield AlertsView(id = "view_alerts")
                    yield LogsView(id = "view_logs")
                    yield ComponentView(id = "view_components")

            with Horizontal(id = "footer"):
                for key, desc in FOOTER_ITEMS:
                    yield Label(key, classes = "footer-key")
                    yield Label(desc, classes = "footer-desc")

        with Horizontal(id = "footer_space"):
            yield Label("")

    def on_mount(self) -> None:
        self.query_one("#sidebar").border_subtitle = " ↑↓ to navigate "
        self.query_one("#sidebar").focus()
        
        self.db_size = get_db_size(DB_PATH)
        calc_db_size, db_unit = self.query_one(DashboardView).human_readable_size(self.db_size)
        self.query_one("#db_size", Label).update(f"{calc_db_size}{db_unit}")

        self.MAX_HISTORY = 30
        self.cpu_history: deque[float] = deque(maxlen = self.MAX_HISTORY)
        self.ram_history: deque[float] = deque(maxlen = self.MAX_HISTORY)

        self.proc_cpu_history: deque[float] = deque(maxlen = self.MAX_HISTORY)
        self.proc_ram_history: deque[float] = deque(maxlen = self.MAX_HISTORY)

        self._proc = psutil.Process(os.getpid())
        self._proc.cpu_percent(interval = None)
        self._cpu_count = psutil.cpu_count() or 1

        for view_id in VIEW_IDS.values():
            self.query_one(f"#{view_id}").display = False

        first_id = VIEW_IDS[ITEMS[0]]
        self.query_one(f"#{first_id}").display = True
        
        self.set_interval(0.5, self.drain_log_queue)
        self.set_interval(15, self.refresh_alerts)
        self.set_interval(0.5, self.refresh_uptime_counter)
        self.set_interval(1, self.refresh_stats)
        self.set_interval(1, self.refresh_pipeline_throughput)
        self.set_interval(15, self.refresh_disk_free)
        self.set_interval(15, self.refresh_db_size)
        self.set_interval(15, self.refresh_alert_summary)
        self.refresh_alerts()
        self.refresh_alert_summary()

        self._stop_event = threading.Event()
        self._agent_thread = threading.Thread(
                target = self._run_agent,
                args = (self._stop_event,),
                daemon = True)
        self._agent_thread.start()

    def on_unmount(self) -> None:
        self._stop_event.set()
        self._agent_thread.join(timeout = 5)

    def watch_selected_item(self, item) -> None:
        nav_items = self.query(".nav-item").results(Label)

        for i, item_label in enumerate(nav_items):
            if i == item:
                item_label.update(f" > {ITEMS[i]}")
                item_label.add_class("nav-selected")
            else:
                item_label.update(f" {ITEMS[i]} ")
                item_label.remove_class("nav-selected")

        self.query_one(f"#content_panel_title", Label).update("◈ " + ITEMS[item])

        for view_id in VIEW_IDS.values():
            self.query_one(f"#{view_id}").display = False
            
        selected_id = VIEW_IDS[ITEMS[item]]
        self.query_one(f"#{selected_id}").display = True

    def watch_agent_state(self, state: AgentState) -> None:
        comp_items = self.query(".status-items").results(Label)

        for i, component_label in enumerate(comp_items):
            enabled = getattr(state, PIPELINE_ITEMS[i].lower())

            if enabled and PIPELINE_ITEMS[i] not in self.uptime_start:
                self.uptime_start[PIPELINE_ITEMS[i]] = datetime.now()
            elif not enabled and PIPELINE_ITEMS[i] in self.uptime_start:
                del self.uptime_start[PIPELINE_ITEMS[i]]

            if enabled:
                component_label.update(Text.assemble(
                    ("🞕  ", "bold #FF9000"),
                    (f"{PIPELINE_ITEMS[i]}", "#FFFFFF")))
            else:
                component_label.update(Text.assemble(
                    ("🞎  ", "#777777"),
                    (f"{PIPELINE_ITEMS[i]}", "#777777"))) 

    def on_key(self, event) -> None:
        if self.focused and self.focused.id == "sidebar":
            if event.key == "down" or event.key == "s":
                self.selected_item = (self.selected_item + 1) % len(ITEMS)
            elif event.key == "up" or event.key == "w":
                self.selected_item = (self.selected_item - 1) % len(ITEMS)

    def _get_active_focusables(self) -> list:
        active_id = VIEW_IDS[ITEMS[self.selected_item]]
        active_view = self.query_one(f"#{active_id}")
        return list(active_view.query("DataTable, RichLog, ComponentView"))

    def action_focus_next(self) -> None:
        focusable = self._get_active_focusables()

        if self.focused and self.focused.id == "sidebar":
            if focusable:
                focusable[0].focus()
            else:
                self.query_one(f"#{VIEW_IDS[ITEMS[self.selected_item]]}").focus()

        elif self.focused in focusable:
            current_index = focusable.index(self.focused)
            next_index = current_index + 1

            if next_index < len(focusable):
                focusable[next_index].focus()
            else:
                self.query_one("#sidebar").focus()

        else:
           self.query_one("#sidebar").focus()

    def action_focus_previous(self) -> None:
        focusable = self._get_active_focusables()

        if self.focused and self.focused.id == "sidebar":
            if focusable:
                focusable[-1].focus()

        elif self.focused in focusable:
            current_index = focusable.index(self.focused)

            if current_index > 0:
                focusable[current_index - 1].focus()
            else:
                self.query_one("#sidebar").focus()

    def action_focus_sidebar(self) -> None:
        self.query_one("#sidebar").focus()

    def _set_content_title_hkey(self, color: str) -> None:
        self.query_one("#content_panel_title", Label).styles.border = ("hkey", color)
        self.query_one("#content_panel_title", Label).styles.color = color

    def _set_panel_title_hkey(self, color: str) -> None:
        self.query(".panel-title").first(Label).styles.border = ("hkey", color)
        self.query(".panel-title").first(Label).styles.color = color

    def action_toggle_agent(self) -> None:
        new_state = replace(self.agent_state)

        for component in PIPELINE_ITEMS:
            setattr(new_state, component.lower(), not getattr(self.agent_state, component.lower()))

        post_log("[Main] Toggled all agent components")
        self.agent_state = new_state
        self.query_one("#view_components", ComponentView).refresh_display()

    def update_alert_count(self, count: int) -> None:
        self.query_one(f"#status_alert_count", Label).update(f"{count}")
 
    def drain_log_queue(self) -> None:
        logs_view = self.query_one("#view_logs", LogsView)
        while True:
            try:
                message = log_queue.get_nowait()
                logs_view.write_log(message)
            except queue.Empty:
                break

    def _run_agent(self, stop_event: threading.Event) -> None:
        logger: logging.Logger = setup_logger()

        last_maintenance = datetime.now()

        try:
            while not stop_event.is_set():
                state = self.agent_state

                collector_ok = True
                if state.collector:
                    if not state.parser:
                        post_log("[Main] Skipping Collector: Parser is disabled")
                    else:
                        collector_ok = run_collector()

                records: EventRecords | None = None
                if state.parser and collector_ok:
                    records = run_parser()
                    set_run_stats(
                            len(records.process_create) if records else 0,
                            len(records.network_connect) if records else 0,
                            last_maintenance)
                                
                if state.detector:
                    if records is None:
                        if not state.parser:
                            post_log("[Main] Skipping Detection: Parser is disabled")
                        else:
                            post_log("[Main] [Error] Parser failed, skipping detection")
                    elif records.process_create or records.network_connect:
                        run_detector(records, logger)

                elapsed = (datetime.now() - last_maintenance).total_seconds()
                if elapsed>= MAINTENANCE_INTERVAL_SECONDS:
                    if state.maintenance:
                        run_maintenance(run_vacuum = True)
                        last_maintenance = datetime.now()

                # Poll in short increments rather than a single long sleep so that a 
                # SIGINT/ SIGTERM is acted on quickly instead of waiting up to LOOP_INTERVAL seconds
                for _ in range(LOOP_INTERVAL * 2):
                    if stop_event.is_set():
                        break
                    stop_event.wait(timeout = 0.5)
        except Exception as e:
            post_log(f"[Main] [Error] Unhandled exception in agent loop: {e}")

    def refresh_alerts(self) -> None:
        self.query_one("#view_alerts", AlertsView).load_alerts()

    def refresh_uptime_counter(self) -> None:
        uptimes: list[str] = []

        for comp in PIPELINE_ITEMS:
            start = self.uptime_start.get(comp)
            if start:
                elapsed = datetime.now() - start
                uptimes.append(str(elapsed).split(".")[0])
            else:
                uptimes.append("--:--:--")

        self.query_one(DashboardView).update_uptime(uptimes)

    def refresh_stats(self) -> None:
        if getattr(self, '_fetching_stats', False):
            return

        self._fetching_stats = True
        threading.Thread(target = self._fetch_stats, daemon = True).start()

    def _fetch_stats(self) -> None:
        try:
            cpu: float = psutil.cpu_percent(interval = 0.5) #type: ignore
            ram: float = psutil.virtual_memory().percent

            proc_cpu = self._proc.cpu_percent(interval = None) / self._cpu_count
            proc_ram = self._proc.memory_percent()

            self.call_from_thread(self._update_stats, cpu, ram, proc_cpu, proc_ram)
        finally:
            self._fetching_stats = False

    def _update_stats(self, cpu, ram, proc_cpu, proc_ram) -> None:
        self.cpu_history.append(cpu)
        self.ram_history.append(ram)

        self.proc_cpu_history.append(proc_cpu)
        self.proc_ram_history.append(proc_ram)

        self.query_one(DashboardView).update_system_stats(cpu, ram, self.cpu_history, self.ram_history)
        self.query_one(DashboardView).update_proc_stats(proc_cpu, proc_ram, self.proc_cpu_history, self.proc_ram_history)

    def refresh_disk_free(self) -> None:
        if getattr(self, '_fetching_disk_free', False):
            return

        self._fetching_disk_free = True
        threading.Thread(target = self._fetch_disk_free, daemon = True).start()

    def _fetch_disk_free(self) -> None:
        try:
            disk_free = psutil.disk_usage("/").free
            self.call_from_thread(self._update_disk_free, disk_free)
        finally:
            self._fetching_disk_free = False

    def _update_disk_free(self, disk_free) -> None:
        dash_view = self.query_one(DashboardView)
        disk_size, disk_unit = dash_view.human_readable_size(disk_free)
        dash_view.update_disk_free(disk_size, disk_unit)

    def refresh_db_size(self) -> None:
        if getattr(self, '_fetching_db_size', False):
            return

        self._fetching_db_size = True
        threading.Thread(target = self._fetch_db_size, daemon = True).start()

    def _fetch_db_size(self) -> None:
        try:
            db_size: int = get_db_size(DB_PATH)
            self.call_from_thread(self._update_db_size, db_size)
        finally:
            self._fetching_db_size = False

    def _update_db_size(self, db_size: int) -> None:
        dash_view = self.query_one(DashboardView)
        calc_db_size, db_unit = dash_view.human_readable_size(db_size)
        dash_view.update_db_size(calc_db_size, db_unit)

    def refresh_pipeline_throughput(self) -> None:
        stats = get_run_stats()
        self.query_one(DashboardView).update_event_count(stats)

        if stats.timestamp:
            age = (datetime.now() - stats.timestamp).seconds
            self.query_one(DashboardView).update_last_run(age)

        if stats.last_maintenance is None:
            seconds_left = MAINTENANCE_INTERVAL_SECONDS
        else:
            elapsed = (datetime.now() - stats.last_maintenance).total_seconds()
            seconds_left = MAINTENANCE_INTERVAL_SECONDS - elapsed

        seconds_left = max(seconds_left, 0)

        self.query_one(DashboardView).update_vacuum_timer(seconds_left)

    def refresh_alert_summary(self) -> None:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        try:
            conn = db_connect()
            rows = conn.execute("select severity, count(*) from alerts group by severity").fetchall()
            conn.close()    

            for severity, count in rows:
                if severity.lower() in counts:
                    counts[severity.lower()] = count
            
        except Exception as e:
            post_log(f"[UI] [Error] Failed to update alert summary: {e}")

        self.query_one(DashboardView).update_alert_summary(counts)
