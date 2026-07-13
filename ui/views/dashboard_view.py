from textual.app import ComposeResult
from textual.widgets import Label, ProgressBar, Sparkline, Static
from textual.containers import Horizontal, Vertical
import psutil
import threading
from collections import deque
from ui.run_stats import RunStats
from ui.constants import PIPELINE_ITEMS

DASH_PROC_ROW_COUNT = 5

class DashboardView(Static):
    def compose(self) -> ComposeResult:
        self.set_interval(5, self.refresh_top_processes)

        with Horizontal(id = "dash_row_one"):

            with Vertical(classes = "dash-panel"):
                with Horizontal(classes = "panel-header"):
                    yield Label("◆ System Resources", classes = "dash-section-header")

                with Horizontal(classes = "dash-label-row"):
                    yield Label("CPU", classes = "dash-label")
                    yield Label("0.0%", id = "cpu_val", classes = "dash-stat-val")
                with Horizontal(classes = "dash-stat-row"):
                    yield ProgressBar(total = 100, id = "cpu_bar", show_eta = False, show_percentage = False)
                yield Sparkline([], id = "cpu_spark", summary_function = max)

                with Horizontal(classes = "dash-label-row"):
                    yield Label("RAM", classes = "dash-label")
                    yield Label("0.0%", id = "ram_val", classes = "dash-stat-val")
                with Horizontal(classes = "dash-stat-row"):
                    yield ProgressBar(total = 100, id = "ram_bar", show_eta = False, show_percentage = False)
                yield Sparkline([], id = "ram_spark", summary_function = max)

                with Horizontal(classes = "sys-row"):
                    yield Label("Free Disk Space", classes = "sys-label")
                    yield Label("--", id = "tele_disk_free", classes = "sys-val")

            with Vertical(id = "dash_agent_load_frame", classes = "dash-panel"):
                with Horizontal(classes = "panel-header"):
                    yield Label("◆ mini EDR Load", classes = "dash-section-header")

                with Horizontal(classes = "dash-label-row"):
                    yield Label("CPU", classes = "dash-label")
                    yield Label("0.0%", id = "proc_cpu_val", classes = "dash-stat-val")
                with Horizontal(classes = "dash-stat-row"):
                    yield ProgressBar(total = 100, id = "proc_cpu_bar", show_eta = False, show_percentage = False)
                yield Sparkline([], id = "proc_cpu_spark", summary_function = max)

                with Horizontal(classes = "dash-label-row"):
                    yield Label("RAM", classes = "dash-label")
                    yield Label("0.0%", id = "proc_ram_val", classes = "dash-stat-val")
                with Horizontal(classes = "dash-stat-row"):
                    yield ProgressBar(total = 100, id = "proc_ram_bar", show_eta = False, show_percentage = False)
                yield Sparkline([], id = "proc_ram_spark", summary_function = max)               

                with Horizontal(classes = "edr-load-row"):
                    yield Label("DB Size", classes = "edr-load-label")
                    yield Label("--", id = "db_size", classes = "edr-load-val")

                with Horizontal(classes = "edr-load-row"):
                    yield Label("Last Run", id = "last_run", classes = "edr-load-label")
                    yield Label("--", id = "last_run_timer", classes = "edr-load-val")

            with Vertical(classes = "dash-panel"):
                with Horizontal(classes = "panel-header"):
                    yield Label("◆ Pipeline Health", classes = "dash-section-header") 
                with Vertical(classes = "uptime-frame"):
                    for comp in PIPELINE_ITEMS:
                        with Vertical(classes = "uptime-row"):
                            yield Label(comp, classes = "comp-uptime-label")
                            yield Label("--:--:--", classes = "uptime")

                with Horizontal(classes = "uptime-stats-row"):
                    yield Label("Events This Run", classes = "uptime-event-label")
                    yield Label("0", id = "uptime_event_val", classes = "uptime-event-val")
                    
                with Horizontal(classes = "uptime-stats-row"):
                    yield Label("Next Vacuum", classes = "uptime-event-label")
                    yield Label("-", id = "uptime_next_vacuum", classes = "uptime-event-val")

        with Horizontal(id = "dash_row_two"):

            with Vertical(classes = "dash-panel"):
                with Vertical(classes = "procs-frame"):
                    with Horizontal(classes = "panel-header"):
                        yield Label("◆ Top CPU Processes", classes = "dash-section-header")
                    for i in range(DASH_PROC_ROW_COUNT):
                        with Horizontal(classes = "dash-proc-row"):
                            yield Label("-", id = f"top_cpu_name_{i}", classes = "dash-proc-name")
                            yield Label("0.0%", id = f"top_cpu_val_{i}", classes = "proc-val")

            with Vertical(classes = "dash-panel"): 
                with Horizontal(classes = "panel-header"):
                    yield Label("◆ Top RAM Processes", classes = "dash-section-header")
                for i in range(DASH_PROC_ROW_COUNT):
                    with Horizontal(classes = "dash-proc-row"):
                        yield Label("-", id = f"top_ram_name_{i}", classes = "dash-proc-name")
                        yield Label("0.0%", id = f"top_ram_val_{i}", classes = "proc-val")

            with Vertical(classes = "dash-panel"): 
                with Horizontal(classes = "panel-header"):
                    yield Label("◆ Alert Summary", classes = "dash-section-header")

                with Vertical(classes = "alerts-summary-frame"):
                    with Horizontal(classes = "alerts-summary-row"):
                        yield Label("Total", id = "summary_total", classes = "alerts-summary-label")
                        yield Label("-", id = "summary_total_val", classes = "alerts-summary-val")
                        
                    with Horizontal(classes = "alerts-summary-row"):
                        yield Label("Critical", id = "summary_critical", classes = "alerts-summary-label")
                        yield Label("-", id = "summary_critical_val", classes = "alerts-summary-val")

                    with Horizontal(classes = "alerts-summary-row"):
                        yield Label("High", id = "summary_high", classes = "alerts-summary-label")
                        yield Label("-", id = "summary_high_val", classes = "alerts-summary-val")

                    with Horizontal(classes = "alerts-summary-row"):
                        yield Label("Medium", id = "summary_medium", classes = "alerts-summary-label")
                        yield Label("-", id = "summary_medium_val", classes = "alerts-summary-val")

                    with Horizontal(classes = "alerts-summary-row"):
                        yield Label("Low", id = "summary_low", classes = "alerts-summary-label")
                        yield Label("-", id = "summary_low_val", classes = "alerts-summary-val")

    def on_mount(self) -> None:
        self.disk_free = psutil.disk_usage("/")

        disk_size, disk_unit = self.human_readable_size(self.disk_free[2])
        self.query_one("#tele_disk_free", Label).update(f"{disk_size}{disk_unit}")

        # primes psutil's internal per-process CPU delta baseline otherwise the next cpu_percent returns a meaningless 0.0 for each process
        for _ in psutil.process_iter(["cpu_percent"]):
            pass

        self._fetching_process = False

    def update_disk_free(self, disk_size, disk_unit) -> None: 
        self.query_one("#tele_disk_free", Label).update(f"{disk_size}{disk_unit}")

    def update_system_stats(self, cpu: float, ram: float, cpu_history: deque[float], ram_history: deque[float]) -> None:
        self.query_one("#cpu_bar", ProgressBar).progress = cpu
        self.query_one("#cpu_val", Label).update(f"{cpu:.1f}%")

        self.query_one("#ram_bar", ProgressBar).progress = ram
        self.query_one("#ram_val", Label).update(f"{ram:.1f}%")

        cpu_spark = self.query_one("#cpu_spark", Sparkline)
        cpu_spark.data = cpu_history
        cpu_spark.refresh()

        ram_spark = self.query_one("#ram_spark", Sparkline)
        ram_spark.data = ram_history
        ram_spark.refresh()

    def update_proc_stats(self, proc_cpu, proc_ram, proc_cpu_history: deque[float], proc_ram_history: deque[float]) -> None:
        self.query_one("#proc_cpu_bar", ProgressBar).progress = proc_cpu
        self.query_one("#proc_cpu_val", Label).update(f"{proc_cpu:.1f}%")

        self.query_one("#proc_ram_bar", ProgressBar).progress = proc_ram
        self.query_one("#proc_ram_val", Label).update(f"{proc_ram:.1f}%")

        proc_cpu_spark = self.query_one("#proc_cpu_spark", Sparkline)
        proc_cpu_spark.data = proc_cpu_history
        proc_cpu_spark.refresh()

        proc_ram_spark = self.query_one("#proc_ram_spark", Sparkline)
        proc_ram_spark.data = proc_ram_history
        proc_ram_spark.refresh()

    def update_last_run(self, age: int) -> None:
            minute = age // 60

            if minute >= 1:
                self.query_one("#last_run_timer", Label).update(f"{minute}m ago")
            else:
                self.query_one("#last_run_timer", Label).update(f"{age}s ago")

    def update_db_size(self, calc_db_size: float, db_unit: str) -> None:
        self.query_one("#db_size", Label).update(f"{calc_db_size}{db_unit}")

    def update_event_count(self, stats: RunStats) -> None:
        total_event_count = stats.process_create + stats.network_connect
        self.query_one("#uptime_event_val", Label).update(f"{total_event_count}")

        #self.query_one("#tele_process_count", Label).update(str(stats.process_create))
        #self.query_one("#tele_network_count", Label).update(str(stats.network_connect))

    def update_vacuum_timer(self, seconds_left: float) -> None:
        total_seconds = int(seconds_left)
        hours, remainder = divmod(total_seconds, 3600)
        minutes = remainder // 60

        self.query_one("#uptime_next_vacuum", Label).update(f"{hours}h {minutes}m")

    def update_uptime(self, uptimes) -> None:
        uptime_timers = self.query(".uptime").results(Label)
        uptime_labels = self.query(".comp-uptime-label").results(Label)
        uptime_rows = self.query(".uptime-row").results(Vertical)

        for i, (timer, row, label) in enumerate(zip(uptime_timers, uptime_rows, uptime_labels)):
            if uptimes[i] == "--:--:--":
                timer.update(uptimes[i])
                timer.add_class("offline")
                row.add_class("offline")
                label.add_class("offline")
            else:
                timer.update(uptimes[i])
                timer.remove_class("offline")
                row.remove_class("offline")
                label.remove_class("offline")

    def human_readable_size(self, size: float) -> tuple[float, str]:
        counter = 0
        units: dict[int, str] = {0: "B",
                                 1: "KB",
                                 2: "MB",
                                 3: "GB",
                                 4: "TB",
                                 5: "PB"}

        while size >= 1024 and counter < len(units) - 1:
            size = round(size / 1024, 2)
            counter += 1

        unit = units.get(counter, "?")
        return size, unit

    def get_top_processes(self) -> tuple[list[tuple[str, float]], list[tuple[str, float]]]:
        cpu_list: list[tuple[str, float]] = []
        ram_list: list[tuple[str, float]] = []

        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
            try:
                info = getattr(p, "info")

                if info['pid'] == 0:
                    continue

                name = info["name"] or "?"
                cpu_percent = info["cpu_percent"] or 0.0
                rss = info["memory_info"].rss if info["memory_info"] else 0.0

                cpu_list.append((name, cpu_percent))
                ram_list.append((name, rss))

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        cpu_list.sort(key = lambda x: x[1], reverse = True)
        ram_list.sort(key = lambda x: x[1], reverse = True)

        return cpu_list[:DASH_PROC_ROW_COUNT], ram_list[:DASH_PROC_ROW_COUNT]

    def update_alert_summary(self, counts: dict[str, int]) -> None:
        vals = counts.values()
        total = 0

        for val in vals:
            total += val

        self.query_one("#summary_total_val", Label).update(f"{total}")
        self.query_one("#summary_critical_val", Label).update(f"{counts.get('critical')}")
        self.query_one("#summary_high_val", Label).update(f"{counts.get('high')}")
        self.query_one("#summary_medium_val", Label).update(f"{counts.get('medium')}")
        self.query_one("#summary_low_val", Label).update(f"{counts.get('low')}")

    def refresh_top_processes(self) -> None:
        if getattr(self, '_fetching_process', False):
            return

        self._fetching_process = True

        threading.Thread(target = self._fetch_top_processes, daemon = True).start()

    def _fetch_top_processes(self) -> None:
        try:
            top_cpu, top_ram = self.get_top_processes()
            self.app.call_from_thread(self.update_top_processes, top_cpu, top_ram)
        finally:
            self._fetching_process = False

    def update_top_processes(self, top_cpu: list[tuple[str, float]], top_ram: list[tuple[str, float]]) -> None:
        for i in range(DASH_PROC_ROW_COUNT):
            if i < len(top_cpu):
                cpu_name, cpu = top_cpu[i]
                self.query_one(f"#top_cpu_name_{i}", Label).update(cpu_name)
                self.query_one(f"#top_cpu_val_{i}", Label).update(f"{cpu:.1f}%")
            else:
                self.query_one(f"#top_cpu_name_{i}", Label).update("-")
                self.query_one(f"#top_cpu_val_{i}", Label).update("0.0%")

        for i in range(DASH_PROC_ROW_COUNT):
            if i < len(top_ram):
                ram_name, rss = top_ram[i]
                ram_size, ram_unit = self.human_readable_size(rss)
                self.query_one(f"#top_ram_name_{i}", Label).update(ram_name)
                self.query_one(f"#top_ram_val_{i}", Label).update(f"{ram_size}{ram_unit}")
            else:
                self.query_one(f"#top_ram_name_{i}", Label).update("-")
                self.query_one(f"#top_ram_val_{i}", Label).update("0.0B")


