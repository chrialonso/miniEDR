from textual.app import ComposeResult
from textual.widgets import Static, RichLog
from textual.containers import Vertical

class LogsView(Static):
    def compose(self) -> ComposeResult:
        with Vertical(id = "logs_frame"):
            yield RichLog(id = "logs_richlog", wrap = True, highlight = True)

    def write_log(self, message: str) -> None:
        self.query_one("#logs_richlog", RichLog).write(message)

