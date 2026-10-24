"""
Detections log: a filterable, sortable, exportable view of recorded detections.

Reads the events table through DataManager. Rows are what the pipeline recorded,
not values the dashboard derives from scores.
"""

import logging
import time
from datetime import datetime
from typing import Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Input, Static

from src.export.events_export import export_events
from src.ui.theme import DETECTION_BADGES, TYPE_LABELS, severity_style

logger = logging.getLogger(__name__)


class DetectionsLogScreen(ModalScreen):
    """
    Full-screen detections log.

    Keys: s minimum severity, t type filter, o sort (time / severity),
    / destination filter, Enter drill into the newest connection for the row's IP,
    e export JSON Lines, c export CSV, Esc close.
    """

    WINDOW_SECONDS = 7 * 86400
    ROW_LIMIT = 500

    TYPE_FILTERS: List[Optional[str]] = [None] + list(DETECTION_BADGES.keys())
    SEVERITY_FILTERS: List[Optional[str]] = [None, "MEDIUM", "HIGH", "CRITICAL"]

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("q", "close", "Close", show=False),
        Binding("s", "cycle_severity", "Min severity"),
        Binding("t", "cycle_type", "Type"),
        Binding("o", "toggle_order", "Sort"),
        Binding("slash", "toggle_ip_filter", "IP filter"),
        Binding("e", "export('jsonl')", "Export JSONL"),
        Binding("c", "export('csv')", "Export CSV"),
    ]

    DEFAULT_CSS = """
    DetectionsLogScreen {
        align: center top;
    }
    #log_container {
        width: 100%;
        height: 100%;
        background: $surface;
    }
    #log_title {
        height: 1;
        padding: 0 1;
        background: $primary;
    }
    #log_status {
        height: auto;
        padding: 0 1;
    }
    #ip_filter {
        display: none;
        height: 3;
    }
    #ip_filter.visible {
        display: block;
    }
    #log_table {
        height: 1fr;
    }
    """

    def __init__(self, data_manager, export_directory: str = "exports", **kwargs):
        super().__init__(**kwargs)
        self.data_manager = data_manager
        self.export_directory = export_directory
        self._type_index = 0
        self._severity_index = 0
        self._order = "time"
        self._ip_filter = ""
        self._rows: List[Dict] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="log_container"):
            yield Static("[bold]DETECTIONS LOG[/bold]  [dim]recorded by the pipeline[/dim]", id="log_title")
            yield Static("", id="log_status")
            yield Input(placeholder="destination IP contains… (Enter to apply, Esc to clear)", id="ip_filter")
            yield DataTable(id="log_table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#log_table", DataTable)
        table.add_column("Time", key="time", width=8)
        table.add_column("Sev", key="sev", width=8)
        table.add_column("Type", key="type", width=12)
        table.add_column("Dst IP", key="dst", width=16)
        table.add_column("Port", key="port", width=6)
        table.add_column("Score", key="score", width=6)
        table.add_column("Org", key="org", width=22)
        table.add_column("Message", key="message")
        # Focus the table explicitly: otherwise the (hidden) IP filter input takes focus
        # and swallows the filter keys
        table.focus()
        self.reload()

    # ------------------------------------------------------------------ data

    def _filters(self) -> Dict:
        return {
            "min_severity": self.SEVERITY_FILTERS[self._severity_index],
            "event_type": self.TYPE_FILTERS[self._type_index],
            "ip": self._ip_filter or None,
            "since": time.time() - self.WINDOW_SECONDS,
            "order": self._order,
            "limit": self.ROW_LIMIT,
        }

    def reload(self) -> None:
        """Query the events table with the current filters and redraw."""
        try:
            self._rows = self.data_manager.query_events(**self._filters())
        except Exception as e:
            logger.warning(f"Detections log query failed: {e}")
            self._rows = []

        table = self.query_one("#log_table", DataTable)
        table.clear()
        for index, row in enumerate(self._rows):
            table.add_row(*self._cells(row), key=str(index))

        self._update_status()

    @staticmethod
    def _cells(row: Dict) -> tuple:
        ts = row.get("timestamp") or 0
        time_str = datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S") if ts else "--:--:--"
        sev = str(row.get("severity") or "INFO").upper()
        event_type = row.get("event_type") or ""
        label = TYPE_LABELS.get(event_type, event_type)
        score = float(row.get("threat_score") or 0)
        port = row.get("dst_port")
        return (
            f"[dim]{time_str}[/]",
            f"[{severity_style(sev)}]{sev}[/]",
            label,
            f"[cyan]{row.get('dst_ip') or '—'}[/]",
            str(port) if port is not None else "—",
            f"{score:.2f}" if row.get("threat_score") is not None else "—",
            (row.get("org_name") or "")[:22],
            (row.get("message") or "")[:120],
        )

    def _update_status(self) -> None:
        severity = self.SEVERITY_FILTERS[self._severity_index] or "any"
        event_type = self.TYPE_FILTERS[self._type_index]
        type_text = TYPE_LABELS.get(event_type, "all") if event_type else "all"
        ip = self._ip_filter or "any"
        status = (
            f"rows [bold]{len(self._rows)}[/] (max {self.ROW_LIMIT})  │  "
            f"min severity [bold]{severity}[/]  │  type [bold]{type_text}[/]  │  "
            f"sort [bold]{self._order}[/]  │  dst {ip}  │  last 7 days"
        )
        if not self._rows:
            status += (
                "\n[bold yellow]No detections match these filters.[/] "
                "Press s to lower the severity, t to change the type, or / to clear the destination filter."
            )
        self.query_one("#log_status", Static).update(status)

    # --------------------------------------------------------------- actions

    def action_close(self) -> None:
        input_box = self.query_one("#ip_filter", Input)
        if input_box.has_class("visible"):
            input_box.remove_class("visible")
            self.query_one("#log_table", DataTable).focus()
            return
        self.dismiss(None)

    def action_cycle_severity(self) -> None:
        self._severity_index = (self._severity_index + 1) % len(self.SEVERITY_FILTERS)
        self.reload()

    def action_cycle_type(self) -> None:
        self._type_index = (self._type_index + 1) % len(self.TYPE_FILTERS)
        self.reload()

    def action_toggle_order(self) -> None:
        self._order = "severity" if self._order == "time" else "time"
        self.reload()

    def action_toggle_ip_filter(self) -> None:
        input_box = self.query_one("#ip_filter", Input)
        if input_box.has_class("visible"):
            input_box.remove_class("visible")
            self.query_one("#log_table", DataTable).focus()
        else:
            input_box.add_class("visible")
            input_box.value = self._ip_filter
            input_box.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "ip_filter":
            return
        self._ip_filter = event.value.strip()
        event.input.remove_class("visible")
        self.query_one("#log_table", DataTable).focus()
        self.reload()

    def action_export(self, fmt: str) -> None:
        if not self._rows:
            self.notify("Nothing to export: the log is empty", severity="warning")
            return
        path, error = export_events(self._rows, fmt, directory=self.export_directory)
        if error:
            self.notify(f"Export failed: {error}", severity="error", timeout=10)
        else:
            self.notify(f"Exported {len(self._rows)} rows to {path}", timeout=8)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        index = int(event.row_key.value)
        if not (0 <= index < len(self._rows)):
            return
        ip = self._rows[index].get("dst_ip")
        latest = self.data_manager.get_latest_connection(ip) if ip else None
        if latest is None:
            self.notify(f"No connection record for {ip}", severity="warning")
            return
        self.dismiss(latest)
