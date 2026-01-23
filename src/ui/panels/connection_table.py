"""
Connection Table Panel
======================

Bottom-left panel displaying recent network connections.
Shows connection details with threat scoring and organization info.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.widgets import Static
from textual.reactive import reactive

logger = logging.getLogger(__name__)


class ConnectionTablePanel(Static):
    """
    Displays recent connections in a scrollable table format.

    Shows:
        - Destination IP and port
        - Protocol (TCP/UDP)
        - Organization and country
        - Threat score with visual indicator
        - Timestamp

    Supports row selection for detailed view.

    Attributes:
        connections: Reactive list of connection dicts
        selected_index: Currently selected row index
    """

    DEFAULT_CSS = """
    ConnectionTablePanel {
        height: 100%;
        width: 100%;
        padding: 0;
    }
    """

    connections = reactive(list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connections = []
        self.selected_index: int = 0
        self._scroll_offset: int = 0

    def watch_connections(self, new_connections: list) -> None:
        """Update display when connections change."""
        self.refresh()

    def select_next(self) -> None:
        """Move selection down."""
        if self.connections:
            self.selected_index = min(len(self.connections) - 1, self.selected_index + 1)
            self._ensure_visible()
            self.refresh()

    def select_previous(self) -> None:
        """Move selection up."""
        if self.connections:
            self.selected_index = max(0, self.selected_index - 1)
            self._ensure_visible()
            self.refresh()

    def get_selected(self) -> Optional[Dict]:
        """Get the currently selected connection."""
        if self.connections and 0 <= self.selected_index < len(self.connections):
            return self.connections[self.selected_index]
        return None

    def _ensure_visible(self) -> None:
        """Adjust scroll to keep selection visible."""
        visible_rows = 8  # Approximate visible rows
        if self.selected_index < self._scroll_offset:
            self._scroll_offset = self.selected_index
        elif self.selected_index >= self._scroll_offset + visible_rows:
            self._scroll_offset = self.selected_index - visible_rows + 1

    def render(self) -> Panel:
        """Render the connection table."""
        if not self.connections:
            return Panel(
                "[dim]No connections recorded[/dim]\n\n"
                "[cyan]Waiting for network traffic...[/cyan]",
                title="[bold cyan]Connections[/bold cyan]",
                border_style="cyan"
            )

        # Create table
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            padding=(0, 1),
        )

        # Define columns
        table.add_column("Dst IP", style="cyan", no_wrap=True, width=16)
        table.add_column("Port", justify="right", width=6)
        table.add_column("Proto", width=5)
        table.add_column("Org", width=12)
        table.add_column("Score", justify="center", width=6)
        table.add_column("Time", width=8)

        # Add rows (with scroll offset)
        visible_connections = self.connections[self._scroll_offset:self._scroll_offset + 10]

        for i, conn in enumerate(visible_connections):
            actual_index = self._scroll_offset + i
            is_selected = actual_index == self.selected_index

            row_style = "reverse" if is_selected else ""

            # Extract values
            dst_ip = conn.get('dst_ip', 'Unknown')[:16]
            dst_port = str(conn.get('dst_port', '-'))[:6]
            protocol = conn.get('protocol', 'TCP')[:5]
            org = (conn.get('dst_org') or conn.get('dst_org_type') or 'Unknown')[:12]
            threat = float(conn.get('threat_score', 0) or 0)
            timestamp = conn.get('timestamp', 0)

            # Format threat score with indicator
            threat_text = self._format_threat(threat)

            # Format time
            time_str = self._format_time(timestamp)

            # Add row
            table.add_row(
                Text(dst_ip, style=row_style),
                Text(dst_port, style=row_style),
                Text(protocol, style=f"magenta {row_style}" if protocol == "UDP" else row_style),
                Text(org, style=f"dim {row_style}"),
                threat_text,
                Text(time_str, style=f"dim {row_style}"),
            )

        # Footer with count
        footer = f"[dim]{len(self.connections)} connections | ↑↓ Navigate | Enter Details[/dim]"

        content = Text()
        content.append_text(Text.from_markup(str(table)))
        content.append(f"\n{footer}")

        return Panel(
            table,
            title=f"[bold cyan]Connections ({len(self.connections)})[/bold cyan]",
            border_style="cyan",
            subtitle=f"[dim]Row {self.selected_index + 1}/{len(self.connections)}[/dim]"
        )

    def _format_threat(self, score: float) -> Text:
        """Format threat score with colored indicator."""
        if score >= 0.8:
            return Text(f"● {score:.0%}", style="bold red")
        elif score >= 0.6:
            return Text(f"◉ {score:.0%}", style="bold yellow")
        elif score >= 0.4:
            return Text(f"◯ {score:.0%}", style="yellow")
        elif score >= 0.2:
            return Text(f"○ {score:.0%}", style="cyan")
        return Text(f"· {score:.0%}", style="green")

    def _format_time(self, timestamp: float) -> str:
        """Format timestamp as relative or absolute time."""
        if not timestamp:
            return "-"

        try:
            dt = datetime.fromtimestamp(timestamp)
            now = datetime.now()
            diff = now - dt

            if diff.total_seconds() < 60:
                return f"{int(diff.total_seconds())}s ago"
            elif diff.total_seconds() < 3600:
                return f"{int(diff.total_seconds() / 60)}m ago"
            else:
                return dt.strftime("%H:%M")
        except Exception:
            return "-"
