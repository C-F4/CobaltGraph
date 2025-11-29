#!/usr/bin/env python3
"""
CobaltGraph Dashboard V2 - Two-Cell Layout

Left Cell:
  ├─ Threat Posture (top)
  ├─ Live Activity Monitor (middle)
  └─ Connections Table (bottom)

Right Cell:
  └─ Rotating ASCII Globe (full height)
"""

import logging
import sqlite3
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from rich.panel import Panel
from rich.table import Table as RichTable
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import Header, Footer, Static
from textual.reactive import reactive

logger = logging.getLogger(__name__)


class DataManager:
    """Database query layer with caching"""

    def __init__(self, db_path: str, cache_ttl: float = 2.0):
        self.db_path = Path(db_path)
        self.cache_ttl = cache_ttl
        self.db_conn = None
        self.is_connected = False
        self._connection_cache: List[Dict] = []
        self._last_update = 0.0

    def connect(self) -> bool:
        """Connect to database"""
        try:
            if not self.db_path.exists():
                logger.error(f"Database not found: {self.db_path}")
                return False
            self.db_conn = sqlite3.connect(str(self.db_path), timeout=5.0)
            self.db_conn.row_factory = sqlite3.Row
            self.is_connected = True
            logger.info(f"DataManager connected to {self.db_path}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Database connection failed: {e}")
            return False

    def disconnect(self) -> None:
        """Close database connection"""
        if self.db_conn:
            self.db_conn.close()
            self.is_connected = False

    def get_connections(self, limit: int = 100) -> List[Dict]:
        """Get recent connections from database"""
        if not self.is_connected:
            return []
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(
                "SELECT * FROM connections ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Query failed: {e}")
            return []

    def get_stats(self) -> Dict:
        """Get threat statistics"""
        if not self.is_connected:
            return {}
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT COUNT(*) as total FROM connections")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) as critical FROM connections WHERE threat_score >= 0.7")
            critical = cursor.fetchone()[0]
            cursor.execute("SELECT AVG(threat_score) as avg_threat FROM connections")
            avg = cursor.fetchone()[0] or 0
            return {
                'total': total,
                'critical': critical,
                'avg_threat': avg
            }
        except sqlite3.Error as e:
            logger.error(f"Stats query failed: {e}")
            return {}


class ThreatPosterPanel(Static):
    """Top-left: Threat posture summary"""
    DEFAULT_CSS = """
    ThreatPosterPanel {
        height: auto;
        width: 100%;
        padding: 1;
    }
    """

    threat_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.threat_data = {'current': 0, 'baseline': 0, 'active': 0, 'ips': 0}

    def watch_threat_data(self, new_data: dict) -> None:
        self.refresh()

    def render(self):
        current = self.threat_data.get('current', 0)
        critical = self.threat_data.get('active', 0)

        if current >= 0.7:
            color = "[bold red]"
            level = "CRITICAL"
        elif current >= 0.5:
            color = "[bold yellow]"
            level = "HIGH"
        elif current >= 0.3:
            color = "[yellow]"
            level = "MEDIUM"
        else:
            color = "[green]"
            level = "LOW"

        content = f"""{color}Threat: {current:.2f}[/] {level}
Critical: {critical} | IPs: {self.threat_data.get('ips', 0)}"""
        return Panel(content, title="[bold cyan]Threat[/bold cyan]")


class LiveActivityPanel(Static):
    """Middle-left: Live activity monitor"""
    DEFAULT_CSS = """
    LiveActivityPanel {
        height: auto;
        width: 100%;
        padding: 1;
    }
    """

    activity_data = reactive(dict)
    frame = 0

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.activity_data = {'volume': 0, 'peak': 0, 'anomalies': 0}
        self.frame = 0

    def watch_activity_data(self, new_data: dict) -> None:
        self.frame = (self.frame + 1) % 10
        self.refresh()

    def render(self):
        spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spinner = spinners[self.frame % len(spinners)]

        vol = self.activity_data.get('volume', 0)
        peak = self.activity_data.get('peak', 0)
        anom = self.activity_data.get('anomalies', 0)

        content = f"""{spinner} Live Activity
Volume: {vol} | Peak: {peak}
Anomalies: {anom}"""
        return Panel(content, title="[bold cyan]Monitor[/bold cyan]")


class ConnectionsPanel(Static):
    """Bottom-left: Connection table"""
    DEFAULT_CSS = """
    ConnectionsPanel {
        height: 1fr;
        width: 100%;
        padding: 1;
        overflow: auto;
    }
    """

    connections = reactive(list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connections = []

    def watch_connections(self, new_conns: list) -> None:
        self.refresh()

    def render(self):
        if not self.connections:
            return Panel("[dim]Loading...[/dim]", title="[bold cyan]Connections[/bold cyan]")

        table = RichTable(title="[bold cyan]Connections[/bold cyan]")
        table.add_column("Time", style="cyan", width=8, no_wrap=True)
        table.add_column("IP", style="cyan", width=12, no_wrap=True)
        table.add_column("Port", width=4, no_wrap=True)
        table.add_column("Org", width=12, no_wrap=True)
        table.add_column("Risk", width=4, no_wrap=True)
        table.add_column("Hops", width=3, no_wrap=True)

        for conn in self.connections[:30]:
            time_str = datetime.fromtimestamp(conn.get('timestamp', 0)).strftime("%H:%M")
            ip = (conn.get('dst_ip') or '-')[:12]
            port = str(conn.get('dst_port', '-'))[:4]
            org = (conn.get('dst_org') or 'U')[:12]
            threat = float(conn.get('threat_score', 0) or 0)
            hops = str(conn.get('hop_count', '-'))[:3]

            if threat >= 0.7:
                risk = "[bold red]●●[/bold red]"
            elif threat >= 0.5:
                risk = "[bold yellow]●○[/bold yellow]"
            elif threat >= 0.3:
                risk = "[yellow]◐○[/yellow]"
            else:
                risk = "[green]○○[/green]"

            table.add_row(time_str, ip, port, org, risk, hops)

        return Panel(table)


class RotatingGlobePanel(Static):
    """Right cell: ASCII rotating globe"""
    DEFAULT_CSS = """
    RotatingGlobePanel {
        height: 1fr;
        width: 100%;
        padding: 1;
    }
    """

    globe_data = reactive(dict)
    rotation = 0

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.globe_data = {'connections': []}
        self.rotation = 0

    def watch_globe_data(self, new_data: dict) -> None:
        self.rotation = (self.rotation + 1) % 36
        self.refresh()

    def render(self):
        """ASCII rotating globe"""
        connections = self.globe_data.get('connections', [])

        # Extract geo data
        geo_threats = {}
        for conn in connections:
            country = (conn.get('dst_country') or 'XX')[:2].upper()
            threat = float(conn.get('threat_score', 0) or 0)
            if country not in geo_threats:
                geo_threats[country] = []
            geo_threats[country].append(threat)

        # Top regions
        top_regions = sorted(
            [(c, sum(t)/len(t), len(t)) for c, t in geo_threats.items()],
            key=lambda x: x[1],
            reverse=True
        )[:8]

        # Rotating globe animation
        rotation_chars = "/─\\|"
        rotation_char = rotation_chars[self.rotation % 4]

        content = f"[bold cyan]{rotation_char} Globe {rotation_char}[/bold cyan]\n\n"

        for country, avg_threat, count in top_regions:
            if avg_threat >= 0.7:
                bar = "[bold red]████████[/bold red]"
            elif avg_threat >= 0.5:
                bar = "[bold yellow]██████░░[/bold yellow]"
            elif avg_threat >= 0.3:
                bar = "[yellow]████░░░░[/yellow]"
            else:
                bar = "[green]██░░░░░░[/green]"

            content += f"{country} {bar} {avg_threat:.2f}\n"

        if not top_regions:
            content += "[dim]Loading geographic data...[/dim]\n"

        content += f"\n[cyan]Total:[/cyan] {len(connections)}"

        return Panel(content, title="[bold cyan]World Map[/bold cyan]")


class CobaltGraphDashboardV2(App):
    """Two-cell dashboard layout"""

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("?", "help", "Help"),
    ]

    CSS = """
    Screen {
        layout: horizontal;
        background: $background;
    }

    #left_panel {
        width: 50%;
        height: 100%;
        layout: vertical;
    }

    #right_panel {
        width: 50%;
        height: 100%;
    }

    ThreatPosterPanel {
        height: auto;
    }

    LiveActivityPanel {
        height: auto;
    }

    ConnectionsPanel {
        height: 1fr;
    }
    """

    def __init__(self):
        super().__init__()
        self.title = "CobaltGraph - Threat Intelligence Dashboard"
        self.sub_title = "Loading..."
        self.data_manager = DataManager("data/cobaltgraph.db")

        self.threat_panel = None
        self.activity_panel = None
        self.connections_panel = None
        self.globe_panel = None

    def compose(self) -> ComposeResult:
        """Create dashboard layout"""
        yield Header()

        with Horizontal():
            # Left panel with sub-cells
            with Vertical(id="left_panel"):
                self.threat_panel = ThreatPosterPanel()
                yield self.threat_panel

                self.activity_panel = LiveActivityPanel()
                yield self.activity_panel

                self.connections_panel = ConnectionsPanel()
                yield self.connections_panel

            # Right panel - rotating globe
            self.globe_panel = RotatingGlobePanel()
            yield self.globe_panel

        yield Footer()

    def on_mount(self) -> None:
        """Initialize dashboard"""
        self.title = "CobaltGraph - Threat Intelligence"
        self.sub_title = "Initializing..."

        if self.data_manager.connect():
            self.set_interval(2.0, self._refresh_data)
            self.set_interval(0.5, self._update_heartbeat)
            self._refresh_data()
        else:
            self.sub_title = "Database connection failed"

    def _update_heartbeat(self) -> None:
        """Update heartbeat timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.sub_title = f"Last update: {timestamp}"

    def _refresh_data(self) -> None:
        """Refresh all panels with data"""
        try:
            # Get stats
            stats = self.data_manager.get_stats()
            if self.threat_panel:
                self.threat_panel.threat_data = {
                    'current': stats.get('avg_threat', 0),
                    'baseline': 0,
                    'active': stats.get('critical', 0),
                    'ips': stats.get('total', 0)
                }

            # Get connections
            connections = self.data_manager.get_connections(limit=100)

            if self.activity_panel and connections:
                threats = [c.get('threat_score', 0) or 0 for c in connections]
                self.activity_panel.activity_data = {
                    'volume': len(connections),
                    'peak': max(threats) if threats else 0,
                    'anomalies': sum(1 for t in threats if t >= 0.7)
                }

            if self.connections_panel:
                self.connections_panel.connections = connections

            if self.globe_panel:
                self.globe_panel.globe_data = {'connections': connections}

        except Exception as e:
            logger.error(f"Refresh error: {e}")

    def action_help(self) -> None:
        """Show help"""
        pass


if __name__ == "__main__":
    app = CobaltGraphDashboardV2()
    app.run()
