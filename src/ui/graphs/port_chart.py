"""
Port Distribution Graph
=======================

Horizontal bar chart showing connection counts by destination port.
Uses plotext for terminal-rendered charts.
"""

import logging
from collections import Counter
from typing import Dict, List, Optional, Tuple

import plotext as plt

from rich.panel import Panel
from rich.text import Text
from textual.widgets import Static
from textual.reactive import reactive

logger = logging.getLogger(__name__)

# Well-known port labels for compact display
PORT_LABELS = {
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SUBMIT",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PgSQL",
    5900: "VNC",
    8080: "HTTP-P",
    8443: "HTTPS-A",
}


def _port_label(port: int) -> str:
    name = PORT_LABELS.get(port)
    if name:
        return f"{port}/{name}"
    return str(port)


def render_port_distribution(
    ports: List[int],
    top_n: int = 10,
    width: int = 60,
    height: int = 15,
    title: str = "Port Distribution",
) -> str:
    """
    Render port distribution as horizontal bars.

    Args:
        ports: List of destination port numbers.
        top_n: Number of top ports to display.
        width: Chart width in characters.
        height: Chart height in rows.
        title: Chart title.

    Returns:
        Rendered chart as a string.
    """
    plt.clear_figure()
    plt.plotsize(width, height)
    plt.theme("dark")
    plt.title(title)

    if not ports:
        plt.title("Awaiting port data...")
        return plt.build()

    counts = Counter(ports)
    top = counts.most_common(top_n)

    labels = [_port_label(port) for port, _ in top]
    values = [count for _, count in top]

    # Reverse so highest is at top
    labels.reverse()
    values.reverse()

    plt.bar(labels, values, orientation="horizontal", color="magenta", width=0.7)
    plt.xlabel("connections")

    return plt.build()


def render_port_threat(
    port_data: List[Tuple[int, float, int]],
    top_n: int = 10,
    width: int = 60,
    height: int = 15,
    title: str = "Port Threat Profile",
) -> str:
    """
    Render port threat scores as horizontal bars.

    Args:
        port_data: List of (port, avg_threat, count) tuples.
        top_n: Number of top ports to display.
        width: Chart width in characters.
        height: Chart height in rows.
        title: Chart title.

    Returns:
        Rendered chart as a string.
    """
    plt.clear_figure()
    plt.plotsize(width, height)
    plt.theme("dark")
    plt.title(title)

    if not port_data:
        plt.title("Awaiting port threat data...")
        return plt.build()

    # Sort by threat score descending, take top N
    sorted_data = sorted(port_data, key=lambda x: x[1], reverse=True)[:top_n]

    labels = [_port_label(p) for p, _, _ in sorted_data]
    threats = [t for _, t, _ in sorted_data]

    labels.reverse()
    threats.reverse()

    plt.bar(labels, threats, orientation="horizontal", color="red", width=0.7)
    plt.xlabel("avg threat")
    plt.xlim(0, 1.05)

    return plt.build()


class PortDistributionGraph(Static):
    """
    Textual widget displaying port distribution.

    Reactive data:
        graph_data: Dict with keys:
            - ports: List[int] of destination ports
            - port_threats: Optional List[(port, avg_threat, count)]
            - mode: "volume" | "threat" (default "volume")
    """

    DEFAULT_CSS = """
    PortDistributionGraph {
        height: 100%;
        width: 100%;
        padding: 0;
    }
    """

    graph_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.graph_data = {"ports": [], "mode": "volume"}
        self._graph_width = 60
        self._graph_height = 15

    def on_resize(self, event) -> None:
        new_w = max(30, event.size.width - 4)
        new_h = max(8, event.size.height - 4)
        if (new_w, new_h) != (self._graph_width, self._graph_height):
            self._graph_width = new_w
            self._graph_height = new_h
            self.refresh()

    def watch_graph_data(self, new_data: dict) -> None:
        self.refresh()

    def render(self) -> Panel:
        mode = self.graph_data.get("mode", "volume")

        if mode == "threat":
            port_threats = self.graph_data.get("port_threats", [])
            chart_str = render_port_threat(
                port_threats,
                width=self._graph_width,
                height=self._graph_height,
            )
            panel_title = "Port Threat Profile"
        else:
            ports = self.graph_data.get("ports", [])
            chart_str = render_port_distribution(
                ports,
                width=self._graph_width,
                height=self._graph_height,
            )
            panel_title = "Port Distribution"

        return Panel(
            Text.from_ansi(chart_str),
            title=f"[bold cyan]{panel_title}[/bold cyan]",
            border_style="dim cyan",
            padding=(0, 0),
        )
