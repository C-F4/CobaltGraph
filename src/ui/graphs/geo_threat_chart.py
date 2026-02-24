"""
Geographic Threat Chart
=======================

Horizontal bar chart showing threat scores and connection
counts by country. Uses plotext for terminal-rendered charts.
"""

import logging
from collections import defaultdict
from typing import Dict, List, Tuple

import plotext as plt

from rich.panel import Panel
from rich.text import Text
from textual.widgets import Static
from textual.reactive import reactive

logger = logging.getLogger(__name__)


def render_geo_threat(
    country_data: List[Tuple[str, float, int]],
    top_n: int = 12,
    width: int = 60,
    height: int = 15,
    title: str = "Geographic Threat Distribution",
) -> str:
    """
    Render geographic threat distribution as horizontal bars.

    Args:
        country_data: List of (country_code, avg_threat, connection_count) tuples.
        top_n: Number of top countries to display.
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

    if not country_data:
        plt.title("Awaiting geographic data...")
        return plt.build()

    # Sort by connection count, take top N
    sorted_data = sorted(country_data, key=lambda x: x[2], reverse=True)[:top_n]

    labels = [cc for cc, _, _ in sorted_data]
    threats = [t for _, t, _ in sorted_data]
    counts = [c for _, _, c in sorted_data]

    # Reverse for top-to-bottom display
    labels.reverse()
    threats.reverse()
    counts.reverse()

    # Stacked-style: show both volume and threat
    plt.multiple_bar(
        labels,
        [counts, [t * max(counts) if counts else 0 for t in threats]],
        orientation="horizontal",
        color=["cyan", "red"],
        width=0.7,
        labels=["volume", "threat (scaled)"],
    )
    plt.xlabel("connections / scaled threat")

    return plt.build()


def render_geo_volume(
    country_data: List[Tuple[str, float, int]],
    top_n: int = 12,
    width: int = 60,
    height: int = 15,
    title: str = "Connections by Country",
) -> str:
    """
    Render connection volume by country as horizontal bars.

    Args:
        country_data: List of (country_code, avg_threat, connection_count) tuples.
        top_n: Number of top countries to display.
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

    if not country_data:
        plt.title("Awaiting geographic data...")
        return plt.build()

    sorted_data = sorted(country_data, key=lambda x: x[2], reverse=True)[:top_n]

    labels = [cc for cc, _, _ in sorted_data]
    counts = [c for _, _, c in sorted_data]

    labels.reverse()
    counts.reverse()

    # Color bars by threat level
    colors = []
    for cc, t, _ in reversed(sorted_data):
        if t >= 0.7:
            colors.append("red")
        elif t >= 0.4:
            colors.append("yellow")
        else:
            colors.append("cyan")

    plt.bar(labels, counts, orientation="horizontal", color=colors, width=0.7)
    plt.xlabel("connections")

    return plt.build()


class GeoThreatGraph(Static):
    """
    Textual widget displaying geographic threat distribution.

    Reactive data:
        graph_data: Dict with keys:
            - country_data: List[(country_code, avg_threat, count)]
            - mode: "volume" | "threat" (default "volume")
    """

    DEFAULT_CSS = """
    GeoThreatGraph {
        height: 100%;
        width: 100%;
        padding: 0;
    }
    """

    graph_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.graph_data = {"country_data": [], "mode": "volume"}
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
        country_data = self.graph_data.get("country_data", [])
        mode = self.graph_data.get("mode", "volume")

        if mode == "threat":
            chart_str = render_geo_threat(
                country_data,
                width=self._graph_width,
                height=self._graph_height,
            )
            panel_title = "Geographic Threat Distribution"
        else:
            chart_str = render_geo_volume(
                country_data,
                width=self._graph_width,
                height=self._graph_height,
            )
            panel_title = "Connections by Country"

        return Panel(
            Text.from_ansi(chart_str),
            title=f"[bold cyan]{panel_title}[/bold cyan]",
            border_style="dim cyan",
            padding=(0, 0),
        )
