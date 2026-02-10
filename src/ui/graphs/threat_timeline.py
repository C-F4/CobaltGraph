"""
Threat Timeline Graph
=====================

Time-series line chart of threat scores over time.
Uses plotext for terminal-rendered charts.

Displays rolling threat score averages as a line plot with
color-coded threat threshold bands.
"""

import logging
import time
from typing import Dict, List, Optional

import plotext as plt

from rich.panel import Panel
from rich.text import Text
from textual.widgets import Static
from textual.reactive import reactive

logger = logging.getLogger(__name__)


def render_threat_timeline(
    timestamps: List[float],
    scores: List[float],
    width: int = 60,
    height: int = 15,
    title: str = "Threat Score Timeline",
) -> str:
    """
    Render a threat timeline as a terminal string.

    Args:
        timestamps: Unix timestamps for each data point.
        scores: Threat scores (0.0-1.0) corresponding to timestamps.
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

    if not timestamps or not scores:
        plt.title("Awaiting threat data...")
        return plt.build()

    # Convert timestamps to relative minutes ago
    now = time.time()
    minutes_ago = [(now - ts) / 60 for ts in timestamps]
    # Reverse so time flows left-to-right (oldest on left)
    minutes_ago = list(reversed(minutes_ago))
    scores_ordered = list(reversed(scores))

    plt.plot(minutes_ago, scores_ordered, marker="braille", color="cyan")

    # Threshold lines
    n = len(minutes_ago)
    if n >= 2:
        x_range = [minutes_ago[0], minutes_ago[-1]]
        plt.plot(x_range, [0.7, 0.7], color="red")
        plt.plot(x_range, [0.3, 0.3], color=(100, 100, 50))

    plt.xlabel("minutes ago")
    plt.ylabel("threat")
    plt.ylim(0, 1.05)

    return plt.build()


class ThreatTimelineGraph(Static):
    """
    Textual widget displaying a threat score timeline.

    Reactive data:
        graph_data: Dict with keys:
            - timestamps: List[float] of unix timestamps
            - scores: List[float] of threat scores (0-1)
    """

    DEFAULT_CSS = """
    ThreatTimelineGraph {
        height: 100%;
        width: 100%;
        padding: 0;
    }
    """

    graph_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.graph_data = {"timestamps": [], "scores": []}
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
        timestamps = self.graph_data.get("timestamps", [])
        scores = self.graph_data.get("scores", [])

        chart_str = render_threat_timeline(
            timestamps,
            scores,
            width=self._graph_width,
            height=self._graph_height,
        )

        return Panel(
            chart_str,
            title="[bold cyan]Threat Timeline[/bold cyan]",
            border_style="dim cyan",
            padding=(0, 0),
        )
