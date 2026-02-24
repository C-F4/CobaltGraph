"""
Connection Volume Graph
=======================

Bar chart showing connection counts bucketed by time interval.
Uses plotext for terminal-rendered charts.
"""

import logging
import time
from collections import defaultdict
from typing import Dict, List

import plotext as plt

from rich.panel import Panel
from rich.text import Text
from textual.widgets import Static
from textual.reactive import reactive

logger = logging.getLogger(__name__)


def render_connection_volume(
    timestamps: List[float],
    bucket_minutes: int = 5,
    width: int = 60,
    height: int = 15,
    title: str = "Connection Volume",
) -> str:
    """
    Render connection volume as a bar chart.

    Args:
        timestamps: Unix timestamps of connections.
        bucket_minutes: Time bucket size in minutes.
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

    if not timestamps:
        plt.title("Awaiting connection data...")
        return plt.build()

    now = time.time()
    bucket_sec = bucket_minutes * 60

    # Bucket connections into time windows
    buckets = defaultdict(int)
    for ts in timestamps:
        bucket_id = int((now - ts) / bucket_sec)
        buckets[bucket_id] += 1

    if not buckets:
        plt.title("No data in window")
        return plt.build()

    max_bucket = max(buckets.keys())
    # Build ordered arrays (oldest first -> left)
    labels = []
    counts = []
    for i in range(max_bucket, -1, -1):
        labels.append(f"-{i * bucket_minutes}m")
        counts.append(buckets.get(i, 0))

    plt.bar(labels, counts, color="cyan", width=0.8)
    plt.xlabel(f"{bucket_minutes}min buckets")
    plt.ylabel("connections")

    return plt.build()


class ConnectionVolumeGraph(Static):
    """
    Textual widget displaying connection volume over time as bars.

    Reactive data:
        graph_data: Dict with keys:
            - timestamps: List[float] of unix timestamps
            - bucket_minutes: int (default 5)
    """

    DEFAULT_CSS = """
    ConnectionVolumeGraph {
        height: 100%;
        width: 100%;
        padding: 0;
    }
    """

    graph_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.graph_data = {"timestamps": [], "bucket_minutes": 5}
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
        bucket_minutes = self.graph_data.get("bucket_minutes", 5)

        chart_str = render_connection_volume(
            timestamps,
            bucket_minutes=bucket_minutes,
            width=self._graph_width,
            height=self._graph_height,
        )

        return Panel(
            Text.from_ansi(chart_str),
            title="[bold cyan]Connection Volume[/bold cyan]",
            border_style="dim cyan",
            padding=(0, 0),
        )
