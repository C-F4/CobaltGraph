"""
Threat Distribution Graph
=========================

Histogram of threat score distribution across all connections.
Uses plotext for terminal-rendered charts.

Shows how threat scores are distributed to give analysts a
quick read on overall network posture.
"""

import logging
from typing import Dict, List

import plotext as plt

from rich.panel import Panel
from rich.text import Text
from textual.widgets import Static
from textual.reactive import reactive

logger = logging.getLogger(__name__)


def render_threat_distribution(
    scores: List[float],
    bins: int = 10,
    width: int = 60,
    height: int = 15,
    title: str = "Threat Score Distribution",
) -> str:
    """
    Render threat score distribution as a histogram.

    Args:
        scores: List of threat scores (0.0-1.0).
        bins: Number of histogram bins.
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

    if not scores:
        plt.title("Awaiting threat scores...")
        return plt.build()

    # Build histogram manually for color control
    bin_width = 1.0 / bins
    bin_counts = [0] * bins
    for s in scores:
        idx = min(int(s / bin_width), bins - 1)
        bin_counts[idx] += 1

    bin_labels = [f"{i * bin_width:.1f}" for i in range(bins)]

    # Color bins by threat level
    colors = []
    for i in range(bins):
        mid = (i + 0.5) * bin_width
        if mid >= 0.7:
            colors.append("red")
        elif mid >= 0.4:
            colors.append("yellow")
        else:
            colors.append("green")

    plt.bar(bin_labels, bin_counts, color=colors, width=0.9)
    plt.xlabel("threat score")
    plt.ylabel("count")

    return plt.build()


def render_threat_cdf(
    scores: List[float],
    width: int = 60,
    height: int = 15,
    title: str = "Threat CDF",
) -> str:
    """
    Render cumulative distribution function of threat scores.

    Args:
        scores: List of threat scores (0.0-1.0).
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

    if not scores:
        plt.title("Awaiting threat scores...")
        return plt.build()

    sorted_scores = sorted(scores)
    n = len(sorted_scores)
    cdf_y = [(i + 1) / n for i in range(n)]

    plt.plot(sorted_scores, cdf_y, marker="braille", color="cyan")

    # Mark thresholds
    plt.vline(0.3, color=(100, 100, 50))
    plt.vline(0.7, color="red")

    plt.xlabel("threat score")
    plt.ylabel("cumulative %")
    plt.xlim(0, 1.05)
    plt.ylim(0, 1.05)

    return plt.build()


class ThreatDistributionGraph(Static):
    """
    Textual widget displaying threat score distribution.

    Reactive data:
        graph_data: Dict with keys:
            - scores: List[float] of threat scores (0-1)
            - mode: "histogram" | "cdf" (default "histogram")
    """

    DEFAULT_CSS = """
    ThreatDistributionGraph {
        height: 100%;
        width: 100%;
        padding: 0;
    }
    """

    graph_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.graph_data = {"scores": [], "mode": "histogram"}
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
        scores = self.graph_data.get("scores", [])
        mode = self.graph_data.get("mode", "histogram")

        if mode == "cdf":
            chart_str = render_threat_cdf(
                scores,
                width=self._graph_width,
                height=self._graph_height,
            )
            panel_title = "Threat Score CDF"
        else:
            chart_str = render_threat_distribution(
                scores,
                width=self._graph_width,
                height=self._graph_height,
            )
            panel_title = "Threat Score Distribution"

        return Panel(
            Text.from_ansi(chart_str),
            title=f"[bold cyan]{panel_title}[/bold cyan]",
            border_style="dim cyan",
            padding=(0, 0),
        )
