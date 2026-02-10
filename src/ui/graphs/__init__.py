"""
Graphs Module
=============

Terminal-based analytical graphing for CobaltGraph.

Uses plotext for rendered terminal charts providing real data
visualization beyond ASCII sparklines. All graphs render as
strings compatible with Rich Panel display inside Textual Static widgets.

Provides:
    - ThreatTimelineGraph: Threat score time series (line chart)
    - ConnectionVolumeGraph: Connection counts over time (bar chart)
    - PortDistributionGraph: Traffic by destination port (horizontal bars)
    - GeoThreatGraph: Threat scores by country (horizontal bars)
    - ThreatDistributionGraph: Threat score histogram

Usage:
    from src.ui.graphs import ThreatTimelineGraph, ConnectionVolumeGraph

    # As Textual widgets
    timeline = ThreatTimelineGraph(id="timeline_graph")
    timeline.graph_data = {"timestamps": [...], "scores": [...]}

    # Standalone string rendering
    from src.ui.graphs.threat_timeline import render_threat_timeline
    output = render_threat_timeline(timestamps, scores, width=60, height=15)
"""

from .threat_timeline import ThreatTimelineGraph
from .connection_volume import ConnectionVolumeGraph
from .port_chart import PortDistributionGraph
from .geo_threat_chart import GeoThreatGraph
from .threat_distribution import ThreatDistributionGraph

__all__ = [
    'ThreatTimelineGraph',
    'ConnectionVolumeGraph',
    'PortDistributionGraph',
    'GeoThreatGraph',
    'ThreatDistributionGraph',
]
