#!/usr/bin/env python3
"""
CobaltGraph Enhanced Unified Dashboard
Comprehensive threat monitoring with mode-aware layout (device/network)

Features:
- 6-cell grid layout matching cobalt_base_maybe.png reference design
- Mode-specific rendering (device vs network)
- Integrated ASCII globe with threat heatmaps and connection trails
- Real-time threat scoring and organization intelligence
- Geographic threat visualization with hop topology
- High-density connection table with full enrichment data

Architecture:
- Inherits from unified_dashboard.UnifiedDashboard for base framework
- Extends with enhanced components and mode-specific panels
- Integrated ascii_globe.py for superior globe rendering
- DataManager + VisualizationManager for real-time updates
"""

import logging
import sqlite3
import time
from collections import deque, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from rich.panel import Panel
from rich.table import Table as RichTable
from rich.text import Text

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import Header, Footer, Static, DataTable
from textual.reactive import reactive

logger = logging.getLogger(__name__)

try:
    from src.ui.unified_dashboard import UnifiedDashboard, DataManager, VisualizationManager
except ImportError:
    from unified_dashboard import UnifiedDashboard, DataManager, VisualizationManager

try:
    from src.ui.globe_simple import SimpleGlobe
except ImportError:
    try:
        from globe_simple import SimpleGlobe
    except ImportError:
        SimpleGlobe = None

try:
    from src.ui.globe_enhanced import EnhancedGlobe
except ImportError:
    try:
        from globe_enhanced import EnhancedGlobe
    except ImportError:
        EnhancedGlobe = None

try:
    from src.ui.globe_flat import FlatWorldMap
except ImportError:
    try:
        from globe_flat import FlatWorldMap
    except ImportError:
        FlatWorldMap = None


class ThreatRadarGraph:
    """
    ASCII-based radar/spider chart renderer for threat visualization.
    Displays multi-dimensional threat scores in a compact visual format.
    """

    # Radar chart dimensions (axes)
    AXES = [
        ('THR', 'Threat'),      # Threat score
        ('CNF', 'Confidence'),  # Confidence level
        ('RIS', 'Risk'),        # Org risk (1 - trust)
        ('HOP', 'Distance'),    # Hop distance normalized
        ('GEO', 'Geo Risk'),    # Geographic risk
    ]

    # ASCII characters for radar visualization
    FULL_BLOCK = '█'
    PARTIAL_BLOCKS = ['░', '▒', '▓', '█']

    @staticmethod
    def render_mini_radar(values: dict, width: int = 15, height: int = 7,
                          label: str = "", color: str = "cyan") -> list:
        """
        Render a compact ASCII radar chart for a single connection.

        Args:
            values: Dict with keys 'threat', 'confidence', 'org_risk', 'hop_dist', 'geo_risk'
                   Each value should be 0.0-1.0
            width: Chart width in characters
            height: Chart height in lines
            label: Label for the chart (e.g., IP or connection ID)
            color: Rich color for the chart

        Returns:
            List of strings representing the radar chart lines
        """
        import math

        # Normalize and extract values (default to 0.5 if missing)
        threat = float(values.get('threat', 0) or 0)
        confidence = float(values.get('confidence', 0.5) or 0.5)
        org_risk = 1.0 - float(values.get('org_trust', 0.5) or 0.5)  # Invert trust to risk
        hop_dist = min(float(values.get('hop_count', 0) or 0) / 30.0, 1.0)  # Normalize to 30 hops max
        geo_risk = float(values.get('geo_risk', 0.3) or 0.3)

        # All values as list in order: THR, CNF, RIS, HOP, GEO
        vals = [threat, confidence, org_risk, hop_dist, geo_risk]

        # Calculate average for overall indicator
        avg_val = sum(vals) / len(vals)

        # Determine threat color based on average
        if avg_val >= 0.7:
            bar_color = "bold red"
            level = "CRIT"
        elif avg_val >= 0.5:
            bar_color = "bold yellow"
            level = "HIGH"
        elif avg_val >= 0.3:
            bar_color = "yellow"
            level = "MED"
        else:
            bar_color = "green"
            level = "LOW"

        lines = []

        # Header with label and threat level
        header = f"[{color}]┌{'─' * (width - 2)}┐[/{color}]"
        lines.append(header)

        # Label line
        label_text = label[:width - 4] if len(label) > width - 4 else label
        label_line = f"[{color}]│[/{color}][{bar_color}]{label_text:^{width - 2}}[/{bar_color}][{color}]│[/{color}]"
        lines.append(label_line)

        # Render each axis as a horizontal bar
        axis_labels = ['THR', 'CNF', 'RIS', 'HOP', 'GEO']
        for i, (ax_label, val) in enumerate(zip(axis_labels, vals)):
            # Calculate bar width
            bar_width = width - 7  # Leave room for label and brackets
            filled = int(val * bar_width)
            empty = bar_width - filled

            # Determine bar character and color based on value
            if val >= 0.7:
                fill_char = '█'
                val_color = "red"
            elif val >= 0.5:
                fill_char = '▓'
                val_color = "yellow"
            elif val >= 0.3:
                fill_char = '▒'
                val_color = "bright_yellow"
            else:
                fill_char = '░'
                val_color = "green"

            bar = f"[{val_color}]{fill_char * filled}[/{val_color}][dim]{'·' * empty}[/dim]"
            line = f"[{color}]│[/{color}]{ax_label}[dim]:[/dim]{bar}[{color}]│[/{color}]"
            lines.append(line)

        # Bottom with overall score
        score_text = f"{avg_val:.2f} {level}"
        bottom_line = f"[{color}]│[/{color}][{bar_color}]{score_text:^{width - 2}}[/{bar_color}][{color}]│[/{color}]"
        lines.append(bottom_line)

        footer = f"[{color}]└{'─' * (width - 2)}┘[/{color}]"
        lines.append(footer)

        return lines

    @staticmethod
    def render_comparison_radar(connections: list, width: int = 40, height: int = 12) -> str:
        """
        Render side-by-side comparison of top 3 threat connections.

        Args:
            connections: List of connection dicts with scoring variables
            width: Total width for all three charts
            height: Height of the visualization

        Returns:
            Formatted string with all three radar charts
        """
        if not connections:
            return "[dim]No threat connections to display[/dim]"

        # Get top 3 highest threats
        sorted_conns = sorted(
            connections,
            key=lambda c: float(c.get('threat_score', 0) or 0),
            reverse=True
        )[:3]

        if not sorted_conns:
            return "[dim]No high-threat connections[/dim]"

        # Render each connection's radar
        chart_width = max(15, (width - 2) // max(len(sorted_conns), 1))
        all_charts = []
        colors = ['cyan', 'magenta', 'yellow']

        for idx, conn in enumerate(sorted_conns):
            # Extract scoring variables
            values = {
                'threat': conn.get('threat_score', 0),
                'confidence': conn.get('confidence', 0.5),
                'org_trust': conn.get('org_trust_score', 0.5),
                'hop_count': conn.get('hop_count', 0),
                'geo_risk': ThreatRadarGraph._calculate_geo_risk(conn),
            }

            # Create label from IP (last octet) or org
            ip = conn.get('dst_ip', 'Unknown')
            org = (conn.get('dst_org') or 'Unknown')[:8]
            label = f"{ip.split('.')[-1] if '.' in ip else ip[:4]}:{org}"

            chart_lines = ThreatRadarGraph.render_mini_radar(
                values,
                width=chart_width,
                height=8,
                label=label,
                color=colors[idx % len(colors)]
            )
            all_charts.append(chart_lines)

        # Combine charts side-by-side
        result_lines = []
        max_lines = max(len(c) for c in all_charts)

        for line_idx in range(max_lines):
            combined = ""
            for chart in all_charts:
                if line_idx < len(chart):
                    combined += chart[line_idx] + " "
                else:
                    combined += " " * (chart_width + 1)
            result_lines.append(combined)

        return "\n".join(result_lines)

    @staticmethod
    def _calculate_geo_risk(conn: dict) -> float:
        """Calculate geographic risk factor from connection data."""
        # Base geo risk on country and org type
        org_type = (conn.get('dst_org_type') or 'unknown').lower()

        # High risk org types
        high_risk_types = {'tor', 'vpn', 'proxy', 'hosting', 'bulletproof'}
        medium_risk_types = {'isp', 'unknown'}

        if org_type in high_risk_types:
            return 0.8
        elif org_type in medium_risk_types:
            return 0.5
        else:
            return 0.2


class ThreatPostureQuickPanel(Static):
    """
    Top-left (50%): Quick threat posture assessment
    Current threat level, baseline, active threats, monitored IPs
    Now includes radar graphs for top 3 highest threat connections
    """

    DEFAULT_CSS = """
    ThreatPostureQuickPanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow-y: auto;
    }
    """

    threat_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.threat_data = {
            'current_threat': 0.0,
            'baseline_threat': 0.0,
            'active_threats': 0,
            'monitored_ips': 0,
            'high_threat_count': 0,
            'top_threats': [],  # Top 3 threat connections for radar graphs
        }

    def watch_threat_data(self, new_data: dict) -> None:
        """Trigger re-render when threat data changes"""
        self.refresh()

    def render(self):
        """Render threat posture with radar graphs for top 3 threats"""
        current = self.threat_data.get('current_threat', 0)
        baseline = self.threat_data.get('baseline_threat', 0)
        active = self.threat_data.get('active_threats', 0)
        ips = self.threat_data.get('monitored_ips', 0)
        high_threat = self.threat_data.get('high_threat_count', 0)
        top_threats = self.threat_data.get('top_threats', [])

        # Color code threat level
        if current >= 0.7:
            threat_color = "[bold red]"
            threat_level = "CRITICAL"
        elif current >= 0.5:
            threat_color = "[bold yellow]"
            threat_level = "HIGH"
        elif current >= 0.3:
            threat_color = "[yellow]"
            threat_level = "MEDIUM"
        else:
            threat_color = "[green]"
            threat_level = "LOW"

        # Build content with threat posture info
        content_lines = []
        content_lines.append(f"{threat_color}Current Threat[/]")
        content_lines.append(f"{current:.2f} [{threat_level}]")
        content_lines.append("")
        content_lines.append(f"[dim]Baseline:[/dim] {baseline:.2f}")
        content_lines.append(f"[red]High Threats:[/red] {high_threat}")
        content_lines.append(f"[cyan]Active:[/cyan] {active}")
        content_lines.append(f"[cyan]Monitored:[/cyan] {ips} IPs")

        # Add separator before radar graphs
        content_lines.append("")
        content_lines.append("[bold cyan]─── TOP THREAT RADAR ───[/bold cyan]")
        content_lines.append("")

        # Add radar graphs for top 3 threats
        if top_threats:
            radar_output = ThreatRadarGraph.render_comparison_radar(
                top_threats,
                width=50,
                height=10
            )
            content_lines.append(radar_output)

            # Add legend
            content_lines.append("")
            content_lines.append("[dim]THR=Threat CNF=Confidence[/dim]")
            content_lines.append("[dim]RIS=OrgRisk HOP=Distance GEO=GeoRisk[/dim]")
        else:
            content_lines.append("[dim]Scanning for threats...[/dim]")

        content = "\n".join(content_lines)

        return Panel(
            content,
            title="[bold cyan]Threat Posture[/bold cyan]",
            border_style="cyan"
        )


class EnhancedThreatGlobePanel(Static):
    """
    Top-Right (50%): Interactive Threat Visualization with 4D Globe
    Provides real-time threat heat mapping with particle system and connection visualization

    Features:
    - High-resolution Braille globe (Drawille 4x resolution if available)
    - 4D color encoding: threat/confidence/age/organization
    - Particle system for dynamic threat events
    - Great-circle connection arcs with animation
    - Real-time threat heatmaps with decay
    - Regional threat aggregation and clustering
    - Sophisticated threat zone analysis
    """

    DEFAULT_CSS = """
    EnhancedThreatGlobePanel {
        height: 100%;
        width: 100%;
        padding: 0;
        overflow: hidden;
    }
    """

    globe_data = reactive(dict)
    animation_frame = reactive(int)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.world_map = None
        self.simple_globe = None
        self.enhanced_globe = None
        self.globe_data = {
            'connections': [],
            'heatmap': {},
            'stats': {},
        }
        self.animation_frame = 0
        self.threat_regions = {}
        self.region_pings = []
        self.last_update_time = time.time()

        # Initialize flat world map (primary implementation)
        # Start with larger default size - will be resized on mount
        if FlatWorldMap:
            try:
                # Use larger default size to fill panel (will resize dynamically)
                self.world_map = FlatWorldMap(width=120, height=30)
                logger.debug("Initialized FlatWorldMap - flat 2D world map with countries and threat visualization")
            except Exception as e:
                logger.warning(f"Failed to initialize FlatWorldMap: {e}")
                self.world_map = None

        # Fallback to enhanced globe if flat map fails
        if not self.world_map and EnhancedGlobe:
            try:
                self.enhanced_globe = EnhancedGlobe(width=70, height=15)
                logger.debug("Initialized EnhancedGlobe - rotating globe with countries and connection lines")
            except Exception as e:
                logger.warning(f"Failed to initialize EnhancedGlobe: {e}")
                self.enhanced_globe = None

        # Fallback to simple globe if enhanced fails
        if not self.world_map and not self.enhanced_globe and SimpleGlobe:
            try:
                self.simple_globe = SimpleGlobe(width=70, height=15)
                logger.debug("Initialized SimpleGlobe - fallback visual rotating globe")
            except Exception as e:
                logger.warning(f"Failed to initialize SimpleGlobe: {e}")
                self.simple_globe = None

    def watch_globe_data(self, new_data: dict) -> None:
        """Update globe when data changes"""
        if self.world_map is None and self.enhanced_globe is None and self.simple_globe is None:
            return

        try:
            # Extract threat regions from connections
            connections = new_data.get('connections', [])

            # Build threat region map
            self.threat_regions = {}

            # Add connections to flat world map (primary)
            if self.world_map:
                self.world_map.clear_threats()
                for conn in connections[-50:]:  # Top 50 threats for flat map
                    try:
                        country = (conn.get('dst_country') or 'Unknown')[:2].upper()
                        threat = float(conn.get('threat_score', 0) or 0)
                        org_type = (conn.get('dst_org_type') or 'unknown').lower()
                        ip = conn.get('dst_ip', 'Unknown')

                        if country not in self.threat_regions:
                            self.threat_regions[country] = {'count': 0, 'avg_threat': 0.0, 'ips': []}

                        self.threat_regions[country]['count'] += 1
                        self.threat_regions[country]['avg_threat'] = threat
                        self.threat_regions[country]['ips'].append(ip)

                        # Add to world map
                        dst_lat = float(conn.get('dst_lat', 0) or 0)
                        dst_lon = float(conn.get('dst_lon', 0) or 0)

                        self.world_map.add_threat(
                            lat=dst_lat,
                            lon=dst_lon,
                            ip=ip,
                            threat_score=threat,
                            org_type=org_type
                        )
                    except Exception as e:
                        logger.debug(f"Failed to process connection: {e}")

            # Fallback: Add to enhanced globe if flat map not available
            elif self.enhanced_globe:
                src_lat, src_lon = 0.0, 0.0
                self.enhanced_globe.clear_connections()
                for conn in connections[-15:]:  # Top 15 threats
                    try:
                        threat = float(conn.get('threat_score', 0) or 0)
                        org_type = (conn.get('dst_org_type') or 'unknown').lower()
                        ip = conn.get('dst_ip', 'Unknown')
                        dst_lat = float(conn.get('dst_lat', 0) or 0)
                        dst_lon = float(conn.get('dst_lon', 0) or 0)

                        self.enhanced_globe.add_connection(
                            src_lat, src_lon, dst_lat, dst_lon,
                            threat, org_type, ip
                        )
                    except Exception as e:
                        logger.debug(f"Failed to process connection: {e}")

            # Fallback: Add to simple globe if enhanced not available
            elif self.simple_globe:
                for conn in connections[-20:]:  # Last 20 connections
                    try:
                        threat = float(conn.get('threat_score', 0) or 0)
                        dst_lat = float(conn.get('dst_lat', 0) or 0)
                        dst_lon = float(conn.get('dst_lon', 0) or 0)

                        self.simple_globe.add_threat(dst_lat, dst_lon, threat)
                    except Exception as e:
                        logger.debug(f"Failed to process connection: {e}")

            # Trigger animation update
            self.animation_frame += 1
            self.last_update_time = time.time()
        except Exception as e:
            logger.warning(f"Globe data watch failed: {e}")

    def watch_animation_frame(self, frame: int) -> None:
        """Animation frame update trigger"""
        self.refresh()

    def on_resize(self, event) -> None:
        """Resize world map to fill panel when size changes"""
        if self.world_map and hasattr(self.world_map, 'resize'):
            # Account for panel border only (2 chars width, 2 lines height for border)
            new_width = max(40, event.size.width - 2)
            new_height = max(12, event.size.height - 2)
            self.world_map.resize(new_width, new_height)
            logger.debug(f"Resized world map to {new_width}x{new_height}")

    def render(self):
        """Render visual threat globe with animated threat markers and connections"""
        # Render flat world map (primary)
        if self.world_map:
            try:
                # Update animation
                dt = 0.05  # 50ms per frame
                self.world_map.update(dt)

                # Render world map
                return self.world_map.render()
            except Exception as e:
                logger.debug(f"World map render failed: {e}")

        # Fallback to enhanced globe
        if self.enhanced_globe:
            try:
                # Update animation
                dt = 0.05  # 50ms per frame
                self.enhanced_globe.update(dt)

                # Render globe
                return self.enhanced_globe.render()
            except Exception as e:
                logger.debug(f"Enhanced globe render failed: {e}")

        # Fallback to simple visual globe
        if self.simple_globe:
            try:
                # Update animation
                dt = 0.1  # 100ms per frame
                self.simple_globe.update(dt)

                # Render globe
                return self.simple_globe.render()
            except Exception as e:
                logger.debug(f"Globe render failed: {e}")

        # Sophisticated fallback: Enhanced threat heatmap with multiple metrics
        lines = []
        lines.append("[bold cyan]═══════════════════════════════════════[/bold cyan]")
        lines.append("[bold cyan]🌐 GLOBAL THREAT INTELLIGENCE MAP[/bold cyan]")
        lines.append("[bold cyan]═══════════════════════════════════════[/bold cyan]")

        # Get connections from globe_data
        connections = self.globe_data.get('connections', [])

        # Geographic threat analysis
        geo_data = {}
        org_types = {}
        threat_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        # Get connections from globe_data
        connections = self.globe_data.get('connections', [])

        for conn in connections:
            country = (conn.get('dst_country') or 'XX')[:2].upper()
            threat = float(conn.get('threat_score', 0) or 0)
            org_type = (conn.get('dst_org_type') or 'unknown').lower()

            if country not in geo_data:
                geo_data[country] = {'threats': [], 'count': 0, 'types': {}}

            geo_data[country]['threats'].append(threat)
            geo_data[country]['count'] += 1
            geo_data[country]['types'][org_type] = geo_data[country]['types'].get(org_type, 0) + 1

            # Track threat distribution
            if threat >= 0.7:
                threat_stats['critical'] += 1
            elif threat >= 0.5:
                threat_stats['high'] += 1
            elif threat >= 0.3:
                threat_stats['medium'] += 1
            else:
                threat_stats['low'] += 1

        # Top threat regions
        top_regions = sorted(
            [(c, sum(d['threats'])/len(d['threats']), d['count']) for c, d in geo_data.items()],
            key=lambda x: x[1] * x[2],  # Sort by threat * count
            reverse=True
        )[:6]

        lines.append("")
        lines.append("[bold]🔴 CRITICAL THREAT ZONES:[/bold]")
        for country, avg_threat, count in top_regions:
            if avg_threat >= 0.7:
                threat_bar = "[bold red]▓▓▓▓▓▓▓▓▓▓[/bold red]"
                indicator = "[bold red]⚠ CRITICAL[/bold red]"
            elif avg_threat >= 0.5:
                threat_bar = "[bold yellow]▓▓▓▓▓▓░░░░[/bold yellow]"
                indicator = "[bold yellow]⚠ HIGH[/bold yellow]"
            elif avg_threat >= 0.3:
                threat_bar = "[yellow]▓▓▓▓░░░░░░[/yellow]"
                indicator = "[yellow]⚠ MEDIUM[/yellow]"
            else:
                threat_bar = "[green]▓▓░░░░░░░░[/green]"
                indicator = "[green]✓ LOW[/green]"

            lines.append(f"  {country:2s} {threat_bar} {avg_threat:5.2f} (n={count:2d}) {indicator}")

        lines.append("")
        lines.append("[bold]🏢 ORGANIZATION TYPE DISTRIBUTION:[/bold]")

        # Organization type breakdown
        org_summary = {}
        for country, data in geo_data.items():
            for org_type, count in data['types'].items():
                if org_type not in org_summary:
                    org_summary[org_type] = 0
                org_summary[org_type] += count

        type_colors = {
            'cloud': 'bold cyan',
            'cdn': 'cyan',
            'hosting': 'blue',
            'isp': 'magenta',
            'vpn': 'bold magenta',
            'tor': 'bold red',
            'enterprise': 'bold green',
            'government': 'bold blue',
        }

        for org_type, count in sorted(org_summary.items(), key=lambda x: x[1], reverse=True)[:5]:
            color = type_colors.get(org_type, 'white')
            lines.append(f"  [{color}]{org_type:12s}[/{color}] ▰▰▰ {count:3d} connections")

        lines.append("")
        lines.append("[bold]📊 THREAT DISTRIBUTION:[/bold]")
        total = sum(threat_stats.values())
        if total > 0:
            crit_pct = (threat_stats['critical'] / total) * 100
            high_pct = (threat_stats['high'] / total) * 100
            med_pct = (threat_stats['medium'] / total) * 100
            low_pct = (threat_stats['low'] / total) * 100

            lines.append(f"  [bold red]CRITICAL[/bold red]: {threat_stats['critical']:3d} ({crit_pct:5.1f}%) [bold red]{'█' * int(crit_pct/5)}[/bold red]")
            lines.append(f"  [bold yellow]HIGH[/bold yellow]:     {threat_stats['high']:3d} ({high_pct:5.1f}%) [bold yellow]{'█' * int(high_pct/5)}[/bold yellow]")
            lines.append(f"  [yellow]MEDIUM[/yellow]:   {threat_stats['medium']:3d} ({med_pct:5.1f}%) [yellow]{'█' * int(med_pct/5)}[/yellow]")
            lines.append(f"  [green]LOW[/green]:      {threat_stats['low']:3d} ({low_pct:5.1f}%) [green]{'█' * int(low_pct/5)}[/green]")

        lines.append("")
        lines.append(f"[dim]Total Connections: {len(connections)} | Active Regions: {len(geo_data)}[/dim]")
        lines.append("[bold cyan]═══════════════════════════════════════[/bold cyan]")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]🌐 THREAT INTELLIGENCE DASHBOARD[/bold cyan]", border_style="cyan")


class SmartConnectionTable(Static):
    """
    Enhanced connection table for both device and network modes
    Adaptive columns, threat coloring, and enrichment data
    Click on a row to view detailed connection information.
    """

    DEFAULT_CSS = """
    SmartConnectionTable {
        height: 100%;
        width: 100%;
        overflow: auto;
    }

    SmartConnectionTable DataTable {
        background: $surface;
    }
    """

    connections = reactive(list)

    def __init__(self, on_row_selected: callable = None, **kwargs):
        super().__init__(**kwargs)
        self.table = None
        self.connections = []
        self.on_row_selected = on_row_selected

    def compose(self) -> ComposeResult:
        """Create data table"""
        self.table = DataTable(id="connection_table")
        self._connection_map = {}  # Track connections by row key for detail modal

        # Enhanced columns (12 total) - shows more enrichment data
        self.table.add_column("Time", key="time", width=8)
        self.table.add_column("Src", key="src_ip", width=12)       # NEW
        self.table.add_column("Dst", key="dst_ip", width=15)
        self.table.add_column("Port", key="port", width=5)
        self.table.add_column("Proto", key="proto", width=5)       # NEW
        self.table.add_column("Org", key="org", width=15)
        self.table.add_column("Type", key="org_type", width=8)
        self.table.add_column("Risk", key="threat", width=4)
        self.table.add_column("Score", key="score", width=6)
        self.table.add_column("Conf", key="conf", width=4)         # NEW
        self.table.add_column("Hops", key="hops", width=4)
        self.table.add_column("Geo", key="country", width=3)       # NEW

        yield self.table

    def watch_connections(self, new_connections: list) -> None:
        """Update table when connections change - text color coded by threat and type"""
        if self.table is None:
            logger.warning("Connection table not yet initialized - skipping update")
            return

        if not new_connections:
            logger.debug("No connections to display")
            return

        self.connections = new_connections
        self.table.clear()
        self._connection_map = {}

        logger.debug(f"Updating connection table with {len(new_connections)} connections")

        # Add rows with text color coding by threat and type
        for conn in self.connections[:50]:  # Limit to 50 for performance
            try:
                # Handle both float timestamps and ISO string timestamps
                ts = conn.get('timestamp', 0)
                if isinstance(ts, str):
                    # Parse ISO format string (legacy data)
                    try:
                        time_str = datetime.fromisoformat(ts).strftime("%H:%M:%S")
                    except ValueError:
                        time_str = ts[:8] if len(ts) >= 8 else "??:??:??"
                else:
                    # Parse Unix timestamp (new data)
                    time_str = datetime.fromtimestamp(float(ts) if ts else 0).strftime("%H:%M:%S")
                threat = float(conn.get('threat_score', 0) or 0)
                org_type = (conn.get('dst_org_type') or 'unknown').lower()
                confidence = float(conn.get('confidence', 0) or 0)
                high_uncertainty = conn.get('high_uncertainty', False)

                # Threat color mapping (text only)
                if threat >= 0.7:
                    threat_color = "bold red"
                    threat_indicator = "●●●"
                elif threat >= 0.5:
                    threat_color = "bold yellow"
                    threat_indicator = "●●○"
                elif threat >= 0.3:
                    threat_color = "yellow"
                    threat_indicator = "●○○"
                else:
                    threat_color = "green"
                    threat_indicator = "○○○"

                # Type color mapping (text only) - based on organization type
                type_colors = {
                    'cloud': 'bold cyan',
                    'cdn': 'cyan',
                    'hosting': 'blue',
                    'isp': 'magenta',
                    'vpn': 'bold magenta',
                    'tor': 'bold red',
                    'enterprise': 'bold green',
                    'government': 'bold blue',
                    'education': 'green',
                    'unknown': 'dim white',
                }
                type_color = type_colors.get(org_type, 'dim white')

                # Extract fields
                src_ip = (conn.get('src_ip') or 'local')[:12]
                dst_ip = (conn.get('dst_ip') or 'Unknown')[:15]
                port = str(conn.get('dst_port', '-'))
                protocol = (conn.get('protocol') or 'TCP')[:5]
                org = (conn.get('dst_org') or 'Unknown')[:15]
                hops = str(conn.get('hop_count') or '-')
                country = (conn.get('dst_country') or '--')[:3]

                # Uncertainty warning indicator (! suffix on score)
                score_display = f"{threat:.2f}"
                if high_uncertainty:
                    score_display = f"{threat:.2f}!"

                # Confidence color (yellow if low, green if high)
                conf_color = 'yellow' if confidence < 0.5 else 'green'

                # Store connection for detail modal
                row_key = str(conn.get('id', id(conn)))
                self._connection_map[row_key] = conn

                # Format row with text color coding only (no backgrounds)
                self.table.add_row(
                    f"[dim]{time_str}[/]",
                    f"[cyan]{src_ip}[/]",
                    f"[cyan]{dst_ip}[/]",
                    f"[magenta]{port}[/]",
                    f"[dim]{protocol}[/]",
                    f"[white]{org}[/]",
                    f"[{type_color}]{org_type:>8}[/]",
                    f"[{threat_color}]{threat_indicator}[/]",
                    f"[{threat_color}]{score_display}[/]",
                    f"[{conf_color}]{confidence:.1f}[/]",
                    f"[cyan]{hops}[/]",
                    f"[dim]{country}[/]",
                    key=row_key
                )
            except Exception as e:
                # Log at warning level so errors are visible
                logger.warning(f"Failed to add connection row for {conn.get('dst_ip', 'unknown')}: {e}")

    def on_data_table_row_selected(self, event) -> None:
        """Handle row selection - show detail modal"""
        row_key = str(event.row_key.value) if event.row_key else None
        if row_key and row_key in self._connection_map:
            connection = self._connection_map[row_key]
            if self.on_row_selected:
                self.on_row_selected(connection)

    def get_connection_by_row_key(self, row_key: str) -> dict:
        """Get connection data by row key"""
        return self._connection_map.get(row_key, {})


class NetworkTopologyPanel(Static):
    """
    Network mode specific: Device → Destination topology
    Shows which devices are communicating with what destinations
    """

    DEFAULT_CSS = """
    NetworkTopologyPanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: auto;
    }
    """

    topology_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.flows = {}
        self.topology_data = {}

    def watch_topology_data(self, new_data: dict) -> None:
        """Update topology when data changes"""
        self.flows = new_data
        self.refresh()

    def render(self):
        """Render device→destination topology with ASCII graph"""
        if not self.flows:
            return Panel(
                "[dim]Scanning network topology...[/dim]",
                title="[bold cyan]🌐 NETWORK TOPOLOGY[/bold cyan]",
                border_style="cyan"
            )

        lines = []
        lines.append("[bold cyan]┌─────────────────────────────────────┐[/bold cyan]")
        lines.append("[bold cyan]│ PASSIVELY DISCOVERED DEVICES        │[/bold cyan]")
        lines.append("[bold cyan]└─────────────────────────────────────┘[/bold cyan]")
        lines.append("")

        device_count = len(self.flows)
        lines.append(f"[dim]Total Devices: {device_count}[/dim]")
        lines.append("")

        # Create a topology graph
        lines.append("[bold]LOCAL NETWORK TOPOLOGY:[/bold]")
        lines.append("")
        lines.append("[cyan]┌─ HOME NETWORK (Local)[/cyan]")

        device_list = list(self.flows.items())[:8]  # Top 8 devices

        for idx, (src_mac, flow_data) in enumerate(device_list):
            vendor = (flow_data.get('device_vendor', 'Unknown'))[:16]
            dest_count = len(flow_data.get('destinations', {}))
            threat_score = flow_data.get('threat_avg', 0)

            is_last = idx == len(device_list) - 1

            # Device node
            prefix = "[cyan]└─[/cyan]" if is_last else "[cyan]├─[/cyan]"

            if threat_score >= 0.7:
                threat_icon = "[bold red]⚠[/bold red]"
                threat_color = "bold red"
            elif threat_score >= 0.5:
                threat_icon = "[bold yellow]⚡[/bold yellow]"
                threat_color = "bold yellow"
            elif threat_score >= 0.3:
                threat_icon = "[yellow]△[/yellow]"
                threat_color = "yellow"
            else:
                threat_icon = "[green]✓[/green]"
                threat_color = "green"

            lines.append(f"{prefix} {threat_icon} [{threat_color}]{vendor:16s}[/{threat_color}] → {dest_count} flows")

            # Show connection flows
            destinations = sorted(
                flow_data.get('destinations', {}).items(),
                key=lambda x: float(x[1].get('threat', 0) or 0),
                reverse=True
            )[:2]  # Top 2 destinations per device

            for dest_idx, (dest, data) in enumerate(destinations):
                threat = float(data.get('threat', 0) or 0)
                count = data.get('count', 0)

                is_dest_last = dest_idx == len(destinations) - 1
                flow_prefix = "[cyan]│  └──[/cyan]" if is_dest_last else "[cyan]│  ├──[/cyan]"

                if threat >= 0.7:
                    dest_color = "bold red"
                    dest_icon = "🔴"
                elif threat >= 0.5:
                    dest_color = "bold yellow"
                    dest_icon = "🟡"
                else:
                    dest_color = "green"
                    dest_icon = "🟢"

                # Truncate IP if too long
                dest_str = dest[:18] if len(dest) > 18 else dest

                lines.append(f"{flow_prefix} {dest_icon} [{dest_color}]{dest_str:18s}[/{dest_color}] x{count}")

        lines.append("")
        lines.append("[bold cyan]═════════════════════════════════════[/bold cyan]")

        # Add statistics
        total_flows = sum(len(f.get('destinations', {})) for f in self.flows.values())
        lines.append(f"[dim]Total Flows: {total_flows} | Active Devices: {device_count}[/dim]")

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold cyan]🌐 NETWORK TOPOLOGY[/bold cyan]",
            border_style="cyan"
        )


class DeviceDiscoveryPanel(Static):
    """
    Device mode specific: Discovered devices on network
    Shows MAC addresses, vendors, and activity summary
    """

    DEFAULT_CSS = """
    DeviceDiscoveryPanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: auto;
    }
    """

    devices = reactive(list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.devices = []

    def watch_devices(self, new_devices: list) -> None:
        """Update devices when data changes"""
        self.devices = new_devices
        self.refresh()

    def render(self):
        """Render discovered devices with network topology"""
        if not self.devices:
            return Panel(
                "[dim]Scanning for connected devices...[/dim]",
                title="[bold cyan]🔍 DEVICE DISCOVERY[/bold cyan]",
                border_style="cyan"
            )

        lines = []
        lines.append("[bold cyan]┌─────────────────────────────────────┐[/bold cyan]")
        lines.append("[bold cyan]│ PASSIVELY DISCOVERED DEVICES        │[/bold cyan]")
        lines.append("[bold cyan]└─────────────────────────────────────┘[/bold cyan]")
        lines.append("")

        # Sort by threat score
        sorted_devices = sorted(
            self.devices,
            key=lambda d: float(d.get('threat_score', 0) or 0),
            reverse=True
        )[:12]  # Show top 12

        # Add summary
        lines.append(f"[dim]Discovered: {len(self.devices)} device(s)[/dim]")
        lines.append("")
        lines.append("[bold]DEVICE INVENTORY:[/bold]")
        lines.append("")

        # Build network tree
        lines.append("[cyan]┌─ LOCAL NETWORK[/cyan]")

        for idx, device in enumerate(sorted_devices):
            mac = device.get('mac', 'Unknown')[:17]
            vendor = (device.get('vendor') or 'Unknown')[:16]
            threat = float(device.get('threat_score', 0) or 0)
            conn_count = device.get('connection_count', 0)

            is_last = idx == len(sorted_devices) - 1
            prefix = "[cyan]└─[/cyan]" if is_last else "[cyan]├─[/cyan]"

            # Threat indicator with color
            if threat >= 0.7:
                threat_icon = "[bold red]⚠[/bold red]"
                threat_color = "bold red"
                threat_label = "CRITICAL"
            elif threat >= 0.5:
                threat_icon = "[bold yellow]⚡[/bold yellow]"
                threat_color = "bold yellow"
                threat_label = "HIGH"
            elif threat >= 0.3:
                threat_icon = "[yellow]△[/yellow]"
                threat_color = "yellow"
                threat_label = "MEDIUM"
            else:
                threat_icon = "[green]✓[/green]"
                threat_color = "green"
                threat_label = "LOW"

            lines.append(f"{prefix} {threat_icon} [{threat_color}]{vendor:16s}[/{threat_color}] [{threat_label:8s}] {conn_count} flows")
            lines.append(f"[dim]   └─ MAC: {mac}[/dim]")

        lines.append("")
        lines.append("[bold cyan]═════════════════════════════════════[/bold cyan]")

        # Statistics
        total_connections = sum(d.get('connection_count', 0) for d in self.devices)
        high_threat_devices = len([d for d in self.devices if float(d.get('threat_score', 0) or 0) >= 0.5])

        lines.append("")
        lines.append("[bold]NETWORK STATISTICS:[/bold]")
        lines.append(f"  [cyan]Devices:[/cyan] {len(self.devices)}")
        lines.append(f"  [cyan]Total Flows:[/cyan] {total_connections}")
        lines.append(f"  [bold yellow]High Risk:[/bold yellow] {high_threat_devices}")

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold cyan]🔍 DEVICE DISCOVERY[/bold cyan]",
            border_style="cyan"
        )


class ConnectionDetailModal(Static):
    """
    Modal dialog showing detailed connection information.
    Displays all enrichment data for a selected connection.
    """

    DEFAULT_CSS = """
    ConnectionDetailModal {
        align: center middle;
        width: 70%;
        height: auto;
        max-height: 80%;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
    }
    """

    connection = reactive(dict)

    def __init__(self, connection_data: dict = None, **kwargs):
        super().__init__(**kwargs)
        self.connection = connection_data or {}

    def watch_connection(self, new_connection: dict) -> None:
        """Update when connection changes"""
        self.connection = new_connection
        self.refresh()

    def render(self):
        """Render detailed connection information"""
        conn = self.connection
        if not conn:
            return Panel(
                "[dim]No connection selected[/dim]",
                title="[bold cyan]CONNECTION DETAILS[/bold cyan]",
                border_style="cyan"
            )

        # Build detailed view
        lines = []

        # Header with threat indicator
        threat = float(conn.get('threat_score', 0) or 0)
        if threat >= 0.7:
            threat_style = "[bold red]"
            threat_label = "CRITICAL"
            threat_bar = "█████████████████████"
        elif threat >= 0.5:
            threat_style = "[bold yellow]"
            threat_label = "HIGH"
            threat_bar = "█████████████░░░░░░░░"
        elif threat >= 0.3:
            threat_style = "[yellow]"
            threat_label = "MEDIUM"
            threat_bar = "████████░░░░░░░░░░░░░"
        else:
            threat_style = "[green]"
            threat_label = "LOW"
            threat_bar = "████░░░░░░░░░░░░░░░░░"

        lines.append(f"{threat_style}╔══════════════════════════════════════════════════╗[/]")
        lines.append(f"{threat_style}║  THREAT LEVEL: {threat_label:8s}  Score: {threat:.3f}          ║[/]")
        lines.append(f"{threat_style}║  {threat_bar}  ║[/]")
        lines.append(f"{threat_style}╚══════════════════════════════════════════════════╝[/]")
        lines.append("")

        # Timestamp
        timestamp = conn.get('timestamp', 0)
        if timestamp:
            time_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        else:
            time_str = "Unknown"
        lines.append(f"[bold cyan]📅 TIMESTAMP:[/bold cyan] {time_str}")
        lines.append("")

        # Network Information
        lines.append("[bold cyan]═══ NETWORK INFORMATION ═══[/bold cyan]")
        lines.append(f"  [cyan]Source IP:[/cyan]      {conn.get('src_ip', 'local')}")
        lines.append(f"  [cyan]Source MAC:[/cyan]     {conn.get('src_mac', 'Unknown')}")
        lines.append(f"  [cyan]Destination IP:[/cyan] {conn.get('dst_ip', 'Unknown')}")
        lines.append(f"  [cyan]Port:[/cyan]           {conn.get('dst_port', '-')}")
        lines.append(f"  [cyan]Protocol:[/cyan]       {conn.get('protocol', 'TCP')}")
        lines.append("")

        # Geolocation
        lines.append("[bold cyan]═══ GEOLOCATION ═══[/bold cyan]")
        lines.append(f"  [cyan]Country:[/cyan]        {conn.get('dst_country', 'Unknown')}")
        lines.append(f"  [cyan]Latitude:[/cyan]       {conn.get('dst_lat', 0):.4f}")
        lines.append(f"  [cyan]Longitude:[/cyan]      {conn.get('dst_lon', 0):.4f}")
        lines.append(f"  [cyan]Hostname:[/cyan]       {conn.get('dst_hostname', 'N/A')}")
        lines.append("")

        # Organization Intelligence
        lines.append("[bold cyan]═══ ORGANIZATION INTEL ═══[/bold cyan]")
        org_type = (conn.get('dst_org_type') or 'unknown').lower()
        org_trust = float(conn.get('org_trust_score', 0) or 0)

        type_colors = {
            'cloud': 'bold cyan', 'cdn': 'cyan', 'hosting': 'blue',
            'isp': 'magenta', 'vpn': 'bold magenta', 'tor': 'bold red',
            'enterprise': 'bold green', 'government': 'bold blue',
        }
        org_color = type_colors.get(org_type, 'white')

        lines.append(f"  [cyan]Organization:[/cyan]   {conn.get('dst_org', 'Unknown')}")
        lines.append(f"  [cyan]Type:[/cyan]           [{org_color}]{org_type.upper()}[/{org_color}]")
        lines.append(f"  [cyan]Trust Score:[/cyan]    {org_trust:.2f}")
        lines.append(f"  [cyan]ASN:[/cyan]            {conn.get('dst_asn', 'N/A')}")
        lines.append(f"  [cyan]ASN Name:[/cyan]       {conn.get('dst_asn_name', 'N/A')}")
        lines.append(f"  [cyan]CIDR:[/cyan]           {conn.get('dst_cidr', 'N/A')}")
        lines.append("")

        # Network Topology
        lines.append("[bold cyan]═══ NETWORK TOPOLOGY ═══[/bold cyan]")
        ttl_observed = conn.get('ttl_observed', 0)
        ttl_initial = conn.get('ttl_initial', 0)
        hop_count = conn.get('hop_count', 0)
        os_fingerprint = conn.get('os_fingerprint', 'Unknown')

        lines.append(f"  [cyan]TTL Observed:[/cyan]   {ttl_observed}")
        lines.append(f"  [cyan]TTL Initial:[/cyan]    {ttl_initial}")
        lines.append(f"  [cyan]Hop Count:[/cyan]      {hop_count}")
        lines.append(f"  [cyan]OS Fingerprint:[/cyan] {os_fingerprint}")
        lines.append("")

        # Scoring Details
        lines.append("[bold cyan]═══ THREAT SCORING ═══[/bold cyan]")
        confidence = float(conn.get('confidence', 0) or 0)
        high_uncertainty = conn.get('high_uncertainty', False)
        scoring_method = conn.get('scoring_method', 'consensus')

        conf_color = 'green' if confidence >= 0.7 else 'yellow' if confidence >= 0.5 else 'red'
        uncertainty_icon = "[bold yellow]⚠ HIGH UNCERTAINTY[/bold yellow]" if high_uncertainty else "[green]✓ Confirmed[/green]"

        lines.append(f"  [cyan]Threat Score:[/cyan]   {threat_style}{threat:.3f}[/]")
        lines.append(f"  [cyan]Confidence:[/cyan]     [{conf_color}]{confidence:.2f}[/{conf_color}]")
        lines.append(f"  [cyan]Uncertainty:[/cyan]    {uncertainty_icon}")
        lines.append(f"  [cyan]Method:[/cyan]         {scoring_method}")
        lines.append("")

        lines.append("[dim]Press ESC or click outside to close[/dim]")

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold cyan]🔍 CONNECTION DETAILS[/bold cyan]",
            border_style="cyan"
        )


class AnomalyAlertPanel(Static):
    """
    Shows recent anomaly detections from threat analytics.
    Displays last 5 anomalies with score, type, IP, and severity.
    """

    DEFAULT_CSS = """
    AnomalyAlertPanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: auto;
    }
    """

    anomalies = reactive(list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.anomalies = []

    def watch_anomalies(self, new_anomalies: list) -> None:
        """Update anomalies when data changes"""
        self.anomalies = new_anomalies
        self.refresh()

    def render(self):
        """Render recent anomaly alerts"""
        if not self.anomalies:
            return Panel(
                "[dim]No anomalies detected[/dim]\n\n"
                "[green]✓[/green] System nominal\n"
                "[dim]Monitoring for statistical outliers,\n"
                "unusual patterns, and threat spikes...[/dim]",
                title="[bold yellow]⚡ ANOMALY ALERTS[/bold yellow]",
                border_style="yellow"
            )

        lines = []
        lines.append("[bold yellow]┌─────────────────────────────────────┐[/bold yellow]")
        lines.append("[bold yellow]│ RECENT ANOMALY DETECTIONS           │[/bold yellow]")
        lines.append("[bold yellow]└─────────────────────────────────────┘[/bold yellow]")
        lines.append("")

        # Severity icons and colors
        severity_styles = {
            'CRITICAL': ('[bold red]', '🔴', 'CRITICAL'),
            'HIGH': ('[bold yellow]', '🟠', 'HIGH'),
            'MEDIUM': ('[yellow]', '🟡', 'MEDIUM'),
            'LOW': ('[green]', '🟢', 'LOW'),
            'INFO': ('[dim]', 'ℹ️', 'INFO'),
        }

        # Show last 5 anomalies
        for idx, anomaly in enumerate(self.anomalies[:5]):
            anomaly_type = anomaly.get('anomaly_type', 'unknown')
            severity = anomaly.get('severity', 'MEDIUM').upper()
            score = float(anomaly.get('anomaly_score', 0) or 0)
            ip = anomaly.get('dst_ip', 'Unknown')[:15]
            message = (anomaly.get('message') or anomaly_type)[:30]
            timestamp = anomaly.get('timestamp', 0)

            style, icon, label = severity_styles.get(severity, ('[dim]', '○', 'UNKNOWN'))

            # Time formatting
            if timestamp:
                time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
            else:
                time_str = "--:--:--"

            lines.append(f"{icon} {style}{label:8s}[/] [{time_str}]")
            lines.append(f"   {style}{anomaly_type:12s}[/] {score:.2f}")
            lines.append(f"   [cyan]{ip}[/cyan]")
            lines.append(f"   [dim]{message}[/dim]")
            lines.append("")

        # Summary statistics
        critical_count = sum(1 for a in self.anomalies if a.get('severity', '').upper() == 'CRITICAL')
        high_count = sum(1 for a in self.anomalies if a.get('severity', '').upper() == 'HIGH')

        lines.append("[bold yellow]═════════════════════════════════════[/bold yellow]")
        lines.append("")
        lines.append("[bold]ANOMALY SUMMARY:[/bold]")
        lines.append(f"  [bold red]Critical:[/bold red] {critical_count}")
        lines.append(f"  [bold yellow]High:[/bold yellow] {high_count}")
        lines.append(f"  [dim]Total:[/dim] {len(self.anomalies)}")

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold yellow]⚡ ANOMALY ALERTS[/bold yellow]",
            border_style="yellow"
        )


class CobaltGraphDashboardEnhanced(UnifiedDashboard):
    """
    Enhanced unified dashboard with mode support (device/network)
    4-cell grid layout (2x2) combining best components

    Grid Layout:
    ┌──────────────────────────────────┬──────────────────────────────────┐
    │ Top-Left (50%):                  │ Top-Right (50%):                 │
    │ Threat Posture + Stats           │ Threat Globe (ASCII)             │
    │                                  │ Heatmaps + Connection Trails     │
    ├──────────────────────────────────┼──────────────────────────────────┤
    │ Bottom-Left (50%):               │ Bottom-Right (50%):              │
    │ Connection Table (PRIMARY)       │ Mode-Specific Panel              │
    │ Full enrichment data             │ Device Discovery / Network Topo  │
    └──────────────────────────────────┴──────────────────────────────────┘

    Modes:
    - device: Personal device security focus
    - network: Network-wide topology and threat monitoring
    """

    BINDINGS = [
        ("q", "quit", "Quit Application"),
        ("r", "refresh", "Refresh Data"),
        ("a", "toggle_anomalies", "Toggle Anomaly Panel"),
        ("g", "toggle_globe", "Pause/Resume Globe Animation"),
        ("m", "toggle_mode_panel", "Toggle Mode Panel"),
        ("escape", "close_modal", "Close Modal"),
        ("?", "help", "Show Keybindings"),
        ("ctrl+p", "command_palette", "Command Palette"),
    ]

    CSS = """
    Screen {
        layout: vertical;
    }

    Header {
        dock: top;
        height: 1;
    }

    Footer {
        dock: bottom;
        height: 1;
    }

    #main_grid {
        height: 1fr;
        layout: vertical;
    }

    #top_row {
        height: 50%;
        layout: horizontal;
    }

    #bottom_row {
        height: 50%;
        layout: horizontal;
    }

    #top_left {
        width: 50%;
        padding: 0 1 0 0;
    }

    #top_right {
        width: 50%;
        padding: 0 0 0 1;
    }

    #bottom_left {
        width: 50%;
        padding: 1 1 0 0;
    }

    #bottom_right {
        width: 50%;
        padding: 1 0 0 1;
    }

    #anomaly_panel {
        width: 50%;
        padding: 1 0 0 1;
        display: none;
    }

    #anomaly_panel.visible {
        display: block;
    }

    #detail_modal {
        display: none;
        layer: modal;
        dock: top;
        margin: 2 4;
    }

    #detail_modal.visible {
        display: block;
    }

    #modal_backdrop {
        display: none;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        layer: backdrop;
    }

    #modal_backdrop.visible {
        display: block;
    }
    """

    def __init__(self, db_path: str = "data/cobaltgraph.db", mode: str = "device"):
        """Initialize enhanced dashboard with mode"""
        super().__init__(db_path=db_path, mode=mode)
        self.title = f"CobaltGraph - {mode.upper()} Mode"
        self.sub_title = "Loading..."

        # Panels
        self.threat_posture_panel = None
        self.globe_panel = None
        self.connection_table = None
        self.mode_specific_panel = None
        self.anomaly_panel = None
        self.detail_modal = None
        self.modal_backdrop = None

    def compose(self) -> ComposeResult:
        """4-cell grid layout with mode-aware content"""
        yield Header()

        with Vertical(id="main_grid"):
            # Top row: Threat Posture (left) + Globe (right)
            with Horizontal(id="top_row"):
                self.threat_posture_panel = ThreatPostureQuickPanel(id="top_left")
                yield self.threat_posture_panel

                self.globe_panel = EnhancedThreatGlobePanel(id="top_right")
                yield self.globe_panel

            # Bottom row: Connection Table (left) + Mode-specific (right)
            with Horizontal(id="bottom_row"):
                self.connection_table = SmartConnectionTable(
                    id="bottom_left",
                    on_row_selected=self._show_connection_detail
                )
                yield self.connection_table

                # Mode-specific panel
                if self.mode == "network":
                    self.mode_specific_panel = NetworkTopologyPanel(id="bottom_right")
                else:
                    self.mode_specific_panel = DeviceDiscoveryPanel(id="bottom_right")

                yield self.mode_specific_panel

                # Anomaly panel (hidden by default, toggle with 'a')
                self.anomaly_panel = AnomalyAlertPanel(id="anomaly_panel")
                yield self.anomaly_panel

        # Detail modal (hidden by default, shown on row click)
        self.modal_backdrop = Static(id="modal_backdrop")
        yield self.modal_backdrop
        self.detail_modal = ConnectionDetailModal(id="detail_modal")
        yield self.detail_modal

        yield Footer()

    def action_refresh(self) -> None:
        """Manual refresh action"""
        self._refresh_data()

    def on_mount(self) -> None:
        """Initialize dashboard on mount"""
        self.title = f"CobaltGraph Enhanced - {self.mode.upper()} Mode"

        if self.data_manager.connect():
            self.is_connected = True
            self.set_interval(2.0, self._refresh_data)
            self.set_interval(0.1, self._update_display)  # 100ms for smooth animations
            self._refresh_data()
        else:
            self.sub_title = "Database connection failed"

    def _refresh_data(self) -> None:
        """Refresh data from database"""
        try:
            if not self.data_manager.is_connected:
                logger.warning("Data manager not connected - skipping refresh")
                return

            # Get connections
            connections = self.data_manager.get_connections(limit=100)
            if not connections:
                logger.debug("No connections returned from database")
            else:
                logger.debug(f"Fetched {len(connections)} connections from database")
            self.recent_connections = deque(connections, maxlen=100)

            # Calculate threat statistics
            threat_scores = [float(c.get('threat_score', 0) or 0) for c in connections]
            current_threat = (sum(threat_scores) / len(threat_scores)) if threat_scores else 0
            high_threat_count = sum(1 for t in threat_scores if t >= 0.7)

            # Get top 3 threat connections for radar graphs
            top_threats = sorted(
                connections,
                key=lambda c: float(c.get('threat_score', 0) or 0),
                reverse=True
            )[:3]

            # Update threat posture panel
            if self.threat_posture_panel:
                self.threat_posture_panel.threat_data = {
                    'current_threat': current_threat,
                    'baseline_threat': 0.2,  # Default baseline
                    'active_threats': high_threat_count,
                    'monitored_ips': len(set(c.get('dst_ip') for c in connections)),
                    'high_threat_count': high_threat_count,
                    'top_threats': top_threats,  # Add top 3 for radar graphs
                }

            # Update connection table
            if self.connection_table:
                self.connection_table.connections = connections

            # Update globe with new connections
            if self.globe_panel:
                self.globe_panel.globe_data = {
                    'connections': connections,
                    'heatmap': self._calculate_heatmap(connections),
                }

            # Mode-specific updates
            if self.mode == "network":
                devices = self.data_manager.get_devices() if hasattr(self.data_manager, 'get_devices') else []
                if self.mode_specific_panel and isinstance(self.mode_specific_panel, NetworkTopologyPanel):
                    self.mode_specific_panel.topology_data = self._build_topology(connections, devices)
            else:
                devices = self.data_manager.get_devices() if hasattr(self.data_manager, 'get_devices') else []
                if self.mode_specific_panel and isinstance(self.mode_specific_panel, DeviceDiscoveryPanel):
                    self.mode_specific_panel.devices = devices

            # Fetch and update anomalies
            if self.anomaly_panel:
                anomalies = self.data_manager.get_anomalies(limit=10) if hasattr(self.data_manager, 'get_anomalies') else []

                # If no anomalies from events table, generate from high-threat connections
                if not anomalies and high_threat_count > 0:
                    anomalies = self._generate_anomalies_from_threats(connections)

                self.anomaly_panel.anomalies = anomalies

            # Update stats
            stats = self.data_manager.get_stats()
            self.sub_title = f"Updated: {datetime.now().strftime('%H:%M:%S')} | Connections: {stats.get('total', 0)} | Risk: {current_threat:.2f}"

        except Exception as e:
            logger.error(f"Refresh failed: {e}")
            self.sub_title = f"Error: {str(e)[:30]}"

    def _update_display(self) -> None:
        """Quick display updates (animations, etc)"""
        # Update globe animation
        if self.globe_panel:
            try:
                # Update the appropriate visualization component
                if self.globe_panel.world_map:
                    self.globe_panel.world_map.update(0.05)  # Update every 50ms
                    self.globe_panel.refresh()  # Force re-render
                elif self.globe_panel.enhanced_globe:
                    self.globe_panel.enhanced_globe.update(0.05)
                    self.globe_panel.refresh()
                elif self.globe_panel.simple_globe:
                    self.globe_panel.simple_globe.update(0.05)  # Consistent with other globe types
                    self.globe_panel.refresh()
            except Exception as e:
                logger.debug(f"Globe update failed: {e}")

    def _calculate_heatmap(self, connections: List[Dict]) -> Dict:
        """Calculate geographic heatmap from connections"""
        heatmap = defaultdict(float)
        for conn in connections:
            lat = conn.get('dst_lat')
            lon = conn.get('dst_lon')
            threat = float(conn.get('threat_score', 0) or 0)

            if lat and lon:
                key = (round(lat, 0), round(lon, 0))
                heatmap[key] += threat

        return dict(heatmap)

    def _generate_anomalies_from_threats(self, connections: List[Dict]) -> List[Dict]:
        """
        Generate anomaly-like data from high-threat connections.
        Used when no events exist in database to provide visual feedback.
        """
        anomalies = []
        for conn in connections:
            threat = float(conn.get('threat_score', 0) or 0)
            if threat >= 0.5:
                # Determine severity and type based on threat score and other factors
                if threat >= 0.8:
                    severity = 'CRITICAL'
                    anomaly_type = 'high_threat'
                elif threat >= 0.7:
                    severity = 'HIGH'
                    anomaly_type = 'elevated_risk'
                else:
                    severity = 'MEDIUM'
                    anomaly_type = 'suspicious'

                # Check for consensus uncertainty
                if conn.get('high_uncertainty', False):
                    anomaly_type = 'consensus_uncertain'
                    severity = 'HIGH'

                anomalies.append({
                    'timestamp': conn.get('timestamp', time.time()),
                    'anomaly_type': anomaly_type,
                    'anomaly_score': threat,
                    'severity': severity,
                    'dst_ip': conn.get('dst_ip', 'Unknown'),
                    'message': f"{conn.get('dst_org', 'Unknown')} - {conn.get('dst_org_type', 'unknown')}",
                })

                if len(anomalies) >= 10:
                    break

        return anomalies

    def _build_topology(self, connections: List[Dict], devices: List[Dict]) -> Dict:
        """Build device→destination topology"""
        topology = defaultdict(lambda: {
            'device_vendor': 'Unknown',
            'destinations': defaultdict(lambda: {
                'count': 0,
                'threat': 0.0,
                'org': 'Unknown'
            })
        })

        device_map = {d.get('mac', ''): d for d in devices}

        for conn in connections:
            src_mac = conn.get('src_mac', 'Unknown')
            dst_ip = conn.get('dst_ip', 'Unknown')
            dst_port = conn.get('dst_port', '-')
            threat = float(conn.get('threat_score', 0) or 0)
            org = (conn.get('dst_org') or 'Unknown')[:15]

            if src_mac in device_map:
                topology[src_mac]['device_vendor'] = device_map[src_mac].get('vendor', 'Unknown')

            key = f"{dst_ip}:{dst_port}"
            topology[src_mac]['destinations'][key]['count'] += 1
            topology[src_mac]['destinations'][key]['threat'] = max(
                topology[src_mac]['destinations'][key]['threat'], threat
            )
            topology[src_mac]['destinations'][key]['org'] = org

        return dict(topology)

    def action_quit(self) -> None:
        """Quit application"""
        self.exit()

    def action_help(self) -> None:
        """Show keybindings help in subtitle"""
        help_text = "Keys: Q=Quit | R=Refresh | A=Anomalies | G=Globe | M=Mode Panel | ?=Help | Ctrl+P=Commands | ESC=Close"
        self.sub_title = help_text

    def _show_connection_detail(self, connection: dict) -> None:
        """Show connection detail modal"""
        if self.detail_modal and self.modal_backdrop:
            self.detail_modal.connection = connection
            self.detail_modal.add_class("visible")
            self.detail_modal.styles.display = "block"
            self.modal_backdrop.add_class("visible")
            self.modal_backdrop.styles.display = "block"
            self.sub_title = f"Viewing details for {connection.get('dst_ip', 'Unknown')} - Press ESC to close"

    def action_close_modal(self) -> None:
        """Close the detail modal"""
        if self.detail_modal and self.modal_backdrop:
            modal_visible = self.detail_modal.has_class("visible")
            if modal_visible:
                self.detail_modal.remove_class("visible")
                self.detail_modal.styles.display = "none"
                self.modal_backdrop.remove_class("visible")
                self.modal_backdrop.styles.display = "none"
                self.sub_title = "Modal closed"

    def action_toggle_anomalies(self) -> None:
        """Toggle anomaly panel visibility (swaps with mode-specific panel)"""
        if self.anomaly_panel and self.mode_specific_panel:
            # Toggle visibility
            anomaly_visible = self.anomaly_panel.has_class("visible")

            if anomaly_visible:
                # Hide anomaly panel, show mode-specific panel
                self.anomaly_panel.remove_class("visible")
                self.anomaly_panel.styles.display = "none"
                self.mode_specific_panel.styles.display = "block"
                self.sub_title = f"Showing {self.mode} panel"
            else:
                # Show anomaly panel, hide mode-specific panel
                self.anomaly_panel.add_class("visible")
                self.anomaly_panel.styles.display = "block"
                self.mode_specific_panel.styles.display = "none"
                self.sub_title = "Showing anomaly alerts (press 'a' to toggle)"

    def action_toggle_globe(self) -> None:
        """Toggle globe animation pause/resume"""
        if self.globe_panel:
            # Toggle animation state by controlling the update timer
            if hasattr(self, '_globe_paused') and self._globe_paused:
                self._globe_paused = False
                self.sub_title = "Globe animation resumed"
            else:
                self._globe_paused = True
                self.sub_title = "Globe animation paused"

    def action_toggle_mode_panel(self) -> None:
        """Toggle between mode-specific panel and anomaly panel"""
        if self.mode_specific_panel and self.anomaly_panel:
            # Check current visibility state
            anomaly_visible = self.anomaly_panel.has_class("visible")
            if anomaly_visible:
                # Show mode panel, hide anomaly
                self.anomaly_panel.remove_class("visible")
                self.anomaly_panel.styles.display = "none"
                self.mode_specific_panel.styles.display = "block"
                panel_name = "Network Topology" if self.mode == "network" else "Device Discovery"
                self.sub_title = f"Showing {panel_name} panel"
            else:
                # Show anomaly, hide mode panel
                self.anomaly_panel.add_class("visible")
                self.anomaly_panel.styles.display = "block"
                self.mode_specific_panel.styles.display = "none"
                self.sub_title = "Showing Anomaly Alerts panel"


if __name__ == '__main__':
    import sys

    mode = "device"
    db_path = "data/cobaltgraph.db"

    if len(sys.argv) > 1:
        mode = sys.argv[1]

    dashboard = CobaltGraphDashboardEnhanced(db_path=db_path, mode=mode)
    dashboard.run()
