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
    Plus: subtle pulse animation for active threat awareness
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

    # Pulse animation characters for "breathing" effect
    PULSE_CHARS = ['◦', '○', '◎', '●', '◉', '●', '◎', '○']
    ACTIVITY_CHARS = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._pulse_frame = 0
        self._activity_frame = 0
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
        self._activity_frame = (self._activity_frame + 1) % len(self.ACTIVITY_CHARS)
        self.refresh()

    def pulse(self) -> None:
        """Advance pulse animation frame"""
        self._pulse_frame = (self._pulse_frame + 1) % len(self.PULSE_CHARS)
        self.refresh()

    def render(self):
        """Render threat posture with radar graphs for top 3 threats"""
        current = self.threat_data.get('current_threat', 0)
        baseline = self.threat_data.get('baseline_threat', 0)
        active = self.threat_data.get('active_threats', 0)
        ips = self.threat_data.get('monitored_ips', 0)
        high_threat = self.threat_data.get('high_threat_count', 0)
        top_threats = self.threat_data.get('top_threats', [])

        # Pulse character for activity indication
        pulse = self.PULSE_CHARS[self._pulse_frame]
        activity = self.ACTIVITY_CHARS[self._activity_frame]

        # Color code threat level with pulse
        if current >= 0.7:
            threat_color = "[bold red]"
            threat_level = "CRITICAL"
            pulse_color = "[bold red]"
        elif current >= 0.5:
            threat_color = "[bold yellow]"
            threat_level = "HIGH"
            pulse_color = "[bold yellow]"
        elif current >= 0.3:
            threat_color = "[yellow]"
            threat_level = "MEDIUM"
            pulse_color = "[yellow]"
        else:
            threat_color = "[green]"
            threat_level = "LOW"
            pulse_color = "[green]"

        # Build content with threat posture info
        content_lines = []
        content_lines.append(f"{pulse_color}{pulse}[/] {threat_color}Threat Level[/] {pulse_color}{pulse}[/]")
        content_lines.append(f"  {threat_color}{current:.2f}[/] [{threat_level}]")
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

    # Map types for cycling
    MAP_TYPES = ["flat", "rotating", "simple"]

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
        self._current_map_type = "flat"  # Track current map type

        # Initialize all map types for cycling
        self._init_all_maps()

    def _init_all_maps(self) -> None:
        """Initialize all available map implementations for cycling"""
        # Initialize flat world map
        if FlatWorldMap:
            try:
                self.world_map = FlatWorldMap(width=120, height=30)
                logger.debug("Initialized FlatWorldMap")
            except Exception as e:
                logger.warning(f"Failed to initialize FlatWorldMap: {e}")
                self.world_map = None

        # Initialize enhanced globe
        if EnhancedGlobe:
            try:
                self.enhanced_globe = EnhancedGlobe(width=70, height=15)
                logger.debug("Initialized EnhancedGlobe")
            except Exception as e:
                logger.warning(f"Failed to initialize EnhancedGlobe: {e}")
                self.enhanced_globe = None

        # Initialize simple globe
        if SimpleGlobe:
            try:
                self.simple_globe = SimpleGlobe(width=70, height=15)
                logger.debug("Initialized SimpleGlobe")
            except Exception as e:
                logger.warning(f"Failed to initialize SimpleGlobe: {e}")
                self.simple_globe = None

        # Set initial map type based on what's available
        if self.world_map:
            self._current_map_type = "flat"
        elif self.enhanced_globe:
            self._current_map_type = "rotating"
        elif self.simple_globe:
            self._current_map_type = "simple"

    def cycle_map_type(self) -> str:
        """
        Cycle to the next available intel map type.

        Returns:
            Name of the new active map type
        """
        available_maps = []
        if self.world_map:
            available_maps.append("flat")
        if self.enhanced_globe:
            available_maps.append("rotating")
        if self.simple_globe:
            available_maps.append("simple")

        if not available_maps:
            return "none"

        # Find current index and move to next
        try:
            current_idx = available_maps.index(self._current_map_type)
            next_idx = (current_idx + 1) % len(available_maps)
        except ValueError:
            next_idx = 0

        self._current_map_type = available_maps[next_idx]
        self.refresh()

        return self._current_map_type

    @property
    def current_map_type(self) -> str:
        """Get the currently active map type"""
        return self._current_map_type

    @property
    def current_map_name(self) -> str:
        """Get a display name for the current map type"""
        names = {
            "flat": "Flat World Map",
            "rotating": "Rotating Globe",
            "simple": "Simple Globe",
        }
        return names.get(self._current_map_type, "Unknown")

    def watch_globe_data(self, new_data: dict) -> None:
        """Update all globe types when data changes (for seamless cycling)"""
        if self.world_map is None and self.enhanced_globe is None and self.simple_globe is None:
            return

        try:
            connections = new_data.get('connections', [])
            self.threat_regions = {}

            # Populate ALL map types for seamless cycling
            # 1. Flat World Map
            if self.world_map:
                self.world_map.clear_threats()
                for conn in connections[-50:]:
                    try:
                        country = (conn.get('dst_country') or 'XX')[:2].upper()
                        threat = float(conn.get('threat_score', 0) or 0)
                        org_type = (conn.get('dst_org_type') or 'unknown').lower()
                        ip = conn.get('dst_ip', 'Unknown')
                        dst_lat = float(conn.get('dst_lat', 0) or 0)
                        dst_lon = float(conn.get('dst_lon', 0) or 0)

                        if country not in self.threat_regions:
                            self.threat_regions[country] = {'count': 0, 'avg_threat': 0.0, 'ips': []}
                        self.threat_regions[country]['count'] += 1
                        self.threat_regions[country]['avg_threat'] = threat
                        self.threat_regions[country]['ips'].append(ip)

                        self.world_map.add_threat(
                            lat=dst_lat, lon=dst_lon,
                            ip=ip, threat_score=threat, org_type=org_type
                        )
                    except Exception as e:
                        logger.debug(f"Failed to add to world map: {e}")

            # 2. Enhanced Globe (rotating)
            if self.enhanced_globe:
                self.enhanced_globe.clear_connections()
                for conn in connections[-15:]:
                    try:
                        threat = float(conn.get('threat_score', 0) or 0)
                        org_type = (conn.get('dst_org_type') or 'unknown').lower()
                        ip = conn.get('dst_ip', 'Unknown')
                        dst_lat = float(conn.get('dst_lat', 0) or 0)
                        dst_lon = float(conn.get('dst_lon', 0) or 0)

                        self.enhanced_globe.add_connection(
                            0.0, 0.0, dst_lat, dst_lon,
                            threat, org_type, ip
                        )
                    except Exception as e:
                        logger.debug(f"Failed to add to enhanced globe: {e}")

            # 3. Simple Globe (fallback)
            if self.simple_globe:
                self.simple_globe.clear_threats()
                for conn in connections[-20:]:
                    try:
                        threat = float(conn.get('threat_score', 0) or 0)
                        dst_lat = float(conn.get('dst_lat', 0) or 0)
                        dst_lon = float(conn.get('dst_lon', 0) or 0)

                        self.simple_globe.add_threat(dst_lat, dst_lon, threat)
                    except Exception as e:
                        logger.debug(f"Failed to add to simple globe: {e}")

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
        """Render the currently selected intel map type"""
        dt = 0.05  # Animation delta time

        # Render based on current map type selection
        if self._current_map_type == "flat" and self.world_map:
            try:
                self.world_map.update(dt)
                return self.world_map.render()
            except Exception as e:
                logger.debug(f"World map render failed: {e}")

        elif self._current_map_type == "rotating" and self.enhanced_globe:
            try:
                self.enhanced_globe.update(dt)
                return self.enhanced_globe.render()
            except Exception as e:
                logger.debug(f"Enhanced globe render failed: {e}")

        elif self._current_map_type == "simple" and self.simple_globe:
            try:
                self.simple_globe.update(0.1)
                return self.simple_globe.render()
            except Exception as e:
                logger.debug(f"Simple globe render failed: {e}")

        # Fallback chain if selected type not available
        if self.world_map:
            try:
                self.world_map.update(dt)
                return self.world_map.render()
            except Exception:
                pass

        if self.enhanced_globe:
            try:
                self.enhanced_globe.update(dt)
                return self.enhanced_globe.render()
            except Exception:
                pass

        if self.simple_globe:
            try:
                self.simple_globe.update(0.1)
                return self.simple_globe.render()
            except Exception:
                pass

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

    SmartConnectionTable .connection-key {
        dock: bottom;
        height: 1;
        padding: 0 1;
        background: $surface;
    }
    """

    connections = reactive(list)

    # Data flow indicators
    FLOW_CHARS = ['▸', '▹', '▸', '▹']

    def __init__(self, on_row_selected: callable = None, **kwargs):
        super().__init__(**kwargs)
        self.table = None
        self.connections = []
        self.on_row_selected = on_row_selected
        self._flow_frame = 0
        self._last_count = 0

    def compose(self) -> ComposeResult:
        """Create data table"""
        self.table = DataTable(id="connection_table")
        self._connection_map = {}  # Track connections by row key for detail modal

        # Enhanced columns (13 total) - shows more enrichment data + anomaly/spread
        self.table.add_column("Time", key="time", width=8)
        self.table.add_column("Src", key="src_ip", width=12)
        self.table.add_column("Dst", key="dst_ip", width=15)
        self.table.add_column("Port", key="port", width=5)
        self.table.add_column("Proto", key="proto", width=5)
        self.table.add_column("Org", key="org", width=12)
        self.table.add_column("Type", key="org_type", width=7)
        self.table.add_column("Risk", key="threat", width=4)
        self.table.add_column("Score", key="score", width=5)
        self.table.add_column("Anom", key="anomaly", width=4)      # Anomaly score
        self.table.add_column("Sprd", key="spread", width=4)       # Score spread
        self.table.add_column("Hops", key="hops", width=4)
        self.table.add_column("Geo", key="country", width=3)

        yield self.table
        yield Static(self._render_connection_key(), classes="connection-key")

    def _render_connection_key(self) -> Text:
        """Render key explaining connection security metrics"""
        key = Text()
        key.append("Risk:", style="dim bold")
        key.append(" ●", style="bold red")
        key.append("H", style="dim")
        key.append(" ●", style="bold yellow")
        key.append("M", style="dim")
        key.append(" ●", style="green")
        key.append("L", style="dim")
        key.append(" │ ", style="dim")
        key.append("Anom", style="dim bold")
        key.append("=Anomaly ", style="dim")
        key.append("Sprd", style="dim bold")
        key.append("=Disagreement ", style="dim")
        key.append("Hops", style="dim bold")
        key.append("=NetDist(resp) ", style="dim")
        key.append("│ ", style="dim")
        key.append("TOR", style="bold red")
        key.append("/", style="dim")
        key.append("VPN", style="bold magenta")
        key.append("=Anon", style="dim")
        return key

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
                # Show '--' for outbound traffic (no response TTL), value for measured hops
                hop_count = conn.get('hop_count')
                hops = str(hop_count) if hop_count is not None else '--'
                country = (conn.get('dst_country') or '--')[:3]

                # Uncertainty warning indicator (! suffix on score)
                score_display = f"{threat:.2f}"
                if high_uncertainty:
                    score_display = f"{threat:.2f}!"

                # Confidence color (yellow if low, green if high)
                conf_color = 'yellow' if confidence < 0.5 else 'green'

                # Anomaly score - highlight if > 0.6
                anomaly_score = float(conn.get('anomaly_score', 0) or 0)
                if anomaly_score >= 0.8:
                    anomaly_color = 'bold red'
                    anomaly_display = f"{anomaly_score:.1f}!"
                elif anomaly_score >= 0.6:
                    anomaly_color = 'bold yellow'
                    anomaly_display = f"{anomaly_score:.1f}"
                elif anomaly_score > 0:
                    anomaly_color = 'dim'
                    anomaly_display = f"{anomaly_score:.1f}"
                else:
                    anomaly_color = 'dim'
                    anomaly_display = '-'

                # Score spread - shows consensus disagreement
                score_spread = float(conn.get('score_spread', 0) or 0)
                if score_spread >= 0.5:
                    spread_color = 'bold yellow'
                    spread_display = f"↔{score_spread:.1f}"  # High disagreement
                elif score_spread >= 0.3:
                    spread_color = 'yellow'
                    spread_display = f"~{score_spread:.1f}"
                elif score_spread > 0:
                    spread_color = 'green'
                    spread_display = f"✓{score_spread:.1f}"
                else:
                    spread_color = 'dim'
                    spread_display = '-'

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
                    f"[{type_color}]{org_type:>7}[/]",
                    f"[{threat_color}]{threat_indicator}[/]",
                    f"[{threat_color}]{threat:.2f}[/]",
                    f"[{anomaly_color}]{anomaly_display}[/]",
                    f"[{spread_color}]{spread_display}[/]",
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


class NetworkDevicePanel(Static):
    """
    Unified panel for both network and device modes.
    Shows discovered devices with MAC addresses, IPs, vendors, and connection flows.

    In network mode: Shows destination flows per device
    In device mode: Shows device inventory with connection counts
    """

    DEFAULT_CSS = """
    NetworkDevicePanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: auto;
    }
    """

    topology_data = reactive(dict)
    devices = reactive(list)
    network_info = reactive(dict)

    def __init__(self, mode: str = "device", **kwargs):
        super().__init__(**kwargs)
        self.mode = mode
        self.flows = {}
        self.topology_data = {}
        self.devices = []
        self.network_info = {
            'ip_range': 'detecting...',
        }

    def watch_topology_data(self, new_data: dict) -> None:
        """Update topology when data changes (network mode)"""
        self.flows = new_data
        self._update_network_info()
        self.refresh()

    def watch_devices(self, new_devices: list) -> None:
        """Update devices when data changes (device mode)"""
        self.devices = new_devices
        self._update_network_info_from_devices()
        self.refresh()

    def _update_network_info(self):
        """Extract network range from observed IPs in flows"""
        if not self.flows:
            return

        src_ips = set()
        for src_mac, flow_data in self.flows.items():
            if 'src_ip' in flow_data:
                src_ips.add(flow_data['src_ip'])

        self._detect_network_range(src_ips)

    def _update_network_info_from_devices(self):
        """Extract network range from device IPs"""
        if not self.devices:
            return

        src_ips = set()
        for device in self.devices:
            ip_addresses = device.get('ip_addresses', [])
            for ip in ip_addresses:
                src_ips.add(ip)

        self._detect_network_range(src_ips)

    def _detect_network_range(self, src_ips: set):
        """Determine network range from a set of IPs"""
        for ip in src_ips:
            if ip.startswith('192.168.'):
                parts = ip.split('.')
                self.network_info['ip_range'] = f"192.168.{parts[2]}.0/24"
                return
            elif ip.startswith('10.'):
                parts = ip.split('.')
                self.network_info['ip_range'] = f"10.{parts[1]}.{parts[2]}.0/24"
                return
            elif ip.startswith('172.'):
                parts = ip.split('.')
                second = int(parts[1])
                if 16 <= second <= 31:
                    self.network_info['ip_range'] = f"172.{parts[1]}.{parts[2]}.0/24"
                    return

    def render(self):
        """Render unified device panel based on mode"""
        # Check if we have data
        has_flow_data = bool(self.flows)
        has_device_data = bool(self.devices)

        if not has_flow_data and not has_device_data:
            return Panel(
                "[dim]Scanning network...[/dim]\n\n"
                "[cyan]Waiting for network traffic...[/cyan]\n"
                "[dim]Devices will appear with:\n"
                "- MAC address\n"
                "- IP address\n"
                "- Connection flows[/dim]",
                title="[bold cyan]NETWORK DEVICES[/bold cyan]",
                border_style="cyan"
            )

        lines = []

        # Header
        lines.append("[bold cyan]┌─────────────────────────────────────────┐[/bold cyan]")
        lines.append("[bold cyan]│           NETWORK DEVICES               │[/bold cyan]")
        lines.append("[bold cyan]└─────────────────────────────────────────┘[/bold cyan]")

        # Show monitored network range
        ip_range = self.network_info.get('ip_range', 'detecting...')
        lines.append(f"[bold]Network:[/bold] [cyan]{ip_range}[/cyan]")
        lines.append("")

        # Render based on available data
        if has_flow_data:
            self._render_with_flows(lines)
        elif has_device_data:
            self._render_devices_only(lines)

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold cyan]NETWORK DEVICES[/bold cyan]",
            border_style="cyan"
        )

    def _render_with_flows(self, lines: list):
        """Render devices with their destination flows"""
        device_count = len(self.flows)
        total_flows = sum(len(f.get('destinations', {})) for f in self.flows.values())

        lines.append(f"[dim]Devices: {device_count} | Flows: {total_flows}[/dim]")
        lines.append("")

        device_list = list(self.flows.items())[:5]  # Top 5 devices

        for idx, (src_mac, flow_data) in enumerate(device_list):
            vendor = (flow_data.get('device_vendor') or 'Unknown')[:12]
            src_ip = flow_data.get('src_ip', '')
            threat_score = float(flow_data.get('threat_avg', 0) or 0)

            is_last = idx == len(device_list) - 1
            prefix = "[cyan]└[/cyan]" if is_last else "[cyan]├[/cyan]"

            # Threat indicator
            threat_icon, threat_color = self._get_threat_style(threat_score)

            # Device line
            lines.append(f"{prefix} {threat_icon} [{threat_color}]{vendor:12s}[/{threat_color}]")
            lines.append(f"[dim]│  MAC: {src_mac}[/dim]")
            if src_ip:
                lines.append(f"[dim]│  IP:  [/dim][cyan]{src_ip}[/cyan]")

            # Show top 2 destination flows
            destinations = sorted(
                flow_data.get('destinations', {}).items(),
                key=lambda x: float(x[1].get('threat', 0) or 0),
                reverse=True
            )[:2]

            for dest_idx, (dest_key, data) in enumerate(destinations):
                threat = float(data.get('threat', 0) or 0)
                count = data.get('count', 0)
                protocol = data.get('protocol', 'TCP')

                # Parse IP:port
                if ':' in dest_key:
                    parts = dest_key.rsplit(':', 1)
                    dst_ip = parts[0][:15]
                    dst_port = parts[1]
                else:
                    dst_ip = dest_key[:15]
                    dst_port = '?'

                # Protocol indicator
                proto = "U" if protocol == "UDP" else "T"
                proto_color = "magenta" if protocol == "UDP" else "cyan"

                _, dest_color = self._get_threat_style(threat)

                is_dest_last = dest_idx == len(destinations) - 1
                flow_prefix = "│  └─" if is_dest_last else "│  ├─"

                lines.append(f"[dim]{flow_prefix}[/dim] [{proto_color}]{proto}[/{proto_color}] [{dest_color}]{dst_ip}:{dst_port}[/{dest_color}] x{count}")

        lines.append("")
        lines.append("[dim]T=TCP U=UDP | !=Crit ~=Med .=Low[/dim]")

    def _render_devices_only(self, lines: list):
        """Render device inventory without flow details"""
        total_flows = sum(d.get('connection_count', 0) for d in self.devices)
        high_risk = len([d for d in self.devices if float(d.get('threat_score', 0) or 0) >= 0.5])

        lines.append(f"[dim]Devices: {len(self.devices)} | Flows: {total_flows} | High Risk: {high_risk}[/dim]")
        lines.append("")

        sorted_devices = sorted(
            self.devices,
            key=lambda d: float(d.get('threat_score', 0) or 0),
            reverse=True
        )[:6]

        for idx, device in enumerate(sorted_devices):
            mac = device.get('mac', 'Unknown')
            vendor = (device.get('vendor') or 'Unknown')[:12]
            threat = float(device.get('threat_score', 0) or 0)
            conn_count = device.get('connection_count', 0)

            ip_addresses = device.get('ip_addresses', [])
            primary_ip = ip_addresses[0] if ip_addresses else ''

            is_last = idx == len(sorted_devices) - 1
            prefix = "[cyan]└[/cyan]" if is_last else "[cyan]├[/cyan]"

            threat_icon, threat_color = self._get_threat_style(threat)

            lines.append(f"{prefix} {threat_icon} [{threat_color}]{vendor:12s}[/{threat_color}] {conn_count} flows")
            lines.append(f"[dim]│  MAC: {mac}[/dim]")
            if primary_ip:
                lines.append(f"[dim]│  IP:  [/dim][cyan]{primary_ip}[/cyan]")

        lines.append("")
        lines.append("[dim]!=Crit ~=Med .=Low threat[/dim]")

    def _get_threat_style(self, threat_score: float) -> tuple:
        """Return (icon, color) based on threat score"""
        if threat_score >= 0.7:
            return "[bold red]![/bold red]", "bold red"
        elif threat_score >= 0.5:
            return "[bold yellow]![/bold yellow]", "bold yellow"
        elif threat_score >= 0.3:
            return "[yellow]~[/yellow]", "yellow"
        else:
            return "[green].[/green]", "green"


# Keep aliases for backwards compatibility
NetworkTopologyPanel = NetworkDevicePanel
DeviceDiscoveryPanel = NetworkDevicePanel


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

        # Individual Scorer Breakdown
        lines.append("[bold cyan]═══ SCORER BREAKDOWN ═══[/bold cyan]")

        # Get individual scores
        score_statistical = conn.get('score_statistical')
        score_rule_based = conn.get('score_rule_based')
        score_ml_based = conn.get('score_ml_based')
        score_organization = conn.get('score_organization')
        anomaly_score = conn.get('anomaly_score')
        score_spread = conn.get('score_spread')

        def format_score(name: str, score, width: int = 10) -> str:
            """Format a score with visual bar"""
            if score is None:
                return f"  [cyan]{name:16s}[/cyan] [dim]N/A[/dim]"
            val = float(score)
            bar_len = int(val * width)
            if val >= 0.7:
                color = 'red'
            elif val >= 0.5:
                color = 'yellow'
            else:
                color = 'green'
            bar = f"[{color}]{'█' * bar_len}[/{color}][dim]{'░' * (width - bar_len)}[/dim]"
            return f"  [cyan]{name:16s}[/cyan] {bar} [{color}]{val:.2f}[/{color}]"

        lines.append(format_score("Statistical", score_statistical))
        lines.append(format_score("Rule-based", score_rule_based))
        lines.append(format_score("ML-based", score_ml_based))
        lines.append(format_score("Organization", score_organization))
        lines.append(format_score("Anomaly", anomaly_score))

        # Score spread with interpretation
        if score_spread is not None:
            spread = float(score_spread)
            if spread >= 0.5:
                spread_desc = "[bold yellow]↔ High disagreement[/bold yellow]"
            elif spread >= 0.3:
                spread_desc = "[yellow]~ Moderate spread[/yellow]"
            else:
                spread_desc = "[green]✓ Strong consensus[/green]"
            lines.append(f"  [cyan]Score Spread:[/cyan]    {spread:.2f} {spread_desc}")
        lines.append("")

        lines.append("[dim]Press ESC or click outside to close[/dim]")

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold cyan]🔍 CONNECTION DETAILS[/bold cyan]",
            border_style="cyan"
        )


class OrganizationIntelPanel(Static):
    """
    Organization Intelligence Panel with type distribution and trends.
    Shows breakdown of org types with trend indicators (↑↓→).
    """

    DEFAULT_CSS = """
    OrganizationIntelPanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: auto;
    }
    """

    org_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.org_data = {
            'type_counts': {},
            'type_threats': {},
            'previous_counts': {},
            'high_risk_orgs': [],
        }

    def watch_org_data(self, new_data: dict) -> None:
        """Update when data changes"""
        self.org_data = new_data
        self.refresh()

    def render(self):
        """Render organization intelligence with trend indicators"""
        type_counts = self.org_data.get('type_counts', {})
        type_threats = self.org_data.get('type_threats', {})
        previous_counts = self.org_data.get('previous_counts', {})
        high_risk_orgs = self.org_data.get('high_risk_orgs', [])

        if not type_counts:
            return Panel(
                "[dim]Collecting organization data...[/dim]\n\n"
                "[cyan]Organization types will appear with:\n"
                "- Connection counts\n"
                "- Threat averages\n"
                "- Trend indicators (↑↓→)[/cyan]",
                title="[bold magenta]ORG INTEL[/bold magenta]",
                border_style="magenta"
            )

        lines = []
        lines.append("[bold magenta]┌─────────────────────────────────────┐[/bold magenta]")
        lines.append("[bold magenta]│      ORGANIZATION INTELLIGENCE      │[/bold magenta]")
        lines.append("[bold magenta]└─────────────────────────────────────┘[/bold magenta]")
        lines.append("")

        # Type distribution with trends
        lines.append("[bold]📊 TYPE DISTRIBUTION:[/bold]")
        lines.append("")

        # Color mapping for org types
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

        # Sort by count descending
        total_count = sum(type_counts.values())
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)

        for org_type, count in sorted_types[:8]:
            color = type_colors.get(org_type, 'white')
            avg_threat = type_threats.get(org_type, 0.0)
            prev_count = previous_counts.get(org_type, count)

            # Calculate trend
            if count > prev_count * 1.2:
                trend = "[bold green]↑[/bold green]"  # Rising
            elif count < prev_count * 0.8:
                trend = "[bold red]↓[/bold red]"    # Falling
            else:
                trend = "[dim]→[/dim]"              # Stable

            # Threat indicator
            if avg_threat >= 0.7:
                threat_icon = "[bold red]●[/bold red]"
            elif avg_threat >= 0.5:
                threat_icon = "[yellow]●[/yellow]"
            else:
                threat_icon = "[green]●[/green]"

            # Percentage bar
            pct = (count / total_count * 100) if total_count > 0 else 0
            bar_len = int(pct / 10)
            bar = f"[{color}]{'▓' * bar_len}{'░' * (10 - bar_len)}[/{color}]"

            lines.append(f"  {trend} [{color}]{org_type:10s}[/{color}] {bar} {count:3d} {threat_icon}")

        lines.append("")
        lines.append(f"[dim]Total: {total_count} connections[/dim]")
        lines.append("")

        # High risk organizations
        if high_risk_orgs:
            lines.append("[bold red]⚠ HIGH RISK ORGANIZATIONS:[/bold red]")
            for org_info in high_risk_orgs[:3]:
                org_name = (org_info.get('name') or 'Unknown')[:18]
                org_type = org_info.get('type', 'unknown')
                threat = float(org_info.get('avg_threat', 0) or 0)
                count = org_info.get('count', 0)

                color = type_colors.get(org_type, 'white')
                lines.append(f"  [bold red]![/bold red] [{color}]{org_name:18s}[/{color}] {threat:.2f} (x{count})")

        lines.append("")
        lines.append("[dim]●=High ●=Med ●=Low threat[/dim]")

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold magenta]ORG INTEL[/bold magenta]",
            border_style="magenta"
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
        ("o", "toggle_org_intel", "Toggle Org Intel Panel"),
        ("g", "toggle_globe", "Pause/Resume Globe Animation"),
        ("i", "cycle_intel_map", "Cycle Intel Map Type"),
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

    #org_intel_panel {
        width: 50%;
        padding: 1 0 0 1;
        display: none;
    }

    #org_intel_panel.visible {
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

    # Activity spinners for live feel
    SPINNERS = ['◐', '◓', '◑', '◒']
    DATA_FLOW = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']

    def __init__(self, db_path: str = "database/cobaltgraph.db", mode: str = "device"):
        """Initialize enhanced dashboard with mode"""
        super().__init__(db_path=db_path, mode=mode)
        self.title = f"CobaltGraph - {mode.upper()} Mode"
        self.sub_title = "Loading..."
        self._spinner_frame = 0

        # Panels
        self.threat_posture_panel = None
        self.globe_panel = None
        self.connection_table = None
        self.mode_specific_panel = None
        self.anomaly_panel = None
        self.org_intel_panel = None
        self.detail_modal = None
        self.modal_backdrop = None

        # Track previous org counts for trend calculation
        self._previous_org_counts = {}

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

                # Unified device panel (adapts based on available data)
                self.mode_specific_panel = NetworkDevicePanel(mode=self.mode, id="bottom_right")
                yield self.mode_specific_panel

                # Anomaly panel (hidden by default, toggle with 'a')
                self.anomaly_panel = AnomalyAlertPanel(id="anomaly_panel")
                yield self.anomaly_panel

                # Organization Intel panel (hidden by default, toggle with 'o')
                self.org_intel_panel = OrganizationIntelPanel(id="org_intel_panel")
                yield self.org_intel_panel

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
        # Import heartbeat singleton for component health tracking
        from src.utils.heartbeat import heartbeat
        import socket
        import os
        import pwd

        # Get hostname and current user for display
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"

        try:
            username = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            try:
                username = os.getlogin()
            except Exception:
                username = os.environ.get("USER", "unknown")

        self._hostname = hostname
        self._username = username
        self.title = f"CobaltGraph Enhanced - {self.mode.upper()} Mode │ {username}@{hostname}"

        if self.data_manager.connect():
            self.is_connected = True
            self.set_interval(2.0, self._refresh_data)
            self.set_interval(0.2, self._update_display)  # 200ms for animations (5 FPS - sufficient)
            self.set_interval(1.0, self._update_heartbeat)  # Heartbeat updates every 1s (reduced)
            self._refresh_data()

            # Send initial heartbeats for all operational components
            heartbeat.beat("dashboard", "UI active")
            heartbeat.beat("database", "DB connected")
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

            # Update unified device panel with both topology and device data
            if self.mode_specific_panel:
                devices = self.data_manager.get_devices() if hasattr(self.data_manager, 'get_devices') else []
                # Always provide topology data (shows flows) and device data
                self.mode_specific_panel.topology_data = self._build_topology(connections, devices)
                self.mode_specific_panel.devices = devices

            # Fetch and update anomalies
            if self.anomaly_panel:
                anomalies = self.data_manager.get_anomalies(limit=10) if hasattr(self.data_manager, 'get_anomalies') else []

                # If no anomalies from events table, generate from high-threat connections
                if not anomalies and high_threat_count > 0:
                    anomalies = self._generate_anomalies_from_threats(connections)

                self.anomaly_panel.anomalies = anomalies

            # Update organization intel panel
            if self.org_intel_panel:
                org_intel_data = self._calculate_org_intel(connections)
                self.org_intel_panel.org_data = org_intel_data

            # Update stats with activity spinner
            stats = self.data_manager.get_stats()
            self._spinner_frame = (self._spinner_frame + 1) % len(self.DATA_FLOW)
            spinner = self.DATA_FLOW[self._spinner_frame]
            self.sub_title = f"{spinner} {datetime.now().strftime('%H:%M:%S')} │ ▶ {stats.get('total', 0)} │ ⚡ {current_threat:.2f}"

        except Exception as e:
            logger.error(f"Refresh failed: {e}")
            self.sub_title = f"Error: {str(e)[:30]}"

    def _update_display(self) -> None:
        """Quick display updates (animations, etc) - optimized for 200ms intervals"""
        # Update globe animation (single refresh per cycle)
        if self.globe_panel:
            try:
                globe_component = (
                    self.globe_panel.world_map or
                    self.globe_panel.enhanced_globe or
                    self.globe_panel.simple_globe
                )
                if globe_component:
                    globe_component.update(0.2)  # Match interval timing
                    self.globe_panel.refresh()
            except Exception as e:
                logger.debug(f"Globe update failed: {e}")

        # Pulse the threat indicator for "breathing" effect
        if self.threat_posture_panel:
            try:
                self.threat_posture_panel.pulse()
            except Exception:
                pass

    def _update_heartbeat(self) -> None:
        """
        Update component heartbeats every 1s (reduced from 0.5s for performance).
        Sends heartbeats for all operational components to keep them marked as ACTIVE.
        """
        from src.utils.heartbeat import heartbeat

        # Always send dashboard heartbeat - we're running
        heartbeat.beat("dashboard", "UI active")

        # Send database heartbeat if connected
        if self.data_manager.is_connected:
            heartbeat.beat("database", "DB connected")

        # Send pipeline heartbeat if we have recent connections
        if self.recent_connections:
            heartbeat.beat("pipeline", "Data flowing")

            # Check connection data for evidence of working services
            for conn in list(self.recent_connections)[:10]:
                # GeoIP heartbeat: if we have geo data, the service is working
                if conn.get('dst_lat') or conn.get('dst_lon') or conn.get('dst_country'):
                    heartbeat.beat("geo_engine", "GeoIP data flowing")
                    break

            for conn in list(self.recent_connections)[:10]:
                # ASN heartbeat: if we have ASN data, the service is working
                if conn.get('dst_asn') or conn.get('dst_org'):
                    heartbeat.beat("asn_lookup", "ASN data flowing")
                    break

            for conn in list(self.recent_connections)[:10]:
                # Consensus heartbeat: if we have threat scores, consensus is working
                if conn.get('threat_score') is not None:
                    heartbeat.beat("consensus", "Threat scoring active")
                    break

            # Check if capture is active based on recent timestamps
            if self.recent_connections:
                latest = list(self.recent_connections)[0]
                latest_ts = latest.get('timestamp', 0)
                if latest_ts and (time.time() - float(latest_ts)) < 60:
                    heartbeat.beat("capture", "Receiving connections")

            # Reputation service heartbeat - check if reputation data exists
            for conn in list(self.recent_connections)[:10]:
                # If we have detailed org_type data, reputation likely contributed
                if conn.get('dst_org_type') and conn.get('dst_org_type') not in ('unknown', None):
                    heartbeat.beat("reputation", "Reputation data active")
                    break

        # Update subtitle with component status
        online, total = heartbeat.get_online_count()
        db_status = "Connected" if self.data_manager.is_connected else "Offline"
        self.sub_title = f"Last update: {datetime.now().strftime('%H:%M:%S')} | Components: {online}/{total} online | DB: {db_status}"

    def _calculate_org_intel(self, connections: List[Dict]) -> Dict:
        """Calculate organization intelligence data with trends"""
        type_counts = defaultdict(int)
        type_threats = defaultdict(list)
        org_details = defaultdict(lambda: {'count': 0, 'threats': [], 'type': 'unknown'})

        for conn in connections:
            org_type = (conn.get('dst_org_type') or 'unknown').lower()
            org_name = conn.get('dst_org') or 'Unknown'
            threat = float(conn.get('threat_score', 0) or 0)

            type_counts[org_type] += 1
            type_threats[org_type].append(threat)

            org_details[org_name]['count'] += 1
            org_details[org_name]['threats'].append(threat)
            org_details[org_name]['type'] = org_type

        # Calculate average threats per type
        type_avg_threats = {}
        for org_type, threats in type_threats.items():
            type_avg_threats[org_type] = sum(threats) / len(threats) if threats else 0.0

        # Find high risk organizations
        high_risk_orgs = []
        for org_name, data in org_details.items():
            avg_threat = sum(data['threats']) / len(data['threats']) if data['threats'] else 0.0
            if avg_threat >= 0.5 or data['count'] >= 5:
                high_risk_orgs.append({
                    'name': org_name,
                    'type': data['type'],
                    'avg_threat': avg_threat,
                    'count': data['count'],
                })

        # Sort by threat then count
        high_risk_orgs.sort(key=lambda x: (x['avg_threat'], x['count']), reverse=True)

        # Build result with previous counts for trend calculation
        result = {
            'type_counts': dict(type_counts),
            'type_threats': type_avg_threats,
            'previous_counts': self._previous_org_counts.copy(),
            'high_risk_orgs': high_risk_orgs[:5],
        }

        # Update previous counts for next comparison
        self._previous_org_counts = dict(type_counts)

        return result

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
        """Build device→destination topology with full flow details"""
        topology = defaultdict(lambda: {
            'device_vendor': 'Unknown',
            'src_ip': '',
            'threat_avg': 0.0,
            'destinations': defaultdict(lambda: {
                'count': 0,
                'threat': 0.0,
                'org': 'Unknown',
                'protocol': 'TCP'
            })
        })

        device_map = {d.get('mac', ''): d for d in devices}

        # Track threat scores per device for averaging
        device_threats = defaultdict(list)

        for conn in connections:
            src_mac = conn.get('src_mac', 'Unknown')
            src_ip = conn.get('src_ip', '')
            dst_ip = conn.get('dst_ip', 'Unknown')
            dst_port = conn.get('dst_port', '-')
            protocol = conn.get('protocol', 'TCP')
            threat = float(conn.get('threat_score', 0) or 0)
            org = (conn.get('dst_org') or 'Unknown')[:15]

            if src_mac in device_map:
                topology[src_mac]['device_vendor'] = device_map[src_mac].get('vendor', 'Unknown')

            # Store source IP for network range detection
            if src_ip:
                topology[src_mac]['src_ip'] = src_ip

            key = f"{dst_ip}:{dst_port}"
            topology[src_mac]['destinations'][key]['count'] += 1
            topology[src_mac]['destinations'][key]['threat'] = max(
                topology[src_mac]['destinations'][key]['threat'], threat
            )
            topology[src_mac]['destinations'][key]['org'] = org
            topology[src_mac]['destinations'][key]['protocol'] = protocol

            # Track for averaging
            device_threats[src_mac].append(threat)

        # Calculate average threat per device
        for src_mac, threats in device_threats.items():
            if threats:
                topology[src_mac]['threat_avg'] = sum(threats) / len(threats)

        return dict(topology)

    def action_quit(self) -> None:
        """Quit application"""
        self.exit()

    def action_help(self) -> None:
        """Show keybindings help in subtitle"""
        help_text = "Keys: Q=Quit | R=Refresh | A=Anomalies | O=OrgIntel | M=Devices | G=Globe | ?=Help | ESC=Close"
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
        """Toggle Anomaly Alerts panel visibility"""
        if not self.anomaly_panel:
            return

        # Hide all bottom-right panels first
        self._hide_all_bottom_right_panels()

        # Show anomaly panel
        self.anomaly_panel.add_class("visible")
        self.anomaly_panel.styles.display = "block"
        self.sub_title = "Showing Anomaly Alerts (press 'm' for devices, 'o' for org intel)"

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

    def action_cycle_intel_map(self) -> None:
        """Cycle through intel map visualization types (flat/rotating/simple)"""
        if self.globe_panel and hasattr(self.globe_panel, 'cycle_map_type'):
            new_type = self.globe_panel.cycle_map_type()
            map_name = self.globe_panel.current_map_name
            self.sub_title = f"Intel Map: {map_name} (press 'i' to cycle)"

    def action_toggle_org_intel(self) -> None:
        """Toggle Organization Intel panel visibility"""
        if not self.org_intel_panel:
            return

        # Hide all bottom-right panels first
        self._hide_all_bottom_right_panels()

        # Show org intel panel
        self.org_intel_panel.add_class("visible")
        self.org_intel_panel.styles.display = "block"
        self.sub_title = "Showing Organization Intel (press 'm' for devices, 'a' for anomalies)"

    def action_toggle_mode_panel(self) -> None:
        """Toggle to mode-specific panel (Network Devices)"""
        if not self.mode_specific_panel:
            return

        # Hide all bottom-right panels first
        self._hide_all_bottom_right_panels()

        # Show mode panel
        self.mode_specific_panel.styles.display = "block"
        panel_name = "Network Topology" if self.mode == "network" else "Device Discovery"
        self.sub_title = f"Showing {panel_name} (press 'a' for anomalies, 'o' for org intel)"

    def _hide_all_bottom_right_panels(self) -> None:
        """Hide all toggleable bottom-right panels"""
        if self.mode_specific_panel:
            self.mode_specific_panel.styles.display = "none"
        if self.anomaly_panel:
            self.anomaly_panel.remove_class("visible")
            self.anomaly_panel.styles.display = "none"
        if self.org_intel_panel:
            self.org_intel_panel.remove_class("visible")
            self.org_intel_panel.styles.display = "none"


if __name__ == '__main__':
    import sys

    mode = "device"
    db_path = "database/cobaltgraph.db"

    if len(sys.argv) > 1:
        mode = sys.argv[1]

    dashboard = CobaltGraphDashboardEnhanced(db_path=db_path, mode=mode)
    dashboard.run()
