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


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/local (RFC 1918 + loopback)"""
    if not ip or ip == 'local':
        return True
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        except (IndexError, ValueError):
            pass
    if ip.startswith("127."):
        return True
    return False


def get_direction(src_ip: str, dst_ip: str) -> tuple:
    """
    Determine packet/connection direction based on source and destination IPs.

    Returns:
        tuple: (direction_label, direction_color, direction_symbol)
        - "OUT" for outgoing (local -> external)
        - "IN" for incoming (external -> local)
        - "INT" for internal (local -> local)
        - "EXT" for external (external -> external, passthrough)
    """
    src_is_private = _is_private_ip(src_ip)
    dst_is_private = _is_private_ip(dst_ip)

    if src_is_private and not dst_is_private:
        return ("OUT", "cyan", "→")  # Outgoing
    elif not src_is_private and dst_is_private:
        return ("IN", "magenta", "←")  # Incoming
    elif src_is_private and dst_is_private:
        return ("INT", "dim", "↔")  # Internal
    else:
        return ("EXT", "yellow", "⇄")  # External/passthrough


try:
    from src.ui.unified_dashboard import UnifiedDashboard, DataManager, VisualizationManager
except ImportError:
    from unified_dashboard import UnifiedDashboard, DataManager, VisualizationManager

# Import consolidated maps module
try:
    from src.ui.maps import FlatWorldMap, RotatingGlobe, SimpleGlobe, is_unknown_location, int_to_roman
    EnhancedGlobe = RotatingGlobe  # Alias for compatibility
except ImportError:
    try:
        from .maps import FlatWorldMap, RotatingGlobe, SimpleGlobe, is_unknown_location, int_to_roman
        EnhancedGlobe = RotatingGlobe
    except ImportError:
        # Fallback to legacy imports if new module not available
        FlatWorldMap = None
        RotatingGlobe = None
        EnhancedGlobe = None
        SimpleGlobe = None
        is_unknown_location = lambda lat, lon: lat == 0.0 and lon == 0.0
        def int_to_roman(num):
            if num <= 0 or num >= 4000:
                return str(num)
            val = [1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1]
            syms = ['M', 'CM', 'D', 'CD', 'C', 'XC', 'L', 'XL', 'X', 'IX', 'V', 'IV', 'I']
            result = ''
            for i, v in enumerate(val):
                while num >= v:
                    result += syms[i]
                    num -= v
            return result


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
    Top-left (50%): Compact SOC Operations Summary

    Professional blue-team interface providing quick threat overview
    with operational metrics and flagged connection alerts.

    Design: Minimal professional aesthetic optimized for quick scanning.
    """

    DEFAULT_CSS = """
    ThreatPostureQuickPanel {
        height: 100%;
        width: 100%;
        padding: 0 1;
        overflow-y: auto;
    }
    """

    threat_data = reactive(dict)

    # Subtle activity indicator
    ACTIVITY_CHARS = ['·', '∙', '•', '∙']

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._activity_frame = 0
        self.threat_data = {
            'current_threat': 0.0,
            'baseline_threat': 0.0,
            'active_threats': 0,
            'monitored_ips': 0,
            'high_threat_count': 0,
            'top_threats': [],
            # Extended SOC metrics
            'total_connections': 0,
            'flagged_connections': 0,
            'high_uncertainty': 0,
            'consensus_agreement': 1.0,
            'inbound_count': 0,
            'outbound_count': 0,
            'protocols': {},
        }

    def watch_threat_data(self, new_data: dict) -> None:
        """Trigger re-render when threat data changes"""
        self._activity_frame = (self._activity_frame + 1) % len(self.ACTIVITY_CHARS)
        self.refresh()

    def pulse(self) -> None:
        """Advance activity animation frame"""
        self._activity_frame = (self._activity_frame + 1) % len(self.ACTIVITY_CHARS)
        self.refresh()

    def _get_threat_indicator(self, score: float) -> tuple:
        """Return (indicator, color, label) for threat level"""
        if score >= 0.7:
            return ("▲", "bold red", "CRIT")
        elif score >= 0.5:
            return ("▲", "yellow", "HIGH")
        elif score >= 0.3:
            return ("─", "dim yellow", "MED")
        else:
            return ("▼", "dim green", "LOW")

    def render(self):
        """Render compact SOC operations summary"""
        # Extract metrics
        current = float(self.threat_data.get('current_threat', 0) or 0)
        baseline = float(self.threat_data.get('baseline_threat', 0) or 0)
        active = int(self.threat_data.get('active_threats', 0) or 0)
        ips = int(self.threat_data.get('monitored_ips', 0) or 0)
        total_conn = int(self.threat_data.get('total_connections', 0) or 0)
        flagged = int(self.threat_data.get('flagged_connections', 0) or 0)
        uncertain = int(self.threat_data.get('high_uncertainty', 0) or 0)
        agreement = float(self.threat_data.get('consensus_agreement', 1.0) or 1.0)
        inbound = int(self.threat_data.get('inbound_count', 0) or 0)
        outbound = int(self.threat_data.get('outbound_count', 0) or 0)
        top_threats = self.threat_data.get('top_threats', [])

        # Activity indicator
        activity = self.ACTIVITY_CHARS[self._activity_frame]

        # Threat indicator
        indicator, threat_color, threat_label = self._get_threat_indicator(current)

        lines = []

        # ═══ Compact threat bar ═══
        delta = current - baseline
        delta_str = f"+{delta:.2f}" if delta >= 0 else f"{delta:.2f}"
        delta_color = "red" if delta > 0.1 else ("green" if delta < -0.1 else "dim")

        threat_bar_width = 16
        filled = int(current * threat_bar_width)
        bar = f"[{threat_color}]{'█' * filled}[/{threat_color}][dim]{'░' * (threat_bar_width - filled)}[/dim]"

        lines.append(f"[dim]{activity}[/dim] [{threat_color}]{indicator}[/{threat_color}] {bar} [{threat_color}]{current:.2f}[/{threat_color}] [{delta_color}]({delta_str})[/{delta_color}]")
        lines.append(f"[dim]   {threat_label} | baseline {baseline:.2f}[/dim]")

        # ═══ Quick metrics ═══
        lines.append("")
        flag_color = "red" if flagged > 5 else ("yellow" if flagged > 0 else "dim")
        lines.append(f"[dim]conn[/dim] {total_conn:>4}  [dim]flag[/dim] [{flag_color}]{flagged:>3}[/{flag_color}]  [dim]crit[/dim] [red]{active:>2}[/red]")
        lines.append(f"[dim]in[/dim]   {inbound:>4}  [dim]out[/dim]  {outbound:>3}  [dim]ips[/dim]  {ips:>3}")

        # ═══ Consensus status ═══
        agree_pct = int(agreement * 100)
        agree_color = "green" if agree_pct >= 80 else ("yellow" if agree_pct >= 60 else "red")
        lines.append(f"[dim]consensus[/dim] [{agree_color}]{agree_pct}%[/{agree_color}]  [dim]uncertain[/dim] {uncertain}")

        # ═══ Top flagged (compact) ═══
        lines.append("")
        lines.append("[dim]FLAGGED[/dim]")

        if top_threats:
            for conn in top_threats[:3]:
                threat_score = float(conn.get('threat_score', 0) or 0)
                dst_ip = conn.get('dst_ip', '?.?.?.?')
                dst_port = conn.get('dst_port', 0)

                t_ind, t_col, _ = self._get_threat_indicator(threat_score)
                ip_short = dst_ip[-12:] if len(dst_ip) > 12 else dst_ip

                lines.append(f"  [{t_col}]{t_ind}[/{t_col}] {ip_short}:{dst_port} [{t_col}]{threat_score:.2f}[/{t_col}]")
        else:
            lines.append("  [dim]none[/dim]")

        content = "\n".join(lines)

        return Panel(
            content,
            title="[bold bright_white]SOC SUMMARY[/bold bright_white]",
            border_style="dim cyan",
            padding=(0, 1)
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
        self._unknown_ips: set = set()  # Track IPs with unknown (0,0) locations
        self._last_size = (0, 0)  # Track size for resize detection

        # Maps will be initialized on first resize when we know the actual panel size
        # Don't initialize with fixed dimensions here

    def _init_all_maps(self, width: int = 80, height: int = 20) -> None:
        """Initialize all available map implementations with specified dimensions"""
        # Initialize flat world map
        if FlatWorldMap:
            try:
                self.world_map = FlatWorldMap(width=width, height=height)
                logger.debug(f"Initialized FlatWorldMap at {width}x{height}")
            except Exception as e:
                logger.warning(f"Failed to initialize FlatWorldMap: {e}")
                self.world_map = None

        # Initialize enhanced globe (rotating)
        if EnhancedGlobe:
            try:
                self.enhanced_globe = EnhancedGlobe(width=width, height=height)
                logger.debug(f"Initialized EnhancedGlobe at {width}x{height}")
            except Exception as e:
                logger.warning(f"Failed to initialize EnhancedGlobe: {e}")
                self.enhanced_globe = None

        # Initialize simple globe
        if SimpleGlobe:
            try:
                self.simple_globe = SimpleGlobe(width=width, height=height)
                logger.debug(f"Initialized SimpleGlobe at {width}x{height}")
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
            self._unknown_ips.clear()

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

                        # Filter out (0,0) unknown locations - track separately
                        if dst_lat == 0.0 and dst_lon == 0.0:
                            self._unknown_ips.add(ip)
                            continue

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

                # Update unknown count on flat world map
                if hasattr(self.world_map, 'set_unknown_count'):
                    self.world_map.set_unknown_count(len(self._unknown_ips))

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
                        src_lat = float(conn.get('src_lat', 0) or 0)
                        src_lon = float(conn.get('src_lon', 0) or 0)

                        # Filter out (0,0) unknown locations
                        if dst_lat == 0.0 and dst_lon == 0.0:
                            self._unknown_ips.add(ip)
                            continue

                        self.enhanced_globe.add_connection(
                            src_lat, src_lon, dst_lat, dst_lon,
                            threat, org_type, ip
                        )
                    except Exception as e:
                        logger.debug(f"Failed to add to enhanced globe: {e}")

                # Update unknown count on enhanced globe
                if hasattr(self.enhanced_globe, 'set_unknown_count'):
                    self.enhanced_globe.set_unknown_count(len(self._unknown_ips))

            # 3. Simple Globe (fallback)
            if self.simple_globe:
                self.simple_globe.clear_threats()
                for conn in connections[-20:]:
                    try:
                        threat = float(conn.get('threat_score', 0) or 0)
                        org_type = (conn.get('dst_org_type') or 'unknown').lower()
                        ip = conn.get('dst_ip', 'Unknown')
                        dst_lat = float(conn.get('dst_lat', 0) or 0)
                        dst_lon = float(conn.get('dst_lon', 0) or 0)

                        # Filter out (0,0) unknown locations
                        if dst_lat == 0.0 and dst_lon == 0.0:
                            self._unknown_ips.add(ip)
                            continue

                        self.simple_globe.add_threat(dst_lat, dst_lon, ip, threat, org_type)
                    except Exception as e:
                        logger.debug(f"Failed to add to simple globe: {e}")

                # Update unknown count on simple globe
                if hasattr(self.simple_globe, 'set_unknown_count'):
                    self.simple_globe.set_unknown_count(len(self._unknown_ips))

            # Trigger animation update
            self.animation_frame += 1
            self.last_update_time = time.time()
        except Exception as e:
            logger.warning(f"Globe data watch failed: {e}")

    def watch_animation_frame(self, frame: int) -> None:
        """Animation frame update trigger"""
        self.refresh()

    def on_resize(self, event) -> None:
        """Resize all maps to fill panel when size changes"""
        # Calculate map size to fit within widget:
        # FlatWorldMap.render() returns a Rich Panel with padding=0:
        #   - Panel borders: 2 width, 2 height
        #   - Canvas: width x height (includes 1 legend row)
        #   - Stats line: 1 height
        # Total overhead: width +2, height +3
        new_width = max(20, event.size.width - 3)
        new_height = max(6, event.size.height - 4)

        # Only act if size actually changed
        if self._last_size == (new_width, new_height):
            return

        self._last_size = (new_width, new_height)

        # Log for debugging
        logger.info(f"Globe panel resize: widget={event.size.width}x{event.size.height} -> map={new_width}x{new_height}")

        # Initialize maps on first resize (when we know actual panel dimensions)
        if self.world_map is None and self.enhanced_globe is None and self.simple_globe is None:
            self._init_all_maps(new_width, new_height)
            self.refresh()
            return

        # Resize existing maps
        if self.world_map and hasattr(self.world_map, 'resize'):
            self.world_map.resize(new_width, new_height)

        if self.enhanced_globe and hasattr(self.enhanced_globe, 'resize'):
            self.enhanced_globe.resize(new_width, new_height)

        if self.simple_globe and hasattr(self.simple_globe, 'resize'):
            self.simple_globe.resize(new_width, new_height)

        self.refresh()

    def render(self):
        """Render the currently selected intel map type"""
        dt = 0.05  # Animation delta time

        # Initialize maps with small default size if not yet initialized (before on_resize)
        # Will be resized properly once on_resize fires with actual panel dimensions
        if self.world_map is None and self.enhanced_globe is None and self.simple_globe is None:
            self._init_all_maps(40, 10)

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

        # Enhanced columns (14 total) - shows more enrichment data + anomaly/spread
        self.table.add_column("Time", key="time", width=8)
        self.table.add_column("Dir", key="direction", width=3)  # Direction indicator
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
        key.append("Dir:", style="dim bold")
        key.append(" →", style="cyan")
        key.append("Out", style="dim")
        key.append(" ←", style="magenta")
        key.append("In", style="dim")
        key.append(" │ ", style="dim")
        key.append("Risk:", style="dim bold")
        key.append(" ●", style="bold red")
        key.append("C", style="dim")
        key.append(" ◉", style="bold yellow")
        key.append("H", style="dim")
        key.append(" ●", style="yellow")
        key.append("M", style="dim")
        key.append(" ●", style="cyan")
        key.append("L", style="dim")
        key.append(" │ ", style="dim")
        key.append("Anom", style="dim bold")
        key.append("=Anomaly ", style="dim")
        key.append("Sprd", style="dim bold")
        key.append("=Disagr ", style="dim")
        key.append("Hops", style="dim bold")
        key.append("=NetDist", style="dim")
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
        for conn in self.connections[-50:]:  # Most recent 50 (matches globe slice direction)
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

                # Threat color mapping (text only) - 5 tiers matching globe THREAT_LEVELS
                if threat >= 0.8:
                    threat_color = "bold red"
                    threat_indicator = "●●●"     # Critical
                elif threat >= 0.7:
                    threat_color = "bold yellow"
                    threat_indicator = "●●◉"     # High
                elif threat >= 0.5:
                    threat_color = "yellow"
                    threat_indicator = "●●○"     # Medium
                elif threat >= 0.3:
                    threat_color = "cyan"
                    threat_indicator = "●○○"     # Low
                else:
                    threat_color = "green"
                    threat_indicator = "○○○"     # Info

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
                src_ip_raw = conn.get('src_ip') or 'local'
                dst_ip_raw = conn.get('dst_ip') or 'Unknown'
                src_ip = src_ip_raw[:12]
                dst_ip = dst_ip_raw[:15]
                port = str(conn.get('dst_port', '-'))
                protocol = (conn.get('protocol') or 'TCP')[:5]
                org = (conn.get('dst_org') or 'Unknown')[:15]

                # Determine direction (incoming/outgoing)
                dir_label, dir_color, dir_symbol = get_direction(src_ip_raw, dst_ip_raw)

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
                    f"[{dir_color}]{dir_symbol}[/]",  # Direction indicator
                    f"[cyan]{src_ip}[/]",
                    f"[cyan]{dst_ip}[/]",
                    f"[magenta]{port}[/]",
                    f"[dim]{protocol}[/]",
                    f"[white]{org}[/]",
                    f"[{type_color}]{org_type:>7}[/]",
                    f"[{threat_color}]{threat_indicator}[/]",
                    f"[{threat_color}]{score_display}[/]",
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
    Network Intelligence Panel - Passive Network Reconnaissance

    Provides passive network intelligence gathered without active scanning.
    Shows traffic flow analysis, MAC discovery, subnet intelligence, and
    protocol distribution - all from observed traffic only.

    Design: Professional SOC aesthetic emphasizing passive intelligence gathering.

    PASSIVITY PRINCIPLE: CobaltGraph sees without being seen.
    - All intelligence derived from observed packets only
    - No ARP probes, no port scans, no active discovery
    - MAC addresses learned from Ethernet frame headers
    - IP associations learned from packet contents
    """

    DEFAULT_CSS = """
    NetworkDevicePanel {
        height: 100%;
        width: 100%;
        padding: 0 1;
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
            # Extended passive intelligence
            'subnets_detected': set(),
            'mac_sources': {},      # MAC -> {'direction': 'src'|'dst'|'both', 'ips': set(), 'count': int}
            'protocol_stats': {},   # {'TCP': int, 'UDP': int}
            'arp_activity': [],     # Recent ARP observations
            'broadcast_count': 0,
            'inbound_macs': set(),  # MACs seen as destination (receiving traffic)
            'outbound_macs': set(), # MACs seen as source (sending traffic)
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
        """Extract network intelligence from observed traffic flows"""
        if not self.flows:
            return

        src_ips = set()
        mac_sources = {}
        protocol_stats = {'TCP': 0, 'UDP': 0, 'OTHER': 0}

        for src_mac, flow_data in self.flows.items():
            # Track MAC as source (outbound traffic)
            if src_mac not in mac_sources:
                mac_sources[src_mac] = {
                    'direction': 'outbound',
                    'ips': set(),
                    'count': 0,
                    'vendor': flow_data.get('device_vendor'),
                    'threat_avg': flow_data.get('threat_avg', 0)
                }

            if 'src_ip' in flow_data:
                src_ips.add(flow_data['src_ip'])
                mac_sources[src_mac]['ips'].add(flow_data['src_ip'])

            # Count flows per MAC
            destinations = flow_data.get('destinations', {})
            mac_sources[src_mac]['count'] += len(destinations)

            # Protocol statistics
            for dest_key, dest_data in destinations.items():
                proto = dest_data.get('protocol', 'TCP').upper()
                if proto in protocol_stats:
                    protocol_stats[proto] += dest_data.get('count', 1)
                else:
                    protocol_stats['OTHER'] += dest_data.get('count', 1)

        self.network_info['mac_sources'] = mac_sources
        self.network_info['protocol_stats'] = protocol_stats
        self.network_info['outbound_macs'] = set(mac_sources.keys())
        self._detect_network_range(src_ips)

    def _update_network_info_from_devices(self):
        """Extract network intelligence from device inventory"""
        if not self.devices:
            return

        src_ips = set()
        mac_sources = {}

        for device in self.devices:
            mac = device.get('mac', '')
            if not mac:
                continue

            ip_addresses = device.get('ip_addresses', [])
            if isinstance(ip_addresses, str):
                try:
                    import json
                    ip_addresses = json.loads(ip_addresses)
                except (json.JSONDecodeError, TypeError):
                    ip_addresses = []

            mac_sources[mac] = {
                'direction': 'observed',
                'ips': set(ip_addresses) if ip_addresses else set(),
                'count': device.get('connection_count', 0),
                'vendor': device.get('vendor'),
                'threat_avg': device.get('threat_score', 0)
            }

            for ip in ip_addresses:
                if isinstance(ip, str):
                    src_ips.add(ip)

        self.network_info['mac_sources'] = mac_sources
        self._detect_network_range(src_ips)

    def _detect_network_range(self, src_ips: set):
        """Passively detect network ranges from observed IPs"""
        detected_subnets = set()

        for ip in src_ips:
            if ip.startswith('192.168.'):
                parts = ip.split('.')
                subnet = f"192.168.{parts[2]}.0/24"
                detected_subnets.add(subnet)
                if 'ip_range' not in self.network_info or self.network_info['ip_range'] == 'detecting...':
                    self.network_info['ip_range'] = subnet
            elif ip.startswith('10.'):
                parts = ip.split('.')
                subnet = f"10.{parts[1]}.{parts[2]}.0/24"
                detected_subnets.add(subnet)
                if self.network_info.get('ip_range') == 'detecting...':
                    self.network_info['ip_range'] = subnet
            elif ip.startswith('172.'):
                parts = ip.split('.')
                try:
                    second = int(parts[1])
                    if 16 <= second <= 31:
                        subnet = f"172.{parts[1]}.{parts[2]}.0/24"
                        detected_subnets.add(subnet)
                        if self.network_info.get('ip_range') == 'detecting...':
                            self.network_info['ip_range'] = subnet
                except (ValueError, IndexError):
                    pass

        self.network_info['subnets_detected'] = detected_subnets

    def render(self):
        """Render professional network intelligence panel"""
        has_flow_data = bool(self.flows)
        has_device_data = bool(self.devices)
        mac_sources = self.network_info.get('mac_sources', {})

        if not has_flow_data and not has_device_data:
            return Panel(
                "[dim]─────────────────────────────────────[/dim]\n"
                "[dim]PASSIVE RECONNAISSANCE ACTIVE[/dim]\n"
                "[dim]─────────────────────────────────────[/dim]\n\n"
                "[dim]Awaiting network traffic...[/dim]\n\n"
                "[dim]Intelligence sources:[/dim]\n"
                "[dim]  ▫ Ethernet frame headers[/dim]\n"
                "[dim]  ▫ ARP cache observations[/dim]\n"
                "[dim]  ▫ IP packet analysis[/dim]\n"
                "[dim]  ▫ Protocol fingerprinting[/dim]\n\n"
                "[dim italic]No active probing performed[/dim italic]",
                title="[bold bright_white]NET INTEL[/bold bright_white]",
                border_style="dim cyan",
                padding=(0, 1)
            )

        lines = []

        # ═══ HEADER: Subnet Intelligence ═══
        lines.append(f"[dim]{'─' * 38}[/dim]")
        ip_range = self.network_info.get('ip_range', 'unknown')
        subnets = self.network_info.get('subnets_detected', set())

        lines.append(f"[bold dim]SUBNET[/bold dim] [bright_white]{ip_range}[/bright_white]")

        if len(subnets) > 1:
            other_subnets = [s for s in subnets if s != ip_range][:2]
            if other_subnets:
                lines.append(f"[dim]  also: {', '.join(other_subnets)}[/dim]")

        # ═══ SECTION: Traffic Flow Summary ═══
        lines.append("")
        lines.append("[bold dim]TRAFFIC FLOW[/bold dim]")

        total_macs = len(mac_sources)
        total_flows = sum(m.get('count', 0) for m in mac_sources.values())
        protocol_stats = self.network_info.get('protocol_stats', {})

        tcp_count = protocol_stats.get('TCP', 0)
        udp_count = protocol_stats.get('UDP', 0)
        other_count = protocol_stats.get('OTHER', 0)
        total_proto = tcp_count + udp_count + other_count

        # Traffic metrics
        lines.append(f"  [dim]endpoints[/dim] {total_macs:>5}  [dim]│[/dim]  [dim]flows[/dim] {total_flows:>6}")

        # Protocol bar visualization
        if total_proto > 0:
            bar_width = 20
            tcp_bar = int((tcp_count / total_proto) * bar_width)
            udp_bar = int((udp_count / total_proto) * bar_width)
            other_bar = bar_width - tcp_bar - udp_bar

            proto_bar = f"[cyan]{'▮' * tcp_bar}[/cyan][magenta]{'▮' * udp_bar}[/magenta][dim]{'▯' * other_bar}[/dim]"
            lines.append(f"  {proto_bar}")
            lines.append(f"  [cyan]TCP {tcp_count}[/cyan] [magenta]UDP {udp_count}[/magenta] [dim]other {other_count}[/dim]")

        # ═══ SECTION: MAC Intelligence ═══
        lines.append("")
        lines.append("[bold dim]MAC DISCOVERY[/bold dim]")
        lines.append(f"  [dim]method: passive observation[/dim]")

        # Sort MACs by activity (flow count)
        sorted_macs = sorted(
            mac_sources.items(),
            key=lambda x: (x[1].get('threat_avg', 0), x[1].get('count', 0)),
            reverse=True
        )[:5]

        for idx, (mac, mac_data) in enumerate(sorted_macs):
            vendor = (mac_data.get('vendor') or 'Unknown')[:10]
            ips = mac_data.get('ips', set())
            flow_count = mac_data.get('count', 0)
            threat_avg = float(mac_data.get('threat_avg', 0) or 0)
            direction = mac_data.get('direction', 'observed')

            # Direction indicator
            if direction == 'outbound':
                dir_icon = "[cyan]→[/cyan]"  # Sending traffic
                dir_label = "OUT"
            elif direction == 'inbound':
                dir_icon = "[magenta]←[/magenta]"  # Receiving traffic
                dir_label = "IN"
            else:
                dir_icon = "[dim]◆[/dim]"  # Observed
                dir_label = "OBS"

            # Threat indicator
            if threat_avg >= 0.5:
                threat_ind = f"[bold red]▲[/bold red]"
            elif threat_avg >= 0.3:
                threat_ind = f"[yellow]─[/yellow]"
            else:
                threat_ind = f"[dim green]▼[/dim green]"

            # MAC line (truncated for display)
            mac_short = mac[:8] + "..." + mac[-5:] if len(mac) > 17 else mac

            is_last = idx == len(sorted_macs) - 1
            prefix = "└" if is_last else "├"

            lines.append(f"  [dim]{prefix}[/dim] {dir_icon} {threat_ind} [dim]{mac_short}[/dim]")

            # Show primary IP and vendor
            primary_ip = list(ips)[0] if ips else "—"
            lines.append(f"  [dim]{'│' if not is_last else ' '}[/dim]   [dim]{vendor:<10}[/dim] {primary_ip}")

        # ═══ SECTION: Intelligence Notes ═══
        lines.append("")
        lines.append(f"[dim]{'─' * 38}[/dim]")
        lines.append("[dim italic]→=outbound ←=inbound ▲=risk ▼=safe[/dim italic]")

        content = "\n".join(lines)

        return Panel(
            content,
            title="[bold bright_white]NET INTEL[/bold bright_white]",
            border_style="dim cyan",
            padding=(0, 1)
        )

    def _get_threat_style(self, threat_score: float) -> tuple:
        """Return (icon, color) based on threat score"""
        if threat_score >= 0.7:
            return "[bold red]▲[/bold red]", "bold red"
        elif threat_score >= 0.5:
            return "[bold yellow]▲[/bold yellow]", "bold yellow"
        elif threat_score >= 0.3:
            return "[yellow]─[/yellow]", "yellow"
        else:
            return "[dim green]▼[/dim green]", "dim green"


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

        # Determine direction
        src_ip = conn.get('src_ip', 'local')
        dst_ip = conn.get('dst_ip', 'Unknown')
        dir_label, dir_color, dir_symbol = get_direction(src_ip, dst_ip)
        dir_full = {"OUT": "Outgoing", "IN": "Incoming", "INT": "Internal", "EXT": "External"}.get(dir_label, "Unknown")
        lines.append(f"  [cyan]Direction:[/cyan]      [{dir_color}]{dir_symbol} {dir_full}[/{dir_color}]")

        lines.append(f"  [cyan]Source IP:[/cyan]      {src_ip}")
        lines.append(f"  [cyan]Source MAC:[/cyan]     {conn.get('src_mac', 'Unknown')}")
        lines.append(f"  [cyan]Destination IP:[/cyan] {dst_ip}")
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
        ("k", "show_metric_key", "Show Full Metric Key"),
        ("v", "cycle_verification_filter", "Cycle Verification Filter"),
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
        """Manual refresh action - resets view to show only new data from this point onward"""
        # Call parent to set timestamp and clear base panels
        super().action_refresh()

        # Also clear enhanced dashboard specific panels
        if self.globe_panel:
            self.globe_panel.globe_data = {'connections': [], 'heatmap': {}}

        if self.connection_table:
            self.connection_table.connections = []

        if self.anomaly_panel:
            if hasattr(self.anomaly_panel, 'anomalies'):
                self.anomaly_panel.anomalies = []
            if hasattr(self.anomaly_panel, 'alert_data'):
                self.anomaly_panel.alert_data = {'alerts': [], 'anomalies': []}

        if self.mode_specific_panel:
            if hasattr(self.mode_specific_panel, 'topology_data'):
                self.mode_specific_panel.topology_data = {}
            if hasattr(self.mode_specific_panel, 'devices'):
                self.mode_specific_panel.devices = []

        # Clear filter cache so it doesn't restore old data
        if hasattr(self, '_all_connections'):
            delattr(self, '_all_connections')
        if hasattr(self, '_verification_filter'):
            self._verification_filter = 0

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

            # Get connections - filter by refresh timestamp if set
            connections = self.data_manager.get_connections(
                limit=100,
                since_timestamp=self._refresh_timestamp
            )
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

            # Update threat posture panel (SOC Summary)
            if self.threat_posture_panel:
                # Calculate extended metrics for SOC Summary
                total_conn = len(connections)
                flagged = sum(1 for c in connections if float(c.get('threat_score', 0) or 0) >= 0.3)
                high_uncertainty = sum(1 for c in connections if c.get('high_uncertainty', False))

                # Calculate consensus agreement from score spread
                spreads = [float(c.get('score_spread', 0) or 0) for c in connections if c.get('score_spread') is not None]
                avg_spread = sum(spreads) / len(spreads) if spreads else 0
                consensus_agreement = max(0, 1.0 - avg_spread)  # Lower spread = higher agreement

                # Traffic direction counts
                inbound_count = 0
                outbound_count = 0
                for c in connections:
                    src_ip = c.get('src_ip', '')
                    dst_ip = c.get('dst_ip', '')
                    # Simple private IP check
                    src_is_private = src_ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                                                        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                                        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'))
                    dst_is_private = dst_ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                                                        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                                        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'))
                    if src_is_private and not dst_is_private:
                        outbound_count += 1
                    elif not src_is_private and dst_is_private:
                        inbound_count += 1

                # Protocol distribution
                protocols = {}
                for c in connections:
                    proto = c.get('protocol', 'TCP')
                    protocols[proto] = protocols.get(proto, 0) + 1

                # Calculate baseline from oldest third of connections
                baseline_threats = threat_scores[:len(threat_scores)//3] if threat_scores else []
                baseline = sum(baseline_threats) / len(baseline_threats) if baseline_threats else 0.15

                self.threat_posture_panel.threat_data = {
                    'current_threat': current_threat,
                    'baseline_threat': baseline,
                    'active_threats': high_threat_count,
                    'monitored_ips': len(set(c.get('dst_ip') for c in connections)),
                    'top_threats': top_threats,
                    # Extended SOC metrics
                    'total_connections': total_conn,
                    'flagged_connections': flagged,
                    'high_uncertainty': high_uncertainty,
                    'consensus_agreement': consensus_agreement,
                    'inbound_count': inbound_count,
                    'outbound_count': outbound_count,
                    'protocols': protocols,
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
                # Use timestamp filter if refresh was triggered
                if hasattr(self.data_manager, 'get_devices'):
                    devices = self.data_manager.get_devices(since_timestamp=self._refresh_timestamp)
                else:
                    devices = []
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
        # Update globe animation for the currently displayed map type
        if self.globe_panel:
            try:
                map_type = self.globe_panel._current_map_type
                if map_type == "flat" and self.globe_panel.world_map:
                    self.globe_panel.world_map.update(0.2)
                elif map_type == "rotating" and self.globe_panel.enhanced_globe:
                    self.globe_panel.enhanced_globe.update(0.2)
                elif map_type == "simple" and self.globe_panel.simple_globe:
                    self.globe_panel.simple_globe.update(0.2)
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

            # Check if capture is active - beat if we have connections (capture is working)
            # The capture monitor was started if pipeline is running, so beat unconditionally
            # when there are connections in the system (even if older than 60s)
            if self.recent_connections:
                heartbeat.beat("capture", "Capture active")

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
        help_text = "Q=Quit R=Refresh A=Anom O=Org M=Dev G=Globe I=Map K=Key V=Filter Enter=Details ?=Help ESC=Close"
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

    def action_show_metric_key(self) -> None:
        """Show full metric key/legend in subtitle area"""
        # Cycle through key display modes
        if not hasattr(self, '_key_mode'):
            self._key_mode = 0

        self._key_mode = (self._key_mode + 1) % 3

        if self._key_mode == 0:
            self.sub_title = "Key: ●=Critical ◉=High ◯=Med ○=Low | V: ✓=Verified !=Flagged ?=Pending | T: 4=All 3=Good 2=Partial"
        elif self._key_mode == 1:
            self.sub_title = "Verification: ✓=AI verified !=Needs review ?=Awaiting data ✗=Cannot verify | Triangulation=scorer agreement"
        else:
            self.sub_title = "Press 'k' to cycle key | Enter=Details | i=Map | v=Filter | ?=Help"

    def action_cycle_verification_filter(self) -> None:
        """Cycle verification filter for connection table (All/Verified/Flagged/Unknown)"""
        if not hasattr(self, '_verification_filter'):
            self._verification_filter = 0

        filters = ["all", "verified", "flagged", "pending", "unknown"]
        self._verification_filter = (self._verification_filter + 1) % len(filters)
        current_filter = filters[self._verification_filter]

        # Update subtitle to show current filter
        filter_labels = {
            "all": "Showing ALL connections",
            "verified": "Showing VERIFIED connections only (✓)",
            "flagged": "Showing FLAGGED connections only (!)",
            "pending": "Showing PENDING connections only (?)",
            "unknown": "Showing UNKNOWN connections only (✗)",
        }
        self.sub_title = f"Filter: {filter_labels[current_filter]} (press 'v' to cycle)"

        # Apply filter to connection table
        if hasattr(self, 'connection_table_panel') and self.connection_table_panel:
            self._apply_verification_filter(current_filter)

    def _apply_verification_filter(self, filter_status: str) -> None:
        """Apply verification filter to connection table"""
        if not hasattr(self, 'connection_table_panel') or not self.connection_table_panel:
            return

        # Store original connections if not already stored
        if not hasattr(self, '_all_connections'):
            self._all_connections = self.connection_table_panel.connections.copy()

        if filter_status == "all":
            # Show all connections
            self.connection_table_panel.connections = self._all_connections
        else:
            # Filter by verification status
            filtered = [
                c for c in self._all_connections
                if c.get('verification_status', 'pending') == filter_status
            ]
            self.connection_table_panel.connections = filtered

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
