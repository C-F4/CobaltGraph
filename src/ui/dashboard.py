#!/usr/bin/env python3
"""
CobaltGraph Dashboard - Unified Threat Monitoring Interface

Features:
- Real-time connection monitoring with threat scoring
- ASCII globe with heatmaps and connection trails
- Organization triage matrix with trust scoring
- Hop count topology visualization
- Event log viewer with filtering
- Adaptive table density modes (LOW/MEDIUM/HIGH/FULL)

Layout:
  Left (55%):  Connection table + Stats panels
  Right (45%): Globe + Organization triage + Hop topology + Logo

Keyboard shortcuts:
  Q - Quit
  R - Refresh data
  A - Alert summary
  G - Toggle globe visibility
  T - Cycle table density mode
  O - Toggle organization triage
  H - Toggle hop topology
  L - Toggle event log viewer
"""

import sqlite3
import time
import math
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from enum import Enum
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table as RichTable

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Static, DataTable, Label, Log
from textual.reactive import reactive

# Import visualization components
try:
    from src.ui.viz_engine import (
        ThreatGlobe, OrganizationTriageMatrix, HopTopologyVisualizer,
        OrganizationTriage, THREAT_COLORS, ORG_TYPE_RISK
    )
    VIZ_ENGINE_AVAILABLE = True
except ImportError:
    try:
        from viz_engine import (
            ThreatGlobe, OrganizationTriageMatrix, HopTopologyVisualizer,
            OrganizationTriage, THREAT_COLORS, ORG_TYPE_RISK
        )
        VIZ_ENGINE_AVAILABLE = True
    except ImportError:
        VIZ_ENGINE_AVAILABLE = False

# Import 3D globe
try:
    from src.ui.globe_3d import Globe3D, MATPLOTLIB_AVAILABLE, SIXEL_SUPPORTED
    GLOBE_3D_AVAILABLE = True
except ImportError:
    try:
        from globe_3d import Globe3D, MATPLOTLIB_AVAILABLE, SIXEL_SUPPORTED
        GLOBE_3D_AVAILABLE = True
    except ImportError:
        GLOBE_3D_AVAILABLE = False
        MATPLOTLIB_AVAILABLE = False
        SIXEL_SUPPORTED = False

# Import legacy ASCII globe as fallback
try:
    from src.ui.ascii_globe import ASCIIGlobe
    GLOBE_AVAILABLE = True
except ImportError:
    try:
        from ascii_globe import ASCIIGlobe
        GLOBE_AVAILABLE = True
    except ImportError:
        GLOBE_AVAILABLE = False


class ThreatDensity(Enum):
    """Adaptive density levels based on threat activity"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    FULL = "full"


class LayoutMode(Enum):
    """Screen layout modes"""
    STANDARD = "standard"
    FULLSCREEN_TABLE = "table"
    FULLSCREEN_GLOBE = "globe"
    SPLIT = "split"


# Column definitions for each density level
DENSITY_COLUMNS = {
    ThreatDensity.LOW: [
        ("Time", 8), ("Dst IP", 15), ("Port", 6),
        ("Score", 6), ("Level", 5), ("Geo", 4),
    ],
    ThreatDensity.MEDIUM: [
        ("Time", 8), ("Dst IP", 15), ("Port", 6),
        ("Score", 6), ("Level", 5), ("Org", 16),
        ("Geo", 4), ("Hops", 4), ("IOCs", 5),
    ],
    ThreatDensity.HIGH: [
        ("Time", 8), ("Dst IP", 15), ("Port", 6),
        ("Score", 6), ("Level", 5), ("ASN", 10),
        ("Org", 14), ("Type", 8), ("Trust", 6),
        ("Geo", 4), ("Hops", 4), ("IOCs", 5),
    ],
    ThreatDensity.FULL: [
        ("Time", 8), ("Dst IP", 15), ("Port", 6),
        ("Score", 6), ("Level", 5), ("ASN", 10),
        ("Org", 16), ("OrgType", 8), ("Trust", 6),
        ("Geo", 3), ("Hops", 4), ("TTL", 4),
        ("OS", 8), ("IOCs", 5),
    ],
}


class EventLogWidget(Static):
    """
    Event Log Viewer Widget

    Displays system events, alerts, and connection logs with filtering
    """

    events = reactive(list)
    visible = True
    filter_level = "ALL"  # ALL, CRITICAL, HIGH, MEDIUM, LOW

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._events: List[Dict] = []
        self._max_events = 100

    def toggle_visibility(self):
        self.visible = not self.visible
        self.refresh()

    def add_event(self, event_type: str, message: str, severity: str = "INFO",
                  metadata: Optional[Dict] = None):
        """Add a new event to the log"""
        event = {
            'timestamp': time.time(),
            'type': event_type,
            'message': message,
            'severity': severity,
            'metadata': metadata or {},
        }
        self._events.append(event)

        # Trim old events
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]

    def cycle_filter(self) -> str:
        """Cycle through filter levels"""
        filters = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        idx = filters.index(self.filter_level)
        self.filter_level = filters[(idx + 1) % len(filters)]
        self.refresh()
        return self.filter_level

    def _get_filtered_events(self) -> List[Dict]:
        """Get events matching current filter"""
        if self.filter_level == "ALL":
            return self._events[-20:]

        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        min_level = severity_order.get(self.filter_level, 0)

        filtered = [e for e in self._events
                   if severity_order.get(e.get('severity', 'INFO'), 0) >= min_level]
        return filtered[-20:]

    def watch_events(self, events: List[Dict]) -> None:
        """Update events from external source"""
        for event in events:
            if event not in self._events:
                self._events.append(event)

    def render(self) -> Panel:
        """Render the event log"""
        if not self.visible:
            return Panel(
                "[dim]Log hidden - press L to show[/dim]",
                title="[bold magenta]Event Log[/bold magenta]",
                border_style="dim"
            )

        lines = []

        # Header with filter indicator
        lines.append(f"[bold]Filter: [{self.filter_level}][/bold] | Total: {len(self._events)}")
        lines.append("─" * 50)

        filtered_events = self._get_filtered_events()

        if not filtered_events:
            lines.append("[dim]No events matching filter[/dim]")
        else:
            for event in reversed(filtered_events[-15:]):
                ts = event.get('timestamp', 0)
                time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "--:--:--"
                severity = event.get('severity', 'INFO')
                event_type = event.get('type', 'EVENT')[:8]
                message = event.get('message', '')[:40]

                # Severity coloring
                severity_styles = {
                    'CRITICAL': 'bold red',
                    'HIGH': 'yellow',
                    'MEDIUM': 'dim yellow',
                    'LOW': 'green',
                    'INFO': 'cyan',
                }
                style = severity_styles.get(severity, 'white')

                # Format line
                icon = "!" if severity == 'CRITICAL' else "~" if severity == 'HIGH' else "*"
                lines.append(f"[{style}]{icon}[/{style}] [dim]{time_str}[/dim] [{style}]{event_type:8s}[/{style}] {message}")

        return Panel(
            "\n".join(lines),
            title="[bold magenta]◎ Event Log[/bold magenta]",
            subtitle=f"[dim]Filter: {self.filter_level}[/dim]",
            border_style="magenta"
        )


class EnhancedGlobeWidget(Static):
    """
    Enhanced Globe Widget with multiple rendering backends

    Features:
    - Threat ASCII globe (default)
    - Legacy ASCII globe (fallback)
    - Real-time connection trail visualization
    - Heatmap overlay
    """

    connections_data = reactive(list)
    visible = True
    use_3d = False  # Toggle between 3D and ASCII

    def __init__(self, width: int = 50, height: int = 22, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.width = width
        self.height = height
        self._seen_connections = set()

        # Connection trails for animation
        self._active_trails: List[Dict] = []
        self._max_trails = 15
        self._trail_lifetime = 4.0

        # Initialize globe renderers
        self.globe_3d = None
        self.globe_threat = None
        self.globe_ascii = None

        if GLOBE_3D_AVAILABLE and MATPLOTLIB_AVAILABLE:
            self.globe_3d = Globe3D(width=width, height=height)

        if VIZ_ENGINE_AVAILABLE:
            self.globe_threat = ThreatGlobe(width=width, height=height)

        if GLOBE_AVAILABLE:
            self.globe_ascii = ASCIIGlobe(width=width, height=height)
            self.globe_ascii.state.rotation_x = 23.5
            self.globe_ascii.rotation_speed = 8.0

        # Select active globe
        self._active_globe = self.globe_threat or self.globe_ascii or self.globe_3d

    def toggle_visibility(self):
        self.visible = not self.visible
        self.refresh()

    def toggle_3d(self) -> bool:
        """Toggle between 3D and ASCII rendering"""
        if self.globe_3d:
            self.use_3d = not self.use_3d
            if self.use_3d:
                self._active_globe = self.globe_3d
            else:
                self._active_globe = self.globe_threat or self.globe_ascii
        return self.use_3d

    def _add_trail(self, conn: Dict):
        """Add a new connection trail for animation"""
        trail = {
            'start_time': time.time(),
            'dst_ip': conn.get('dst_ip') or '',
            'dst_lat': conn.get('dst_lat') or 0,
            'dst_lon': conn.get('dst_lon') or 0,
            'threat_score': conn.get('threat_score') or 0,
            'country': conn.get('country') or conn.get('dst_country') or '',
            'org': conn.get('dst_org') or conn.get('dst_asn_name') or '',
        }
        self._active_trails.append(trail)

        # Limit active trails
        if len(self._active_trails) > self._max_trails:
            self._active_trails = self._active_trails[-self._max_trails:]

    def _get_active_trails(self) -> List[Dict]:
        """Get trails that are still active (within lifetime)"""
        now = time.time()
        active = []
        for trail in self._active_trails:
            age = now - trail['start_time']
            if age < self._trail_lifetime:
                trail['progress'] = min(1.0, age / (self._trail_lifetime * 0.6))
                trail['fade'] = 1.0 - (age / self._trail_lifetime)
                active.append(trail)
        self._active_trails = active
        return active

    def watch_connections_data(self, connections: List[Dict]) -> None:
        """Update globe when new connections arrive"""
        if not self._active_globe or not connections:
            return

        new_connections = []
        for conn in connections:
            conn_key = (
                conn.get('timestamp', 0),
                conn.get('dst_ip', ''),
                conn.get('dst_port', 0)
            )
            if conn_key not in self._seen_connections:
                self._seen_connections.add(conn_key)
                new_connections.append(conn)
                # Add to active trails for animation
                self._add_trail(conn)

        if len(self._seen_connections) > 500:
            self._seen_connections = set(list(self._seen_connections)[-300:])

        for conn in new_connections[:10]:
            dst_lat = conn.get('dst_lat')
            dst_lon = conn.get('dst_lon')

            if not dst_lat or not dst_lon or (dst_lat == 0 and dst_lon == 0):
                country = conn.get('country', '') or conn.get('dst_country', '')
                coords = self._country_to_coords(country)
                if coords:
                    dst_lat, dst_lon = coords
                else:
                    continue

            threat_score = conn.get('threat_score', 0.0) or 0.0

            # Add to active globe
            if self.use_3d and self.globe_3d:
                self.globe_3d.add_connection(
                    39.8, -98.5,  # US center
                    float(dst_lat), float(dst_lon),
                    threat_score,
                    metadata=conn
                )
            elif hasattr(self._active_globe, 'add_connection'):
                if isinstance(self._active_globe, ThreatGlobe):
                    self._active_globe.add_connection(conn)
                else:
                    self._active_globe.add_connection(
                        39.8, -98.5, float(dst_lat), float(dst_lon),
                        threat_score, metadata=conn
                    )

    def _country_to_coords(self, country: str) -> Optional[Tuple[float, float]]:
        """Get approximate coordinates for a country"""
        coords = {
            'United States': (39.8, -98.5), 'US': (39.8, -98.5),
            'United Kingdom': (51.5, -0.1), 'UK': (51.5, -0.1), 'GB': (51.5, -0.1),
            'Germany': (51.2, 10.4), 'DE': (51.2, 10.4),
            'France': (46.2, 2.2), 'FR': (46.2, 2.2),
            'Japan': (35.7, 139.7), 'JP': (35.7, 139.7),
            'China': (35.9, 104.2), 'CN': (35.9, 104.2),
            'Russia': (55.8, 37.6), 'RU': (55.8, 37.6),
            'Australia': (-33.9, 151.2), 'AU': (-33.9, 151.2),
            'Brazil': (-14.2, -51.9), 'BR': (-14.2, -51.9),
            'India': (20.6, 78.9), 'IN': (20.6, 78.9),
            'Canada': (56.1, -106.3), 'CA': (56.1, -106.3),
            'Netherlands': (52.1, 5.3), 'NL': (52.1, 5.3),
            'Singapore': (1.4, 103.8), 'SG': (1.4, 103.8),
        }
        return coords.get(country)

    def render(self) -> Panel:
        """Render the globe with styled output"""
        if not self.visible:
            return Panel(
                "[dim]Globe hidden - press G to show[/dim]",
                title="[bold cyan]Globe[/bold cyan]",
                border_style="dim"
            )

        if not self._active_globe:
            return Panel(
                "[dim]No globe renderer available[/dim]",
                title="[bold cyan]Globe[/bold cyan]",
                border_style="dim"
            )

        # Update globe state
        if hasattr(self._active_globe, 'update'):
            self._active_globe.update()

        # Get rendered output from globe
        if self.use_3d and self.globe_3d:
            globe_output = self.globe_3d.render_ascii(self.width, self.height)
            mode = "3D"
        elif hasattr(self._active_globe, 'render'):
            globe_output = self._active_globe.render()
            mode = "Threat" if isinstance(self._active_globe, ThreatGlobe) else "ASCII"
        else:
            globe_output = Text("[dim]Render error[/dim]")
            mode = "Error"

        # Get stats
        stats = {}
        if hasattr(self._active_globe, 'get_stats'):
            stats = self._active_globe.get_stats()
        elif hasattr(self._active_globe, 'get_stats_summary'):
            stats = self._active_globe.get_stats_summary()

        # Get active trails
        active_trails = self._get_active_trails()

        # Build combined display - preserve Rich Text styling
        combined = Text()

        # Handle Rich Text object directly to preserve styling
        if isinstance(globe_output, Text):
            # Rich Text object - append directly to preserve all styling
            combined.append_text(globe_output)
        elif isinstance(globe_output, str):
            # Plain string - use markup parsing
            combined.append(globe_output)
        else:
            # Fallback - convert to string
            combined.append(str(globe_output))

        # Trail indicators (animated connection paths)
        if active_trails:
            combined.append("\n")
            for trail in active_trails[:3]:
                progress = trail.get('progress', 0) or 0
                threat = trail.get('threat_score', 0) or 0
                country = (trail.get('country') or '??')[:3]
                ip = (trail.get('dst_ip') or '')[-8:]

                # Progress bar with particle effect
                bar_len = 12
                filled = int(progress * bar_len)
                particle = '●' if progress < 0.9 else '◉'

                # Color based on threat
                if threat >= 0.7:
                    color = 'red'
                elif threat >= 0.4:
                    color = 'yellow'
                else:
                    color = 'green'

                bar = '─' * filled + particle + '─' * (bar_len - filled - 1)
                combined.append(bar, style=color)
                combined.append(f" {country} ", style=color)
                combined.append(f"{ip}\n", style="dim")

        # Stats overlay
        rotation = stats.get('rotation', stats.get('rotation_y', 0))
        connections = stats.get('connections', stats.get('active_pings', 0))
        heat_zones = stats.get('heat_zones', 0)
        trail_count = len(active_trails)

        combined.append(f"R:{rotation:.0f}° ", style="cyan")
        combined.append(f"C:{connections} ", style="yellow")
        combined.append(f"T:{trail_count} ", style="magenta")
        combined.append(f"H:{heat_zones}", style="red")

        title = f"[bold cyan]◉ {mode} Globe[/bold cyan]"
        subtitle = "[dim]heatmap + trails[/dim]"

        return Panel(
            combined,
            title=title,
            subtitle=subtitle,
            border_style="cyan"
        )


class ConnectionTableWidget(Static):
    """
    Primary connection table with adaptive column density

    FIXED: Density toggle now works correctly without removing table data
    """

    connections = reactive(list)
    density = reactive(ThreatDensity.MEDIUM)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._current_density = ThreatDensity.MEDIUM
        self._columns_initialized = False

    def compose(self) -> ComposeResult:
        yield DataTable(id="main-table")

    def on_mount(self) -> None:
        """Set up the table"""
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        self._setup_columns(ThreatDensity.MEDIUM)
        self._columns_initialized = True

    def _setup_columns(self, density: ThreatDensity) -> None:
        """Configure columns based on density level"""
        try:
            table = self.query_one(DataTable)
            # Store current data before clearing
            current_data = list(self.connections) if self.connections else []

            table.clear(columns=True)

            columns = DENSITY_COLUMNS[density]
            for col_name, _ in columns:
                table.add_column(col_name, key=col_name.lower().replace(" ", "_"))

            self._current_density = density

            # Re-populate with stored data
            if current_data:
                self._populate_table(current_data)

        except Exception:
            pass

    def cycle_density(self) -> ThreatDensity:
        """Cycle through density modes - FIXED version"""
        cycle_order = [ThreatDensity.LOW, ThreatDensity.MEDIUM, ThreatDensity.HIGH, ThreatDensity.FULL]
        current_idx = cycle_order.index(self._current_density)
        new_density = cycle_order[(current_idx + 1) % len(cycle_order)]

        # Store connections before changing
        stored_connections = list(self.connections) if self.connections else []

        # Setup new columns
        self._setup_columns(new_density)

        # Update reactive (don't trigger watch since we already populated)
        self._current_density = new_density

        return new_density

    def _get_ioc_indicators(self, conn: Dict) -> Text:
        """Generate IOC indicator flags"""
        indicators = []
        score = conn.get('threat_score', 0) or 0
        org_trust = conn.get('org_trust_score', 0.5) or 0.5
        org_type = conn.get('dst_org_type', '') or ''
        port = conn.get('dst_port', 0) or 0
        hop_count = conn.get('hop_count')

        if score >= 0.7:
            indicators.append(("!", "bold red"))
        elif score >= 0.5:
            indicators.append(("~", "yellow"))

        if org_trust < 0.3:
            indicators.append(("U", "red"))

        if org_type in ('hosting', 'vpn', 'proxy', 'tor'):
            indicators.append(("H", "magenta"))

        suspicious_ports = {22, 23, 3389, 445, 135, 139, 4444, 5555, 1337, 6667}
        if port in suspicious_ports:
            indicators.append(("P", "cyan"))

        if hop_count and hop_count > 20:
            indicators.append(("D", "yellow"))

        if not indicators:
            return Text("-", style="dim")

        result = Text()
        for char, style in indicators[:5]:
            result.append(char, style=style)
        return result

    def _truncate(self, text: str, max_len: int = 12) -> str:
        """Truncate text with ellipsis"""
        if not text:
            return "-"
        return text[:max_len-1] + "…" if len(text) > max_len else text

    def _get_org_type_badge(self, org_type: str) -> Text:
        """Get colored org type badge"""
        type_colors = {
            'cloud': ('CLD', 'cyan'),
            'cdn': ('CDN', 'green'),
            'isp': ('ISP', 'blue'),
            'hosting': ('HST', 'yellow'),
            'vpn': ('VPN', 'magenta'),
            'proxy': ('PRX', 'magenta'),
            'tor': ('TOR', 'red'),
            'unknown': ('UNK', 'dim'),
        }
        badge, color = type_colors.get(org_type, ('???', 'dim'))
        return Text(badge, style=color)

    def _populate_table(self, connections: List[Dict]) -> None:
        """Populate table with connection data"""
        try:
            table = self.query_one(DataTable)
            table.clear()

            for conn in connections[:60]:
                row = self._build_row(conn)
                if row:
                    table.add_row(*row)
        except Exception:
            pass

    def _build_row(self, conn: Dict) -> Optional[List]:
        """Build a table row for a connection"""
        timestamp = conn.get('timestamp', 0)
        time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S") if timestamp else "--:--:--"

        dst_ip = conn.get('dst_ip', '-')
        dst_port = str(conn.get('dst_port', 0))
        score = conn.get('threat_score', 0.0) or 0.0
        country = (conn.get('country', '') or conn.get('dst_country', ''))[:3].upper() or "--"

        # Threat level styling
        if score >= 0.7:
            level = Text("CRIT", style="bold red")
            score_text = Text(f"{score:.2f}", style="bold red")
        elif score >= 0.5:
            level = Text("HIGH", style="bold yellow")
            score_text = Text(f"{score:.2f}", style="yellow")
        elif score >= 0.3:
            level = Text("MED", style="yellow")
            score_text = Text(f"{score:.2f}", style="dim yellow")
        else:
            level = Text("LOW", style="green")
            score_text = Text(f"{score:.2f}", style="dim green")

        # Additional fields
        asn = conn.get('dst_asn')
        asn_str = f"AS{asn}" if asn else "-"
        org = self._truncate(conn.get('dst_org') or conn.get('dst_asn_name', ''), 16)
        org_type = conn.get('dst_org_type', '') or ''
        org_trust = conn.get('org_trust_score', 0.5) or 0.5
        hop_count = conn.get('hop_count')
        hop_str = f"{hop_count}h" if hop_count else "-"
        ttl = conn.get('ttl_observed')
        ttl_str = str(ttl) if ttl else "-"
        os_fp = self._truncate(conn.get('os_fingerprint', ''), 8)

        # Trust display
        if org_trust >= 0.7:
            trust_text = Text(f"{org_trust:.2f}", style="green")
        elif org_trust >= 0.4:
            trust_text = Text(f"{org_trust:.2f}", style="yellow")
        else:
            trust_text = Text(f"{org_trust:.2f}", style="red")

        iocs = self._get_ioc_indicators(conn)

        # Build row based on density
        if self._current_density == ThreatDensity.LOW:
            return [time_str, dst_ip, dst_port, score_text, level, country]
        elif self._current_density == ThreatDensity.MEDIUM:
            return [time_str, dst_ip, dst_port, score_text, level, org, country, hop_str, iocs]
        elif self._current_density == ThreatDensity.HIGH:
            return [time_str, dst_ip, dst_port, score_text, level, asn_str,
                   self._truncate(org, 14), self._get_org_type_badge(org_type),
                   trust_text, country, hop_str, iocs]
        else:  # FULL
            return [time_str, dst_ip, dst_port, score_text, level, asn_str,
                   org, self._get_org_type_badge(org_type), trust_text,
                   country, hop_str, ttl_str, os_fp, iocs]

    def watch_connections(self, connections: List[Dict]) -> None:
        """Update table when connections change"""
        if self._columns_initialized:
            self._populate_table(connections)

    def watch_density(self, density: ThreatDensity) -> None:
        """Handle density changes from external sources"""
        if density != self._current_density and self._columns_initialized:
            self._setup_columns(density)


class OrganizationTriageWidget(Static):
    """Organization Triage Matrix Widget"""

    org_data = reactive(list)
    visible = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.organizations: Dict[str, Dict] = {}

    def toggle_visibility(self):
        self.visible = not self.visible
        self.refresh()

    def watch_org_data(self, orgs: List[Dict]) -> None:
        for org in orgs:
            name = org.get('name', '')
            if name:
                self.organizations[name] = org

    def _calculate_triage(self, org: Dict) -> Tuple[str, str]:
        count = org.get('count', 1)
        avg_threat = org.get('threat_sum', 0) / max(1, count)
        trust = org.get('trust', 0.5)
        org_type = org.get('org_type', 'unknown')

        risk_coeff = ORG_TYPE_RISK.get(org_type, 0.5) if VIZ_ENGINE_AVAILABLE else 0.5
        risk = avg_threat * (1.0 - trust) * risk_coeff

        if risk >= 0.5:
            return 'CRIT', 'bold red'
        elif risk >= 0.3:
            return 'HIGH', 'yellow'
        elif risk >= 0.15:
            return 'MED', 'dim yellow'
        return 'LOW', 'green'

    def render(self) -> Panel:
        if not self.visible:
            return Panel("[dim]Hidden - press O[/dim]", title="[bold yellow]Org[/bold yellow]", border_style="dim")

        lines = ["[bold]ORG              TRIAGE TRUST CNT[/bold]", "─" * 36]

        sorted_orgs = sorted(
            self.organizations.values(),
            key=lambda o: o.get('threat_sum', 0) / max(1, o.get('count', 1)),
            reverse=True
        )[:8]

        if not sorted_orgs:
            lines.append("[dim]No organizations[/dim]")
        else:
            for org in sorted_orgs:
                name = org.get('name', 'Unknown')[:16].ljust(16)
                level, color = self._calculate_triage(org)
                trust = org.get('trust', 0.5)
                trust_bar = '█' * int(trust * 4) + '░' * (4 - int(trust * 4))
                t_color = 'green' if trust >= 0.6 else 'yellow' if trust >= 0.3 else 'red'
                count = str(org.get('count', 0)).rjust(3)

                lines.append(f"[cyan]{name}[/cyan] [{color}]{level:4s}[/{color}] [{t_color}]{trust_bar}[/{t_color}] [dim]{count}[/dim]")

        return Panel("\n".join(lines), title="[bold yellow]◆ Org Triage[/bold yellow]", border_style="yellow")


class HopTopologyWidget(Static):
    """Hop Topology Visualization"""

    hop_data = reactive(dict)
    visible = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hop_counts: Dict[int, Dict] = {}

    def toggle_visibility(self):
        self.visible = not self.visible
        self.refresh()

    def watch_hop_data(self, data: Dict) -> None:
        self.hop_counts.update(data)

    def render(self) -> Panel:
        if not self.visible:
            return Panel("[dim]Hidden - press H[/dim]", title="[bold green]Hops[/bold green]", border_style="dim")

        lines = ["[bold]Hop Distribution[/bold]", "─" * 28]

        if not self.hop_counts:
            lines.append("[dim]No hop data[/dim]")
        else:
            max_count = max(d['count'] for d in self.hop_counts.values()) or 1

            for hop in sorted(h for h in self.hop_counts.keys() if 1 <= h <= 20)[:8]:
                data = self.hop_counts[hop]
                count = data['count']
                avg_threat = data['threat_sum'] / max(1, count)

                bar_len = int((count / max_count) * 15)
                bar = '█' * bar_len

                color = 'red' if avg_threat >= 0.6 else 'yellow' if avg_threat >= 0.3 else 'green'
                lines.append(f"[cyan]{hop:2d}h[/cyan] [{color}]{bar:15s}[/{color}] {count:3d}")

            if self.hop_counts:
                total = sum(d['count'] for d in self.hop_counts.values())
                avg = sum(h * d['count'] for h, d in self.hop_counts.items()) / max(1, total)
                lines.append(f"\n[dim]Avg: {avg:.1f}h | Tot: {total}[/dim]")

        return Panel("\n".join(lines), title="[bold green]▲ Hops[/bold green]", border_style="green")


class ThreatMatrixWidget(Static):
    """Threat distribution matrix"""

    threat_data = reactive(dict)

    def render(self) -> Panel:
        data = self.threat_data
        total = data.get('total', 1) or 1
        low = data.get('low', 0)
        medium = data.get('medium', 0)
        high = data.get('high', 0)
        critical = data.get('critical', 0)

        def bar(val, tot, w=14):
            filled = int((val / tot) * w) if tot > 0 else 0
            return '█' * filled + '░' * (w - filled)

        lines = [
            f"[green]LOW [/green] {bar(low, total)} {low:3d}",
            f"[yellow]MED [/yellow] {bar(medium, total)} {medium:3d}",
            f"[bold yellow]HIGH[/bold yellow] {bar(high, total)} {high:3d}",
            f"[bold red]CRIT[/bold red] {bar(critical, total)} {critical:3d}",
        ]

        return Panel("\n".join(lines), title="[bold cyan]Threat[/bold cyan]", border_style="cyan")


class SystemStatsWidget(Static):
    """System statistics"""

    system_stats = reactive(dict)

    def render(self) -> Panel:
        stats = self.system_stats
        uptime = time.time() - stats.get('uptime_start', time.time())
        h, m = int(uptime // 3600), int((uptime % 3600) // 60)

        lines = [
            f"[bold]Up:[/bold] {h}h{m}m",
            f"[bold]Conn:[/bold] {stats.get('total_connections', 0)}",
            f"[bold]Rate:[/bold] {stats.get('rate', 0):.1f}/s",
            f"[bold]IPs:[/bold] {stats.get('unique_ips', 0)}",
            f"[bold]Orgs:[/bold] {stats.get('unique_orgs', 0)}",
            f"[bold]Mode:[/bold] {stats.get('density', 'MED')}",
        ]

        return Panel("\n".join(lines), title="[bold blue]Stats[/bold blue]", border_style="blue")


class AlertTickerWidget(Static):
    """Scrolling ticker for critical alerts in the footer area"""

    alerts = reactive(list)
    _scroll_pos = 0
    _ticker_text = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._critical_alerts: List[str] = []
        self._scroll_pos = 0

    def add_alert(self, message: str, severity: str = "HIGH"):
        """Add an alert to the ticker"""
        ts = datetime.now().strftime("%H:%M:%S")
        if severity == "CRITICAL":
            alert_str = f"[bold red]! {ts} CRIT: {message}[/bold red]"
        elif severity == "HIGH":
            alert_str = f"[yellow]~ {ts} HIGH: {message}[/yellow]"
        else:
            alert_str = f"[cyan]* {ts}: {message}[/cyan]"

        self._critical_alerts.append(alert_str)
        # Keep last 10 alerts
        if len(self._critical_alerts) > 10:
            self._critical_alerts = self._critical_alerts[-10:]

    def watch_alerts(self, alerts: List[Dict]) -> None:
        """Update ticker when alerts change"""
        for alert in alerts:
            if alert.get('severity') in ('CRITICAL', 'HIGH'):
                msg = alert.get('message', '')
                if msg and msg not in [a for a in self._critical_alerts]:
                    self.add_alert(msg, alert.get('severity', 'HIGH'))

    def scroll_ticker(self):
        """Advance scroll position for animation"""
        if self._critical_alerts:
            self._scroll_pos = (self._scroll_pos + 1) % max(1, len(self._critical_alerts))

    def render(self) -> Text:
        """Render scrolling ticker"""
        if not self._critical_alerts:
            return Text("◉ Status: Monitoring active | No critical alerts", style="dim cyan")

        # Build ticker string
        separator = "  │  "
        all_alerts = separator.join(self._critical_alerts[-5:])

        # Create scrolling effect by showing a window
        ticker = Text()
        ticker.append("◉ ", style="bold cyan")
        ticker.append_text(Text.from_markup(all_alerts))

        return ticker


class LogoWidget(Static):
    """CobaltGraph ASCII Logo - Static display"""

    def render(self) -> Panel:
        logo = Text()
        # Clean ASCII art logo
        logo.append("┌─────────────────────┐\n", style="cyan")
        logo.append("│", style="cyan")
        logo.append("   C O B A L T       ", style="bold cyan")
        logo.append("│\n", style="cyan")
        logo.append("│", style="cyan")
        logo.append("     G R A P H       ", style="bold blue")
        logo.append("│\n", style="cyan")
        logo.append("├─────────────────────┤\n", style="cyan")
        logo.append("│", style="cyan")
        logo.append("  ◉ ", style="cyan")
        logo.append("4D Recon", style="bold white")
        logo.append("       │\n", style="cyan")
        logo.append("│", style="cyan")
        logo.append("  ◆ ", style="yellow")
        logo.append("Threat Intel", style="dim")
        logo.append("    │\n", style="cyan")
        logo.append("│", style="cyan")
        logo.append("  ▲ ", style="green")
        logo.append("Network Mon", style="dim")
        logo.append("     │\n", style="cyan")
        logo.append("└─────────────────────┘", style="cyan")

        return Panel(
            logo,
            title="",
            border_style="dim cyan",
        )


class AlertFeedWidget(Static):
    """Alert feed"""

    alerts = reactive(list)

    def render(self) -> Panel:
        lines = []
        if not self.alerts:
            lines = ["[dim]No alerts[/dim]"]
        else:
            for alert in self.alerts[:6]:
                ts = alert.get('time', '')
                msg = alert.get('message', '')[:28]
                sev = alert.get('severity', 'INFO')
                style = 'bold red' if sev == 'CRITICAL' else 'yellow' if sev == 'HIGH' else 'cyan'
                icon = '!' if sev == 'CRITICAL' else '~' if sev == 'HIGH' else '*'
                lines.append(f"[{style}]{icon}[/{style}] {ts} {msg}")

        return Panel("\n".join(lines), title="[bold red]Alerts[/bold red]", border_style="red")


class CobaltGraphDashboard(App):
    """
    CobaltGraph Dashboard - Main monitoring interface

    Features:
    - Real-time connection monitoring
    - ASCII globe with connection trails
    - Organization triage matrix
    - Hop count topology
    - Event log viewer
    """

    CSS = """
    #main-table { height: 100%; border: solid cyan; }

    /* Main layout with ticker */
    .main-content { height: 1fr; }
    #alert-ticker { height: 3; dock: bottom; background: $surface; }

    /* Main two-column layout */
    #left-column { width: 55%; }
    #right-column { width: 45%; }

    /* Left column sections */
    #connection-panel { height: 70%; }
    #bottom-left { height: 30%; }

    /* Right column sections */
    #globe-widget { height: 45%; }
    #middle-right { height: 30%; }
    #bottom-right { height: 25%; }

    /* Bottom panels - equal width */
    #org-triage { width: 1fr; }
    #hop-topology { width: 1fr; }
    #threat-matrix { width: 1fr; }
    #alert-widget { width: 1fr; }
    #log-widget { width: 1fr; }
    #system-stats { width: 1fr; }
    #logo-widget { width: 1fr; min-width: 25; }

    Horizontal { height: 1fr; }
    Vertical { height: 1fr; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("a", "alerts", "Alerts"),
        ("g", "toggle_globe", "Globe"),
        ("t", "toggle_density", "Density"),
        ("o", "toggle_org", "Org"),
        ("h", "toggle_hop", "Hop"),
        ("l", "toggle_log", "Log"),
    ]

    def __init__(self, database_path: str = "data/cobaltgraph.db"):
        super().__init__()
        self.database_path = database_path
        self.connections = []
        self.alerts = []
        self.organizations: Dict[str, Dict] = {}
        self.hop_counts: Dict[int, Dict] = {}
        self.stats = {
            'uptime_start': time.time(),
            'total_connections': 0,
            'rate': 0.0,
            'unique_asns': 0,
            'unique_ips': 0,
            'unique_orgs': 0,
            'density': 'MEDIUM',
        }
        self.threat_data = {'total': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0}

        self._last_count = 0
        self._last_max_timestamp = 0.0
        self._data_changed = True
        self._update_count = 0
        self._last_rate_time = time.time()
        self._last_rate_count = 0
        self._auto_density = True

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Vertical(classes="main-content"):
            with Horizontal():
                # Left column - Connection table and bottom panels
                with Vertical(id="left-column"):
                    yield ConnectionTableWidget(id="connection-panel")
                    with Horizontal(id="bottom-left"):
                        yield OrganizationTriageWidget(id="org-triage")
                        yield HopTopologyWidget(id="hop-topology")

                # Right column - Globe, alerts/stats, log/logo
                with Vertical(id="right-column"):
                    yield EnhancedGlobeWidget(width=50, height=18, id="globe-widget")
                    with Horizontal(id="middle-right"):
                        yield AlertFeedWidget(id="alert-widget")
                        yield ThreatMatrixWidget(id="threat-matrix")
                    with Horizontal(id="bottom-right"):
                        yield EventLogWidget(id="log-widget")
                        yield SystemStatsWidget(id="system-stats")
                        yield LogoWidget(id="logo-widget")

        # Alert ticker at bottom
        yield AlertTickerWidget(id="alert-ticker")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "CobaltGraph Dashboard"
        self.sub_title = "Unified Threat Monitoring"

        # Register event log callback for UI events
        try:
            from src.utils.logging_config import UIEventHandler, UIEventPoster
            log_widget = self.query_one("#log-widget", EventLogWidget)
            UIEventHandler.register_callback(log_widget.add_event)
            UIEventPoster.system("Dashboard initialized", "INFO")
        except Exception:
            pass  # UI logging is optional

        self.set_interval(1.0, self.update_data)
        self.set_interval(0.25, self.update_animations)

        self.load_data_from_db()

    def _check_data_changed(self) -> bool:
        try:
            if not Path(self.database_path).exists():
                return False

            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*), MAX(timestamp) FROM connections")
            row = cursor.fetchone()
            conn.close()

            count = row[0] or 0
            max_ts = row[1] or 0.0

            if count != self._last_count or max_ts != self._last_max_timestamp:
                self._last_count = count
                self._last_max_timestamp = max_ts
                return True
            return False
        except Exception:
            return False

    def load_data_from_db(self):
        try:
            if not Path(self.database_path).exists():
                return

            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT timestamp, dst_ip, dst_port, threat_score,
                       dst_country, protocol, dst_lat, dst_lon,
                       dst_asn, dst_asn_name, dst_org, dst_org_type,
                       org_trust_score, ttl_observed, hop_count, dst_cidr,
                       ttl_initial, os_fingerprint
                FROM connections ORDER BY timestamp DESC LIMIT 100
            """)

            rows = cursor.fetchall()
            self.connections = []
            self.alerts = []
            threat_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            unique_ips, unique_asns, unique_orgs = set(), set(), set()

            for row in rows:
                score = row[3] or 0.0
                dst_ip, dst_asn = row[1], row[8]
                dst_org = row[10] or row[9] or ''
                org_trust = row[12] or 0.5
                hop_count = row[14]
                org_type = row[11] or 'unknown'

                unique_ips.add(dst_ip)
                if dst_asn: unique_asns.add(dst_asn)
                if dst_org: unique_orgs.add(dst_org)

                if score >= 0.7: threat_counts['critical'] += 1
                elif score >= 0.5: threat_counts['high'] += 1
                elif score >= 0.3: threat_counts['medium'] += 1
                else: threat_counts['low'] += 1

                # Track organizations
                if dst_org:
                    if dst_org not in self.organizations:
                        self.organizations[dst_org] = {
                            'name': dst_org, 'asn': dst_asn, 'org_type': org_type,
                            'count': 0, 'threat_sum': 0.0, 'trust': org_trust, 'hops': {},
                        }
                    self.organizations[dst_org]['count'] += 1
                    self.organizations[dst_org]['threat_sum'] += score

                # Track hops
                if hop_count:
                    if hop_count not in self.hop_counts:
                        self.hop_counts[hop_count] = {'count': 0, 'threat_sum': 0.0}
                    self.hop_counts[hop_count]['count'] += 1
                    self.hop_counts[hop_count]['threat_sum'] += score

                conn_data = {
                    'timestamp': row[0], 'dst_ip': dst_ip, 'dst_port': row[2],
                    'threat_score': score, 'country': row[4], 'dst_country': row[4],
                    'protocol': row[5], 'dst_lat': row[6], 'dst_lon': row[7],
                    'dst_asn': dst_asn, 'dst_asn_name': row[9], 'dst_org': row[10],
                    'dst_org_type': org_type, 'org_trust_score': org_trust,
                    'ttl_observed': row[13], 'hop_count': hop_count,
                    'dst_cidr': row[15], 'ttl_initial': row[16], 'os_fingerprint': row[17],
                }
                self.connections.append(conn_data)

                # Alerts
                ts_str = datetime.fromtimestamp(row[0]).strftime("%H:%M:%S") if row[0] else "--:--:--"
                if score >= 0.7:
                    self.alerts.append({'time': ts_str, 'message': f"CRIT {dst_ip}:{row[2]}", 'severity': 'CRITICAL'})
                elif org_trust < 0.3:
                    self.alerts.append({'time': ts_str, 'message': f"Untrust: {dst_ip}", 'severity': 'HIGH'})

            self.alerts = self.alerts[:6]

            # Stats
            now = time.time()
            elapsed = now - self._last_rate_time
            if elapsed > 0:
                self.stats['rate'] = max(0, (len(rows) - self._last_rate_count) / elapsed)
            self._last_rate_time = now
            self._last_rate_count = len(rows)

            self.stats['total_connections'] = len(rows)
            self.stats['unique_ips'] = len(unique_ips)
            self.stats['unique_asns'] = len(unique_asns)
            self.stats['unique_orgs'] = len(unique_orgs)

            self.threat_data.update(threat_counts)
            self.threat_data['total'] = len(rows)
            self._data_changed = True

            conn.close()
        except Exception:
            pass

    def update_data(self):
        self._update_count += 1
        if self._check_data_changed() or self._update_count % 5 == 0:
            self.load_data_from_db()

        if not self._data_changed:
            return
        self._data_changed = False

        # Update widgets
        try:
            self.query_one("#connection-panel", ConnectionTableWidget).connections = self.connections
        except: pass

        try:
            self.query_one("#globe-widget", EnhancedGlobeWidget).connections_data = self.connections
        except: pass

        try:
            self.query_one("#alert-widget", AlertFeedWidget).alerts = self.alerts
        except: pass

        try:
            w = self.query_one("#org-triage", OrganizationTriageWidget)
            w.organizations = self.organizations
        except: pass

        try:
            w = self.query_one("#hop-topology", HopTopologyWidget)
            w.hop_counts = self.hop_counts
        except: pass

        try:
            self.query_one("#threat-matrix", ThreatMatrixWidget).threat_data = self.threat_data
        except: pass

        try:
            self.query_one("#system-stats", SystemStatsWidget).system_stats = self.stats
        except: pass

        # Update alert ticker with high/critical alerts
        try:
            ticker = self.query_one("#alert-ticker", AlertTickerWidget)
            for alert in self.alerts:
                if alert.get('severity') in ('CRITICAL', 'HIGH'):
                    ticker.add_alert(alert.get('message', ''), alert.get('severity', 'HIGH'))
        except: pass

    def update_animations(self):
        try:
            globe = self.query_one("#globe-widget", EnhancedGlobeWidget)
            if globe.visible:
                globe.refresh()
        except: pass

        # Scroll ticker
        try:
            ticker = self.query_one("#alert-ticker", AlertTickerWidget)
            ticker.scroll_ticker()
            ticker.refresh()
        except: pass

    def action_refresh(self):
        self._data_changed = True
        self.load_data_from_db()
        self.update_data()
        self.notify("Refreshed!")

    def action_alerts(self):
        crit = len([a for a in self.alerts if a.get('severity') == 'CRITICAL'])
        high = len([a for a in self.alerts if a.get('severity') == 'HIGH'])
        self.notify(f"{crit} CRITICAL, {high} HIGH", title="Alerts")

    def action_toggle_globe(self):
        try:
            w = self.query_one("#globe-widget", EnhancedGlobeWidget)
            w.toggle_visibility()
            self.notify(f"Globe {'shown' if w.visible else 'hidden'}")
        except: pass

    def action_toggle_density(self):
        try:
            w = self.query_one("#connection-panel", ConnectionTableWidget)
            new = w.cycle_density()
            self._auto_density = False
            self.stats['density'] = new.value.upper()
            self.notify(f"Density: {new.value.upper()}")
        except: pass

    def action_toggle_org(self):
        try:
            w = self.query_one("#org-triage", OrganizationTriageWidget)
            w.toggle_visibility()
        except: pass

    def action_toggle_hop(self):
        try:
            w = self.query_one("#hop-topology", HopTopologyWidget)
            w.toggle_visibility()
        except: pass

    def action_toggle_log(self):
        try:
            w = self.query_one("#log-widget", EventLogWidget)
            w.toggle_visibility()
        except: pass

    def on_unmount(self) -> None:
        """Clean up on shutdown"""
        try:
            from src.utils.logging_config import UIEventHandler
            log_widget = self.query_one("#log-widget", EventLogWidget)
            UIEventHandler.unregister_callback(log_widget.add_event)
        except Exception:
            pass


def main():
    app = CobaltGraphDashboard()
    app.run()


if __name__ == '__main__':
    main()
