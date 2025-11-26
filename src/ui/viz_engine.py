#!/usr/bin/env python3
"""
CobaltGraph Multi-Dimensional Visualization Engine
N-Dimensional threat vector projection with advanced rendering

Features:
- Dimensional reduction for threat visualization
- Heatmap with temporal decay
- Organization triage with trust scoring matrix
- Network hop topology with depth visualization
- Parallel coordinate threat analysis
- Time-series anomaly detection visualization
- Braille-based high-resolution rendering
"""

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict
from enum import Enum

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.style import Style

# Try numpy for vector operations
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


# ============================================================================
# VISUALIZATION CONSTANTS
# ============================================================================

# Braille patterns for ultra-high resolution rendering (2x4 dots per char)
BRAILLE_BASE = 0x2800
BRAILLE_DOTS = [
    [0x01, 0x08],
    [0x02, 0x10],
    [0x04, 0x20],
    [0x40, 0x80]
]

# Block elements for heatmap intensity
INTENSITY_CHARS = ' ·░▒▓█'
INTENSITY_LEVELS = len(INTENSITY_CHARS) - 1

# Box drawing for topology visualization
BOX_CHARS = {
    'h': '─', 'v': '│',
    'tl': '┌', 'tr': '┐', 'bl': '└', 'br': '┘',
    'cross': '┼', 'lt': '├', 'rt': '┤', 'top': '┬', 'bot': '┴',
    'arrow_r': '►', 'arrow_l': '◄', 'arrow_u': '▲', 'arrow_d': '▼',
    'dot': '●', 'ring': '○', 'star': '★', 'diamond': '◆',
}

# Threat color spectrum (intensity levels)
THREAT_COLORS = {
    0: 'dim green',      # Safe
    1: 'green',          # Low threat
    2: 'yellow',         # Moderate
    3: 'bold yellow',    # Elevated
    4: 'red',            # High
    5: 'bold red',       # Critical
    6: 'bold magenta',   # Anomaly
}

# Organization type risk coefficients
ORG_TYPE_RISK = {
    'cloud': 0.2,       # AWS, Azure, GCP - generally trusted
    'cdn': 0.15,        # Cloudflare, Akamai - low risk
    'isp': 0.3,         # ISPs - moderate risk
    'hosting': 0.6,     # Hosting providers - elevated risk
    'vpn': 0.7,         # VPN providers - high risk
    'proxy': 0.75,      # Proxy services - very high risk
    'tor': 0.9,         # Tor exit nodes - critical risk
    'unknown': 0.5,     # Unknown organizations
}


class ThreatState(Enum):
    """Threat state enumeration"""
    BASELINE = 0    # Normal baseline
    ELEVATED = 1    # Elevated activity
    MULTIPLE = 2    # Multiple threat vectors active
    CORRELATED = 3  # Correlated with other threats
    CONFIRMED = 4   # Confirmed threat


@dataclass
class ThreatVector:
    """N-dimensional threat vector with analysis properties"""
    dimensions: Dict[str, float] = field(default_factory=dict)
    magnitude: float = 0.0
    phase: float = 0.0  # Temporal phase
    state: ThreatState = ThreatState.BASELINE
    correlated_with: Set[str] = field(default_factory=set)

    def __post_init__(self):
        self.dimensions = self.dimensions or {
            'threat_score': 0.0,
            'org_trust': 1.0,
            'hop_distance': 0.0,
            'port_entropy': 0.0,
            'geo_risk': 0.0,
            'temporal_anomaly': 0.0,
            'asn_reputation': 0.5,
            'connection_velocity': 0.0,
        }
        self._update_magnitude()

    def _update_magnitude(self):
        """Calculate magnitude from dimension values"""
        if NUMPY_AVAILABLE:
            values = np.array(list(self.dimensions.values()))
            self.magnitude = float(np.linalg.norm(values))
        else:
            self.magnitude = math.sqrt(sum(v**2 for v in self.dimensions.values()))

    def project_to_2d(self) -> Tuple[float, float]:
        """Project N-dimensional vector to 2D for visualization"""
        # Use PCA-like projection with predefined principal components
        # PC1: threat_score + geo_risk - org_trust
        # PC2: hop_distance + temporal_anomaly - asn_reputation
        pc1 = (self.dimensions.get('threat_score', 0) +
               self.dimensions.get('geo_risk', 0) -
               self.dimensions.get('org_trust', 0.5))
        pc2 = (self.dimensions.get('hop_distance', 0) / 32.0 +
               self.dimensions.get('temporal_anomaly', 0) -
               self.dimensions.get('asn_reputation', 0.5))
        return (pc1, pc2)

    def collapse(self) -> float:
        """Collapse threat state to single threat score"""
        weights = {
            'threat_score': 0.35,
            'org_trust': -0.20,
            'hop_distance': 0.05,
            'port_entropy': 0.10,
            'geo_risk': 0.15,
            'temporal_anomaly': 0.10,
            'asn_reputation': -0.10,
            'connection_velocity': 0.05,
        }
        score = sum(self.dimensions.get(k, 0) * v for k, v in weights.items())
        return max(0.0, min(1.0, score + 0.5))


@dataclass
class OrganizationTriage:
    """Organization with triage status and trust metrics"""
    name: str
    asn: Optional[int] = None
    org_type: str = 'unknown'
    trust_score: float = 0.5
    connection_count: int = 0
    threat_sum: float = 0.0
    unique_ips: int = 0
    unique_ports: Set[int] = field(default_factory=set)
    hop_distribution: Dict[int, int] = field(default_factory=dict)
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def avg_threat(self) -> float:
        return self.threat_sum / max(1, self.connection_count)

    @property
    def triage_level(self) -> str:
        """Get triage priority level"""
        risk = self.avg_threat * (1.0 - self.trust_score) * ORG_TYPE_RISK.get(self.org_type, 0.5)
        if risk >= 0.6:
            return 'CRITICAL'
        elif risk >= 0.4:
            return 'HIGH'
        elif risk >= 0.2:
            return 'MEDIUM'
        else:
            return 'LOW'

    @property
    def hop_summary(self) -> str:
        """Get hop distribution summary"""
        if not self.hop_distribution:
            return "?"
        avg_hop = sum(h * c for h, c in self.hop_distribution.items()) / max(1, sum(self.hop_distribution.values()))
        return f"{avg_hop:.1f}"


@dataclass
class HopNode:
    """Network hop node for topology visualization"""
    depth: int
    ip: str = ""
    country: str = ""
    asn: Optional[int] = None
    org: str = ""
    threat_score: float = 0.0
    children: List['HopNode'] = field(default_factory=list)


class ThreatHeatmap:
    """
    Heatmap with intensity rendering
    Uses temporal decay for threat visualization
    """

    def __init__(self, width: int = 60, height: int = 20, resolution: float = 5.0):
        self.width = width
        self.height = height
        self.resolution = resolution  # Degrees per cell

        # Heatmap grid: (lat_idx, lon_idx) -> intensity
        self.grid: Dict[Tuple[int, int], float] = {}
        self.temporal_grid: Dict[Tuple[int, int], float] = {}  # Timestamp of last update

        # Decay rate
        self.decay_rate = 0.92

        # Layered rendering (multiple threat dimensions)
        self.layers = {
            'threat': {},
            'velocity': {},
            'anomaly': {},
        }

        # Time tracking
        self.last_update = time.time()

    def add_point(self, lat: float, lon: float, intensity: float,
                  layer: str = 'threat', timestamp: Optional[float] = None):
        """Add a point to the heatmap with blending"""
        lat_idx = int((lat + 90) / self.resolution)
        lon_idx = int((lon + 180) / self.resolution)
        key = (lat_idx, lon_idx)

        ts = timestamp or time.time()

        # Update main grid with blending
        current = self.grid.get(key, 0.0)
        self.grid[key] = min(1.0, current + intensity * 0.5)
        self.temporal_grid[key] = ts

        # Update specific layer
        layer_grid = self.layers.get(layer, {})
        layer_current = layer_grid.get(key, 0.0)
        layer_grid[key] = min(1.0, layer_current + intensity * 0.3)
        self.layers[layer] = layer_grid

    def decay(self):
        """Apply temporal decay"""
        current_time = time.time()
        dt = current_time - self.last_update
        decay_factor = self.decay_rate ** dt

        for key in list(self.grid.keys()):
            self.grid[key] *= decay_factor
            if self.grid[key] < 0.01:
                del self.grid[key]
                self.temporal_grid.pop(key, None)

        for layer in self.layers.values():
            for key in list(layer.keys()):
                layer[key] *= decay_factor
                if layer[key] < 0.01:
                    del layer[key]

        self.last_update = current_time

    def render(self, show_layers: bool = True) -> Text:
        """Render heatmap to Rich Text with threat color mapping"""
        self.decay()

        # Calculate grid bounds for visible data
        lat_cells = int(180 / self.resolution)
        lon_cells = int(360 / self.resolution)

        # Scale to display size
        lat_scale = max(1, lat_cells // self.height)
        lon_scale = max(1, lon_cells // self.width)

        output = Text()

        for y in range(self.height):
            for x in range(self.width):
                # Aggregate intensity for this display cell
                max_intensity = 0.0
                layer_mix = {'threat': 0, 'velocity': 0, 'anomaly': 0}

                for dy in range(lat_scale):
                    for dx in range(lon_scale):
                        lat_idx = (self.height - 1 - y) * lat_scale + dy
                        lon_idx = x * lon_scale + dx
                        key = (lat_idx, lon_idx)

                        intensity = self.grid.get(key, 0.0)
                        max_intensity = max(max_intensity, intensity)

                        # Track which layer contributes most
                        for layer_name, layer_grid in self.layers.items():
                            if key in layer_grid:
                                layer_mix[layer_name] = max(layer_mix[layer_name], layer_grid[key])

                # Select character and color based on intensity
                char_idx = int(max_intensity * INTENSITY_LEVELS)
                char = INTENSITY_CHARS[min(char_idx, INTENSITY_LEVELS)]

                # Determine color from layer mix and intensity
                if max_intensity < 0.1:
                    color = 'dim blue'
                elif layer_mix['anomaly'] > layer_mix['threat']:
                    color = 'magenta' if max_intensity > 0.5 else 'dim magenta'
                elif layer_mix['velocity'] > layer_mix['threat']:
                    color = 'cyan' if max_intensity > 0.5 else 'dim cyan'
                else:
                    color = THREAT_COLORS.get(int(max_intensity * 5), 'white')

                output.append(char, style=color)
            output.append('\n')

        return output


class ThreatGlobe:
    """
    ASCII globe with multi-dimensional threat visualization

    Features:
    - Arc rendering
    - Organization clustering
    - Hop depth visualization
    - Temporal phase animation
    """

    def __init__(self, width: int = 50, height: int = 22):
        self.width = width
        self.height = height

        # Frame buffers
        self.char_buffer: List[List[str]] = []
        self.color_buffer: List[List[str]] = []
        self._init_buffers()

        # Globe state
        self.rotation_y = 0.0
        self.rotation_x = 23.5  # Earth tilt
        self.rotation_speed = 8.0

        # Heatmap layer
        self.heatmap = ThreatHeatmap(width, height)

        # Active connections
        self.connections: List[Dict] = []
        self.max_connections = 40
        self.connection_lifetime = 5.0

        # Organization clusters
        self.org_clusters: Dict[str, OrganizationTriage] = {}

        # Hop topology
        self.hop_tree: Dict[int, List[HopNode]] = defaultdict(list)

        # Animation
        self.last_update = time.time()
        self.frame = 0

        # Arc particles for trail effect
        self.arc_particles: List[Dict] = []

    def _init_buffers(self):
        self.char_buffer = [[' ' for _ in range(self.width)] for _ in range(self.height)]
        self.color_buffer = [['white' for _ in range(self.width)] for _ in range(self.height)]

    def _clear_buffers(self):
        for y in range(self.height):
            for x in range(self.width):
                self.char_buffer[y][x] = ' '
                self.color_buffer[y][x] = 'white'

    def latlon_to_screen(self, lat: float, lon: float) -> Optional[Tuple[int, int, float]]:
        """Convert lat/lon to screen coordinates with depth"""
        lat_rad = math.radians(lat)
        lon_rad = math.radians(lon + self.rotation_y)

        # 3D coordinates
        x = math.cos(lat_rad) * math.cos(lon_rad)
        y = math.cos(lat_rad) * math.sin(lon_rad)
        z = math.sin(lat_rad)

        # Apply tilt
        tilt_rad = math.radians(self.rotation_x)
        z_tilted = z * math.cos(tilt_rad) - y * math.sin(tilt_rad)
        y_tilted = z * math.sin(tilt_rad) + y * math.cos(tilt_rad)

        # Check if visible (facing camera)
        if y_tilted < 0:
            return None

        # Project to screen (orthographic)
        radius = min(self.width // 2, self.height) * 0.8
        sx = int(self.width // 2 + x * radius)
        sy = int(self.height // 2 - z_tilted * radius * 0.5)  # Aspect correction

        if 0 <= sx < self.width and 0 <= sy < self.height:
            return (sx, sy, y_tilted)
        return None

    def add_connection(self, conn: Dict):
        """Add connection with metadata"""
        conn['timestamp'] = time.time()
        conn['phase'] = 0.0
        conn['trail'] = []

        # Update heatmap
        dst_lat = conn.get('dst_lat', 0)
        dst_lon = conn.get('dst_lon', 0)
        threat = conn.get('threat_score', 0)

        if dst_lat and dst_lon:
            self.heatmap.add_point(dst_lat, dst_lon, threat, layer='threat')

        # Update organization cluster
        org_name = conn.get('dst_org') or conn.get('dst_asn_name') or f"AS{conn.get('dst_asn', '?')}"
        if org_name and org_name != 'AS?':
            if org_name not in self.org_clusters:
                self.org_clusters[org_name] = OrganizationTriage(
                    name=org_name,
                    asn=conn.get('dst_asn'),
                    org_type=conn.get('dst_org_type', 'unknown'),
                    first_seen=time.time(),
                )

            cluster = self.org_clusters[org_name]
            cluster.connection_count += 1
            cluster.threat_sum += threat
            cluster.trust_score = conn.get('org_trust_score', 0.5) or 0.5
            cluster.last_seen = time.time()

            if conn.get('dst_port'):
                cluster.unique_ports.add(conn['dst_port'])

            hop_count = conn.get('hop_count')
            if hop_count:
                cluster.hop_distribution[hop_count] = cluster.hop_distribution.get(hop_count, 0) + 1

        # Store connection
        self.connections.append(conn)
        if len(self.connections) > self.max_connections:
            self.connections = self.connections[-self.max_connections:]

    def _render_globe_outline(self):
        """Render globe sphere with glow effect"""
        cx, cy = self.width // 2, self.height // 2
        radius = min(self.width // 2, self.height) * 0.8

        for angle in range(0, 360, 3):
            rad = math.radians(angle)
            x = int(cx + radius * math.cos(rad))
            y = int(cy + radius * 0.5 * math.sin(rad))  # Aspect correction

            if 0 <= x < self.width and 0 <= y < self.height:
                # Pulsing effect
                pulse = math.sin(self.frame * 0.1 + angle * 0.05) * 0.5 + 0.5
                char = '○' if pulse > 0.5 else '·'
                self.char_buffer[y][x] = char
                self.color_buffer[y][x] = 'cyan'

    def _render_grid_lines(self):
        """Render lat/lon grid lines"""
        # Latitude lines
        for lat in range(-60, 90, 30):
            for lon in range(0, 360, 8):
                result = self.latlon_to_screen(lat, lon)
                if result:
                    x, y, _ = result
                    if self.char_buffer[y][x] == ' ':
                        self.char_buffer[y][x] = '·'
                        self.color_buffer[y][x] = 'dim blue'

        # Longitude lines
        for lon in range(-180, 180, 45):
            for lat in range(-80, 85, 8):
                result = self.latlon_to_screen(lat, lon)
                if result:
                    x, y, _ = result
                    if self.char_buffer[y][x] == ' ':
                        self.char_buffer[y][x] = '·'
                        self.color_buffer[y][x] = 'dim blue'

    def _render_heatmap_overlay(self):
        """Render heatmap on globe surface"""
        for (lat_idx, lon_idx), intensity in self.heatmap.grid.items():
            if intensity < 0.15:
                continue

            lat = lat_idx * self.heatmap.resolution - 90
            lon = lon_idx * self.heatmap.resolution - 180

            result = self.latlon_to_screen(lat, lon)
            if result:
                x, y, depth = result
                char_idx = int(intensity * INTENSITY_LEVELS)
                char = INTENSITY_CHARS[min(char_idx, INTENSITY_LEVELS)]
                color = THREAT_COLORS.get(int(intensity * 5), 'yellow')

                self.char_buffer[y][x] = char
                self.color_buffer[y][x] = color

    def _render_connection_arcs(self):
        """Render arc connections with particle trails"""
        current_time = time.time()
        src_lat, src_lon = 39.8, -98.5  # US center

        for conn in self.connections:
            age = current_time - conn.get('timestamp', current_time)
            if age > self.connection_lifetime:
                continue

            dst_lat = conn.get('dst_lat', 0)
            dst_lon = conn.get('dst_lon', 0)
            threat = conn.get('threat_score', 0)

            if not dst_lat and not dst_lon:
                continue

            # Animate progress along arc
            progress = min(1.0, age / (self.connection_lifetime * 0.4))

            # Render arc
            num_points = 8
            for i in range(int(num_points * progress) + 1):
                t = i / num_points

                # Interpolate position
                lat = src_lat + (dst_lat - src_lat) * t
                lon = src_lon + (dst_lon - src_lon) * t

                # Arc height
                arc_height = math.sin(t * math.pi) * 0.08

                # Apply height to latitude (fake 3D effect)
                result = self.latlon_to_screen(lat + arc_height * 20, lon)
                if result:
                    x, y, depth = result

                    # Character based on position and threat
                    if i == int(num_points * progress):
                        char = '●'  # Head
                        color = THREAT_COLORS.get(int(threat * 5), 'yellow')
                    else:
                        fade = i / num_points
                        char = '○' if fade > 0.5 else '·'
                        color = f"dim {THREAT_COLORS.get(int(threat * 4), 'yellow').replace('bold ', '')}"

                    self.char_buffer[y][x] = char
                    self.color_buffer[y][x] = color

            # Render destination marker
            if progress >= 0.9:
                result = self.latlon_to_screen(dst_lat, dst_lon)
                if result:
                    x, y, _ = result
                    pulse = math.sin(current_time * 5) * 0.5 + 0.5
                    char = '◉' if pulse > 0.5 else '●'
                    self.char_buffer[y][x] = char
                    self.color_buffer[y][x] = f"bold {THREAT_COLORS.get(int(threat * 5), 'red')}"

    def _render_local_marker(self, lat: float = 39.8, lon: float = -98.5):
        """Render local system origin marker"""
        result = self.latlon_to_screen(lat, lon)
        if result:
            x, y, _ = result
            self.char_buffer[y][x] = '◆'
            self.color_buffer[y][x] = 'bold cyan'

    def update(self):
        """Update animation state"""
        current_time = time.time()
        dt = current_time - self.last_update
        self.last_update = current_time

        # Rotate globe
        self.rotation_y += self.rotation_speed * dt
        if self.rotation_y >= 360:
            self.rotation_y -= 360

        # Decay heatmap
        self.heatmap.decay()

        # Clean old connections
        self.connections = [c for c in self.connections
                          if current_time - c.get('timestamp', 0) < self.connection_lifetime]

        self.frame += 1

    def render(self) -> Text:
        """Render complete globe frame"""
        self.update()
        self._clear_buffers()

        # Render layers (back to front)
        self._render_grid_lines()
        self._render_heatmap_overlay()
        self._render_connection_arcs()
        self._render_local_marker()
        self._render_globe_outline()

        # Build output
        output = Text()
        for y in range(self.height):
            for x in range(self.width):
                output.append(self.char_buffer[y][x], style=self.color_buffer[y][x])
            output.append('\n')

        return output

    def get_stats(self) -> Dict:
        """Return globe statistics for display overlay"""
        return {
            'rotation': self.rotation_y,
            'rotation_y': self.rotation_y,
            'connections': len(self.connections),
            'active_pings': len(self.connections),
            'heat_zones': len([k for k, v in self.heatmap.grid.items() if v > 0.15]),
            'organizations': len(self.org_clusters),
        }


class OrganizationTriageMatrix:
    """
    Multi-dimensional organization triage visualization
    Shows trust scores, hop counts, threat levels, and connection patterns
    """

    def __init__(self):
        self.organizations: Dict[str, OrganizationTriage] = {}
        self.max_display = 8

    def update(self, org: OrganizationTriage):
        """Update organization data"""
        self.organizations[org.name] = org

    def render(self, width: int = 50) -> Text:
        """Render organization triage matrix"""
        output = Text()

        # Sort by triage priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_orgs = sorted(
            self.organizations.values(),
            key=lambda o: (priority_order.get(o.triage_level, 4), -o.avg_threat)
        )[:self.max_display]

        if not sorted_orgs:
            output.append("[dim]No organizations tracked[/dim]\n")
            return output

        # Header
        output.append("ORG", style="bold cyan")
        output.append(" " * 12)
        output.append("TRIAGE", style="bold")
        output.append(" ")
        output.append("TRUST", style="bold green")
        output.append(" ")
        output.append("HOPS", style="bold yellow")
        output.append(" ")
        output.append("CNT", style="bold")
        output.append("\n")
        output.append("─" * (width - 2) + "\n")

        for org in sorted_orgs:
            # Org name (truncated)
            name = org.name[:14].ljust(14)

            # Triage level with color
            level = org.triage_level
            level_colors = {
                'CRITICAL': 'bold red',
                'HIGH': 'yellow',
                'MEDIUM': 'dim yellow',
                'LOW': 'green',
            }

            # Trust score bar
            trust_bar_len = int(org.trust_score * 5)
            trust_bar = '█' * trust_bar_len + '░' * (5 - trust_bar_len)
            trust_color = 'green' if org.trust_score >= 0.6 else 'yellow' if org.trust_score >= 0.3 else 'red'

            # Hop summary
            hop_str = org.hop_summary.rjust(4)

            # Connection count
            count_str = str(org.connection_count).rjust(3)

            output.append(name, style="cyan")
            output.append(" ")
            output.append(level.ljust(8), style=level_colors.get(level, 'white'))
            output.append(" ")
            output.append(trust_bar, style=trust_color)
            output.append(" ")
            output.append(hop_str, style="yellow")
            output.append(" ")
            output.append(count_str, style="dim")
            output.append("\n")

        return output


class HopTopologyVisualizer:
    """
    Network hop topology tree visualization
    Shows connection depth and routing patterns
    """

    def __init__(self, width: int = 40, height: int = 12):
        self.width = width
        self.height = height
        self.hop_data: Dict[int, Dict] = {}  # hop_count -> {count, avg_threat, countries}

    def add_connection(self, hop_count: int, threat_score: float, country: str = ""):
        """Add connection hop data"""
        if hop_count not in self.hop_data:
            self.hop_data[hop_count] = {
                'count': 0,
                'threat_sum': 0.0,
                'countries': set(),
            }

        self.hop_data[hop_count]['count'] += 1
        self.hop_data[hop_count]['threat_sum'] += threat_score
        if country:
            self.hop_data[hop_count]['countries'].add(country)

    def render(self) -> Text:
        """Render hop distribution visualization"""
        output = Text()

        if not self.hop_data:
            output.append("[dim]No hop data available[/dim]\n")
            return output

        # Calculate max for scaling
        max_count = max(d['count'] for d in self.hop_data.values()) or 1

        # Display range (typical hops 1-32)
        display_hops = sorted([h for h in self.hop_data.keys() if 1 <= h <= 32])

        if not display_hops:
            output.append("[dim]No valid hop data[/dim]\n")
            return output

        output.append("[bold]Network Hop Distribution[/bold]\n")
        output.append("─" * (self.width - 2) + "\n")

        # Horizontal bar chart
        for hop in display_hops[:10]:  # Limit display
            data = self.hop_data[hop]
            count = data['count']
            avg_threat = data['threat_sum'] / max(1, count)

            # Bar length
            bar_len = int((count / max_count) * (self.width - 15))

            # Color based on threat
            if avg_threat >= 0.6:
                color = 'red'
            elif avg_threat >= 0.3:
                color = 'yellow'
            else:
                color = 'green'

            # Format line
            hop_label = f"{hop:2d}h "
            bar = '█' * bar_len
            count_label = f" {count:3d}"

            output.append(hop_label, style="cyan")
            output.append(bar, style=color)
            output.append(count_label, style="dim")
            output.append("\n")

        # Summary
        total_connections = sum(d['count'] for d in self.hop_data.values())
        avg_hops = sum(h * d['count'] for h, d in self.hop_data.items()) / max(1, total_connections)
        output.append(f"\n[dim]Avg hops: {avg_hops:.1f} | Total: {total_connections}[/dim]\n")

        return output


class ParallelCoordinatesThreat:
    """
    Parallel coordinates visualization for multi-dimensional threat analysis
    Each vertical axis represents a threat dimension
    """

    DIMENSIONS = [
        ('threat', 'Threat'),
        ('trust', 'Trust'),
        ('hops', 'Hops'),
        ('ports', 'Ports'),
        ('geo', 'Geo'),
    ]

    def __init__(self, width: int = 60, height: int = 10):
        self.width = width
        self.height = height
        self.data_points: List[Dict] = []
        self.max_points = 20

    def add_point(self, values: Dict[str, float], threat_level: float):
        """Add a data point with dimension values"""
        self.data_points.append({
            'values': values,
            'threat': threat_level,
        })
        if len(self.data_points) > self.max_points:
            self.data_points = self.data_points[-self.max_points:]

    def render(self) -> Text:
        """Render parallel coordinates chart"""
        output = Text()

        if len(self.data_points) < 2:
            output.append("[dim]Insufficient data for parallel coordinates[/dim]\n")
            return output

        num_dims = len(self.DIMENSIONS)
        axis_spacing = self.width // (num_dims + 1)

        # Header with dimension labels
        for i, (key, label) in enumerate(self.DIMENSIONS):
            x_pos = (i + 1) * axis_spacing
            padding = x_pos - len(output) % self.width
            if padding > 0:
                output.append(" " * padding)
            output.append(label[:5], style="bold cyan")
        output.append("\n")

        # Draw axes and connections
        for row in range(self.height):
            line = [' '] * self.width
            colors = ['white'] * self.width

            # Draw vertical axes
            for i in range(num_dims):
                x_pos = min((i + 1) * axis_spacing, self.width - 1)
                line[x_pos] = '│'
                colors[x_pos] = 'dim'

            # Draw data points at this row level
            y_level = 1.0 - (row / (self.height - 1))  # 1.0 at top, 0.0 at bottom

            for point in self.data_points[-8:]:  # Show last 8 points
                values = point['values']
                threat = point['threat']

                # Color based on threat level
                if threat >= 0.7:
                    point_color = 'red'
                elif threat >= 0.4:
                    point_color = 'yellow'
                else:
                    point_color = 'green'

                for i, (key, _) in enumerate(self.DIMENSIONS):
                    val = values.get(key, 0.5)
                    # Check if this value falls at this y level
                    if abs(val - y_level) < 0.15:
                        x_pos = min((i + 1) * axis_spacing, self.width - 1)
                        line[x_pos] = '●'
                        colors[x_pos] = point_color

            for x, (char, color) in enumerate(zip(line, colors)):
                output.append(char, style=color)
            output.append('\n')

        return output


# ============================================================================
# INTEGRATED VISUALIZATION ENGINE
# ============================================================================

class VisualizationEngine:
    """
    Master visualization engine combining all components
    """

    def __init__(self, width: int = 80, height: int = 40):
        self.width = width
        self.height = height

        # Component visualizers
        self.globe = ThreatGlobe(width=50, height=20)
        self.org_triage = OrganizationTriageMatrix()
        self.hop_viz = HopTopologyVisualizer(width=40, height=10)
        self.parallel_coords = ParallelCoordinatesThreat(width=60, height=8)

        # Statistics
        self.total_connections = 0
        self.high_threats = 0
        self.unique_orgs = 0

    def add_connection(self, conn: Dict):
        """Process connection through all visualization components"""
        self.total_connections += 1

        threat_score = conn.get('threat_score', 0)
        if threat_score >= 0.6:
            self.high_threats += 1

        # Update globe
        self.globe.add_connection(conn)

        # Update hop visualization
        hop_count = conn.get('hop_count')
        if hop_count:
            self.hop_viz.add_connection(
                hop_count,
                threat_score,
                conn.get('dst_country', '')
            )

        # Update parallel coordinates
        org_trust = conn.get('org_trust_score', 0.5) or 0.5
        self.parallel_coords.add_point({
            'threat': threat_score,
            'trust': org_trust,
            'hops': (hop_count or 10) / 32.0,
            'ports': 0.5,  # Would need port entropy calculation
            'geo': 0.5,    # Would need geo risk calculation
        }, threat_score)

        # Update org triage
        for org in self.globe.org_clusters.values():
            self.org_triage.update(org)
        self.unique_orgs = len(self.globe.org_clusters)

    def render_globe_panel(self) -> Panel:
        """Render globe with overlay"""
        globe_text = self.globe.render()

        return Panel(
            globe_text,
            title="[bold cyan]◉ Threat Globe[/bold cyan]",
            subtitle=f"[dim]R:{self.globe.rotation_y:.0f}° | P:{len(self.globe.connections)} | T:{self.high_threats}[/dim]",
            border_style="cyan"
        )

    def render_triage_panel(self) -> Panel:
        """Render organization triage matrix"""
        triage_text = self.org_triage.render(width=48)

        return Panel(
            triage_text,
            title="[bold yellow]◆ Organization Triage[/bold yellow]",
            subtitle=f"[dim]{self.unique_orgs} organizations tracked[/dim]",
            border_style="yellow"
        )

    def render_hop_panel(self) -> Panel:
        """Render hop topology visualization"""
        hop_text = self.hop_viz.render()

        return Panel(
            hop_text,
            title="[bold green]▲ Hop Topology[/bold green]",
            border_style="green"
        )

    def render_parallel_panel(self) -> Panel:
        """Render parallel coordinates threat analysis"""
        parallel_text = self.parallel_coords.render()

        return Panel(
            parallel_text,
            title="[bold magenta]≡ Threat Dimensions[/bold magenta]",
            border_style="magenta"
        )

    def get_stats(self) -> Dict:
        """Get visualization statistics"""
        return {
            'total_connections': self.total_connections,
            'active_pings': len(self.globe.connections),
            'high_threats': self.high_threats,
            'unique_orgs': self.unique_orgs,
            'rotation': self.globe.rotation_y,
            'heat_zones': len(self.globe.heatmap.grid),
        }


# Demo mode
if __name__ == '__main__':
    import random

    console = Console()
    engine = VisualizationEngine(width=80, height=40)

    # Test data
    test_orgs = [
        ('Google LLC', 15169, 'cloud', 0.9),
        ('Cloudflare', 13335, 'cdn', 0.85),
        ('DigitalOcean', 14061, 'hosting', 0.4),
        ('Unknown VPN', 0, 'vpn', 0.2),
        ('Tor Exit', 0, 'tor', 0.1),
    ]

    test_locations = [
        (40.7, -74.0),   # NYC
        (51.5, -0.1),    # London
        (35.7, 139.7),   # Tokyo
        (55.8, 37.6),    # Moscow
        (-33.9, 151.2),  # Sydney
    ]

    console.print("[bold cyan]CobaltGraph Visualization Demo[/bold cyan]")
    console.print("Press Ctrl+C to exit\n")

    try:
        for frame in range(1000):
            # Add random connection
            if frame % 5 == 0:
                org = random.choice(test_orgs)
                loc = random.choice(test_locations)

                engine.add_connection({
                    'dst_lat': loc[0] + random.uniform(-5, 5),
                    'dst_lon': loc[1] + random.uniform(-5, 5),
                    'threat_score': random.uniform(0, 1),
                    'org_trust_score': org[3],
                    'dst_org': org[0],
                    'dst_asn': org[1],
                    'dst_org_type': org[2],
                    'hop_count': random.randint(5, 25),
                    'dst_country': random.choice(['US', 'UK', 'JP', 'RU', 'AU']),
                    'dst_port': random.choice([80, 443, 22, 3389, 8080]),
                })

            # Render
            console.clear()
            console.print(engine.render_globe_panel())
            console.print(engine.render_triage_panel())
            console.print(engine.render_hop_panel())

            time.sleep(0.15)

    except KeyboardInterrupt:
        console.print("\n[yellow]Demo stopped[/yellow]")
