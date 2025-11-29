#!/usr/bin/env python3
"""
CobaltGraph ASCII 4D Globe Visualization
High-resolution terminal globe with threat heat mapping, connection pings, and metadata overlay

Features:
- 4D spinning globe (3D rotation + time dimension for animation)
- Braille character rendering for high-resolution ASCII display
- Heat-mapped threat zones by geographic region
- Active connection ping trails with animation
- Real-time metadata overlay
- Threat scoring visualization
"""

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.style import Style


# Braille character mapping for 2x4 dot patterns (high-res ASCII)
# Each braille char represents a 2x4 pixel block
BRAILLE_OFFSET = 0x2800
BRAILLE_MAP = [
    [0x01, 0x08],
    [0x02, 0x10],
    [0x04, 0x20],
    [0x40, 0x80]
]

# Globe characters for different rendering modes
GLOBE_CHARS = {
    'empty': ' ',
    'light': '░',
    'medium': '▒',
    'heavy': '▓',
    'solid': '█',
    'dot': '·',
    'ping': '●',
    'ping_trail': '○',
    'connection': '◉',
}

# Continental landmass approximation (simplified world map)
# Format: (lat_min, lat_max, lon_min, lon_max, region_name)
CONTINENTS = [
    # North America
    (25, 72, -170, -50, "NA"),
    # South America
    (-56, 12, -82, -34, "SA"),
    # Europe
    (36, 71, -10, 40, "EU"),
    # Africa
    (-35, 37, -18, 52, "AF"),
    # Asia
    (5, 77, 40, 180, "AS"),
    # Australia
    (-47, -10, 110, 180, "AU"),
    # Antarctica
    (-90, -60, -180, 180, "AN"),
]

# Major cities for reference points
MAJOR_CITIES = {
    "NYC": (40.7128, -74.0060),
    "London": (51.5074, -0.1278),
    "Tokyo": (35.6762, 139.6503),
    "Sydney": (-33.8688, 151.2093),
    "Moscow": (55.7558, 37.6173),
    "Dubai": (25.2048, 55.2708),
    "Singapore": (1.3521, 103.8198),
    "São Paulo": (-23.5505, -46.6333),
    "Mumbai": (19.0760, 72.8777),
    "Beijing": (39.9042, 116.4074),
}


@dataclass
class ThreatZone:
    """Geographic threat zone with heat score"""
    lat: float
    lon: float
    radius: float  # degrees
    threat_score: float  # 0.0 - 1.0
    connection_count: int = 0
    last_ping: float = 0.0


@dataclass
class ConnectionPing:
    """Active connection ping for visualization"""
    src_lat: float
    src_lon: float
    dst_lat: float
    dst_lon: float
    threat_score: float
    timestamp: float
    metadata: Dict = field(default_factory=dict)
    trail_progress: float = 0.0  # 0.0 - 1.0 for animation


@dataclass
class GlobeState:
    """Current state of the globe visualization"""
    rotation_x: float = 0.0  # Tilt
    rotation_y: float = 0.0  # Spin (primary rotation)
    rotation_z: float = 0.0  # Roll
    time_offset: float = 0.0  # 4th dimension - animation time
    zoom: float = 1.0


class ASCIIGlobe:
    """
    High-resolution ASCII globe renderer with 4D visualization

    Renders a spinning Earth globe using Braille characters for
    maximum terminal resolution, with threat heat mapping and
    connection ping visualization.
    """

    def __init__(self, width: int = 80, height: int = 40):
        """
        Initialize the ASCII globe renderer

        Args:
            width: Terminal width in characters
            height: Terminal height in characters
        """
        self.width = width
        self.height = height
        self.console = Console()

        # Globe state
        self.state = GlobeState()
        self.auto_rotate = True
        self.rotation_speed = 15.0  # degrees per second

        # Threat zones (aggregated by region)
        self.threat_zones: Dict[str, ThreatZone] = {}
        self.region_threat_scores: Dict[str, List[float]] = defaultdict(list)

        # Active connection pings
        self.active_pings: List[ConnectionPing] = []
        self.max_pings = 50
        self.ping_lifetime = 3.0  # seconds

        # Heat map data
        self.heat_grid: Dict[Tuple[int, int], float] = {}
        self.heat_decay = 0.95  # decay factor per frame

        # Frame buffer for double buffering
        self.frame_buffer: List[List[str]] = []
        self.color_buffer: List[List[str]] = []

        # Statistics
        self.total_pings = 0
        self.high_threat_count = 0

        # Last update time for animation
        self.last_update = time.time()

        # Initialize buffers
        self._init_buffers()

    def _init_buffers(self):
        """Initialize frame buffers"""
        self.frame_buffer = [[' ' for _ in range(self.width)] for _ in range(self.height)]
        self.color_buffer = [['white' for _ in range(self.width)] for _ in range(self.height)]

    def _clear_buffers(self):
        """Clear frame buffers for new frame"""
        for y in range(self.height):
            for x in range(self.width):
                self.frame_buffer[y][x] = ' '
                self.color_buffer[y][x] = 'white'

    def latlon_to_3d(self, lat: float, lon: float, radius: float = 1.0) -> Tuple[float, float, float]:
        """
        Convert latitude/longitude to 3D Cartesian coordinates

        Args:
            lat: Latitude in degrees (-90 to 90)
            lon: Longitude in degrees (-180 to 180)
            radius: Sphere radius

        Returns:
            (x, y, z) tuple
        """
        lat_rad = math.radians(lat)
        lon_rad = math.radians(lon)

        x = radius * math.cos(lat_rad) * math.cos(lon_rad)
        y = radius * math.cos(lat_rad) * math.sin(lon_rad)
        z = radius * math.sin(lat_rad)

        return (x, y, z)

    def rotate_point(self, x: float, y: float, z: float) -> Tuple[float, float, float]:
        """
        Apply 3D rotation to a point based on current globe state

        Uses Euler angles for rotation (Y-X-Z order)
        """
        # Rotation around Y axis (main spin)
        cos_y = math.cos(math.radians(self.state.rotation_y))
        sin_y = math.sin(math.radians(self.state.rotation_y))
        x1 = x * cos_y - z * sin_y
        z1 = x * sin_y + z * cos_y

        # Rotation around X axis (tilt)
        cos_x = math.cos(math.radians(self.state.rotation_x))
        sin_x = math.sin(math.radians(self.state.rotation_x))
        y1 = y * cos_x - z1 * sin_x
        z2 = y * sin_x + z1 * cos_x

        # Rotation around Z axis (roll) - usually 0
        cos_z = math.cos(math.radians(self.state.rotation_z))
        sin_z = math.sin(math.radians(self.state.rotation_z))
        x2 = x1 * cos_z - y1 * sin_z
        y2 = x1 * sin_z + y1 * cos_z

        return (x2, y2, z2)

    def project_to_screen(self, x: float, y: float, z: float) -> Optional[Tuple[int, int, float]]:
        """
        Project 3D point to 2D screen coordinates

        Uses orthographic projection with depth for visibility check

        Returns:
            (screen_x, screen_y, depth) or None if behind globe
        """
        # Orthographic projection (simple, works well for globe)
        # Scale to fit screen
        scale = min(self.width, self.height * 2) * 0.4 * self.state.zoom

        screen_x = int(self.width / 2 + x * scale)
        screen_y = int(self.height / 2 - z * scale)  # Invert Z for screen coords

        # Depth for visibility (y axis points into screen)
        depth = y

        # Check bounds
        if 0 <= screen_x < self.width and 0 <= screen_y < self.height:
            return (screen_x, screen_y, depth)
        return None

    def is_point_visible(self, lat: float, lon: float) -> bool:
        """Check if a geographic point is on the visible side of the globe"""
        x, y, z = self.latlon_to_3d(lat, lon)
        x, y, z = self.rotate_point(x, y, z)
        return y > 0  # Positive Y means facing camera

    def get_threat_color(self, score: float) -> str:
        """Get Rich color string for threat score"""
        if score >= 0.8:
            return "bold red"
        elif score >= 0.6:
            return "red"
        elif score >= 0.4:
            return "yellow"
        elif score >= 0.2:
            return "green"
        else:
            return "dim green"

    def get_heat_char(self, intensity: float) -> str:
        """Get character for heat map intensity"""
        if intensity >= 0.8:
            return '█'
        elif intensity >= 0.6:
            return '▓'
        elif intensity >= 0.4:
            return '▒'
        elif intensity >= 0.2:
            return '░'
        else:
            return '·'

    def add_connection(self, src_lat: float, src_lon: float,
                       dst_lat: float, dst_lon: float,
                       threat_score: float, metadata: Optional[Dict] = None):
        """
        Add a new connection to visualize

        Creates a ping animation from source to destination
        """
        ping = ConnectionPing(
            src_lat=src_lat,
            src_lon=src_lon,
            dst_lat=dst_lat,
            dst_lon=dst_lon,
            threat_score=threat_score,
            timestamp=time.time(),
            metadata=metadata or {},
            trail_progress=0.0
        )

        self.active_pings.append(ping)
        self.total_pings += 1

        if threat_score >= 0.6:
            self.high_threat_count += 1

        # Update heat map at destination
        grid_lat = int(dst_lat / 10) * 10
        grid_lon = int(dst_lon / 10) * 10
        key = (grid_lat, grid_lon)
        current_heat = self.heat_grid.get(key, 0.0)
        self.heat_grid[key] = min(1.0, current_heat + threat_score * 0.3)

        # Update regional threat scores
        for lat_min, lat_max, lon_min, lon_max, region in CONTINENTS:
            if lat_min <= dst_lat <= lat_max and lon_min <= dst_lon <= lon_max:
                self.region_threat_scores[region].append(threat_score)
                # Keep only last 100 scores per region
                if len(self.region_threat_scores[region]) > 100:
                    self.region_threat_scores[region] = self.region_threat_scores[region][-100:]
                break

        # Trim old pings
        if len(self.active_pings) > self.max_pings:
            self.active_pings = self.active_pings[-self.max_pings:]

    def update(self, dt: Optional[float] = None):
        """
        Update globe state for animation

        Args:
            dt: Delta time in seconds (auto-calculated if None)
        """
        current_time = time.time()
        if dt is None:
            dt = current_time - self.last_update
        self.last_update = current_time

        # Auto-rotate globe (4D: time-based rotation)
        if self.auto_rotate:
            self.state.rotation_y += self.rotation_speed * dt
            if self.state.rotation_y >= 360:
                self.state.rotation_y -= 360

        # Update time offset (4th dimension)
        self.state.time_offset = current_time

        # Update ping animations
        for ping in self.active_pings:
            age = current_time - ping.timestamp
            if age < self.ping_lifetime:
                # Animate trail progress
                ping.trail_progress = min(1.0, age / (self.ping_lifetime * 0.5))

        # Remove expired pings
        self.active_pings = [p for p in self.active_pings
                            if (current_time - p.timestamp) < self.ping_lifetime]

        # Decay heat map
        for key in list(self.heat_grid.keys()):
            self.heat_grid[key] *= self.heat_decay
            if self.heat_grid[key] < 0.01:
                del self.heat_grid[key]

    def _render_globe_outline(self):
        """Render the globe sphere outline"""
        center_x = self.width // 2
        center_y = self.height // 2
        radius_x = int(min(self.width, self.height * 2) * 0.35 * self.state.zoom)
        radius_y = int(radius_x * 0.5)  # Aspect ratio correction

        # Draw globe edge using ellipse
        for angle in range(0, 360, 2):
            rad = math.radians(angle)
            x = int(center_x + radius_x * math.cos(rad))
            y = int(center_y + radius_y * math.sin(rad))

            if 0 <= x < self.width and 0 <= y < self.height:
                self.frame_buffer[y][x] = '○'
                self.color_buffer[y][x] = 'cyan'

    def _render_latitude_lines(self):
        """Render latitude grid lines on globe"""
        for lat in range(-60, 90, 30):
            for lon in range(0, 360, 5):
                if not self.is_point_visible(lat, lon - 180):
                    continue

                x, y, z = self.latlon_to_3d(lat, lon - 180)
                x, y, z = self.rotate_point(x, y, z)
                result = self.project_to_screen(x, y, z)

                if result:
                    sx, sy, depth = result
                    if self.frame_buffer[sy][sx] == ' ':
                        self.frame_buffer[sy][sx] = '·'
                        self.color_buffer[sy][sx] = 'dim blue'

    def _render_longitude_lines(self):
        """Render longitude grid lines on globe"""
        for lon in range(-180, 180, 30):
            for lat in range(-80, 90, 5):
                if not self.is_point_visible(lat, lon):
                    continue

                x, y, z = self.latlon_to_3d(lat, lon)
                x, y, z = self.rotate_point(x, y, z)
                result = self.project_to_screen(x, y, z)

                if result:
                    sx, sy, depth = result
                    if self.frame_buffer[sy][sx] == ' ':
                        self.frame_buffer[sy][sx] = '·'
                        self.color_buffer[sy][sx] = 'dim blue'

    def _render_continents(self):
        """Render continental landmasses"""
        for lat_min, lat_max, lon_min, lon_max, region in CONTINENTS:
            # Get average threat score for region coloring
            scores = self.region_threat_scores.get(region, [])
            avg_threat = sum(scores) / len(scores) if scores else 0.0

            # Sample points within continent bounds
            lat_step = max(1, (lat_max - lat_min) // 10)
            lon_step = max(1, (lon_max - lon_min) // 15)

            for lat in range(int(lat_min), int(lat_max), lat_step):
                for lon in range(int(lon_min), int(lon_max), lon_step):
                    if not self.is_point_visible(lat, lon):
                        continue

                    x, y, z = self.latlon_to_3d(lat, lon)
                    x, y, z = self.rotate_point(x, y, z)
                    result = self.project_to_screen(x, y, z)

                    if result:
                        sx, sy, depth = result
                        # Color based on threat level
                        if avg_threat > 0.1:
                            char = self.get_heat_char(avg_threat)
                            color = self.get_threat_color(avg_threat)
                        else:
                            char = '░'
                            color = 'green'

                        self.frame_buffer[sy][sx] = char
                        self.color_buffer[sy][sx] = color

    def _render_heat_zones(self):
        """Render heat-mapped threat zones"""
        for (grid_lat, grid_lon), intensity in self.heat_grid.items():
            if intensity < 0.1:
                continue

            # Render zone as cluster of points
            for d_lat in range(-5, 6, 2):
                for d_lon in range(-5, 6, 2):
                    lat = grid_lat + d_lat
                    lon = grid_lon + d_lon

                    if not self.is_point_visible(lat, lon):
                        continue

                    x, y, z = self.latlon_to_3d(lat, lon)
                    x, y, z = self.rotate_point(x, y, z)
                    result = self.project_to_screen(x, y, z)

                    if result:
                        sx, sy, depth = result
                        # Distance-based intensity falloff
                        dist = math.sqrt(d_lat**2 + d_lon**2) / 7.0
                        local_intensity = intensity * (1 - dist)

                        if local_intensity > 0.1:
                            char = self.get_heat_char(local_intensity)
                            color = self.get_threat_color(local_intensity)
                            self.frame_buffer[sy][sx] = char
                            self.color_buffer[sy][sx] = color

    def _render_pings(self):
        """Render active connection pings with animated trails"""
        current_time = time.time()

        for ping in self.active_pings:
            age = current_time - ping.timestamp

            # Interpolate position along arc
            progress = ping.trail_progress

            # Calculate points along great circle arc
            num_trail_points = 5
            for i in range(num_trail_points + 1):
                t = (i / num_trail_points) * progress

                # Linear interpolation (simplified - could use great circle)
                lat = ping.src_lat + (ping.dst_lat - ping.src_lat) * t
                lon = ping.src_lon + (ping.dst_lon - ping.src_lon) * t

                if not self.is_point_visible(lat, lon):
                    continue

                # Add slight altitude for arc effect
                arc_height = 0.05 * math.sin(t * math.pi)
                x, y, z = self.latlon_to_3d(lat, lon, radius=1.0 + arc_height)
                x, y, z = self.rotate_point(x, y, z)
                result = self.project_to_screen(x, y, z)

                if result:
                    sx, sy, depth = result

                    # Head of ping is solid, trail fades
                    if i == num_trail_points:
                        char = '●'
                        color = self.get_threat_color(ping.threat_score)
                    else:
                        fade = (i / num_trail_points)
                        char = '○' if fade > 0.5 else '·'
                        color = 'dim ' + self.get_threat_color(ping.threat_score).replace('bold ', '')

                    self.frame_buffer[sy][sx] = char
                    self.color_buffer[sy][sx] = color

            # Render destination marker
            if progress >= 0.9:
                if self.is_point_visible(ping.dst_lat, ping.dst_lon):
                    x, y, z = self.latlon_to_3d(ping.dst_lat, ping.dst_lon)
                    x, y, z = self.rotate_point(x, y, z)
                    result = self.project_to_screen(x, y, z)

                    if result:
                        sx, sy, _ = result
                        # Pulsing effect based on time
                        pulse = math.sin(current_time * 4) * 0.5 + 0.5
                        char = '◉' if pulse > 0.5 else '●'
                        self.frame_buffer[sy][sx] = char
                        self.color_buffer[sy][sx] = 'bold ' + self.get_threat_color(ping.threat_score)

    def _render_local_marker(self, lat: float = 39.8283, lon: float = -98.5795):
        """Render local system marker (default: US center)"""
        if not self.is_point_visible(lat, lon):
            return

        x, y, z = self.latlon_to_3d(lat, lon)
        x, y, z = self.rotate_point(x, y, z)
        result = self.project_to_screen(x, y, z)

        if result:
            sx, sy, _ = result
            self.frame_buffer[sy][sx] = '◆'
            self.color_buffer[sy][sx] = 'bold cyan'

    def render(self) -> Text:
        """
        Render the complete globe frame

        Returns:
            Rich Text object with the rendered globe
        """
        # Update animation state
        self.update()

        # Clear buffers
        self._clear_buffers()

        # Render layers (back to front)
        self._render_latitude_lines()
        self._render_longitude_lines()
        self._render_continents()
        self._render_heat_zones()
        self._render_pings()
        self._render_local_marker()
        self._render_globe_outline()

        # Build Rich Text output
        output = Text()
        for y in range(self.height):
            for x in range(self.width):
                char = self.frame_buffer[y][x]
                color = self.color_buffer[y][x]
                output.append(char, style=color)
            output.append('\n')

        return output

    def render_with_overlay(self) -> Panel:
        """
        Render globe with metadata overlay panel

        Returns:
            Rich Panel containing globe and stats overlay
        """
        globe_text = self.render()

        # Build overlay text
        overlay_lines = []

        # Rotation info
        overlay_lines.append(f"[cyan]◐ Rotation:[/cyan] {self.state.rotation_y:.1f}°")
        overlay_lines.append(f"[cyan]⟳ Speed:[/cyan] {self.rotation_speed:.0f}°/s")
        overlay_lines.append("")

        # Connection stats
        overlay_lines.append(f"[yellow]● Active Pings:[/yellow] {len(self.active_pings)}")
        overlay_lines.append(f"[green]↑ Total Tracked:[/green] {self.total_pings}")
        overlay_lines.append(f"[red]⚠ High Threats:[/red] {self.high_threat_count}")
        overlay_lines.append("")

        # Regional threat summary
        overlay_lines.append("[bold]Regional Threats:[/bold]")
        for region in ["NA", "EU", "AS", "SA", "AF", "AU"]:
            scores = self.region_threat_scores.get(region, [])
            if scores:
                avg = sum(scores) / len(scores)
                bar_width = int(avg * 10)
                bar = '█' * bar_width + '░' * (10 - bar_width)
                color = self.get_threat_color(avg)
                overlay_lines.append(f"[{color}]{region}[/{color}] [{color}]{bar}[/{color}] {avg:.2f}")

        overlay_lines.append("")

        # Heat zones
        hot_zones = sorted(self.heat_grid.items(), key=lambda x: x[1], reverse=True)[:3]
        if hot_zones:
            overlay_lines.append("[bold red]Hot Zones:[/bold red]")
            for (lat, lon), heat in hot_zones:
                overlay_lines.append(f"  [{self.get_threat_color(heat)}]({lat:+.0f}°, {lon:+.0f}°) {heat:.2f}[/{self.get_threat_color(heat)}]")

        overlay_lines.append("")

        # Recent connections with org/hop data
        if self.active_pings:
            overlay_lines.append("[bold magenta]Recent Connections:[/bold magenta]")
            for ping in list(self.active_pings)[-3:]:  # Last 3
                meta = ping.metadata
                org = meta.get('org', '') or f"AS{meta.get('asn', '?')}" if meta.get('asn') else ""
                org_type = meta.get('org_type', '')[:8] if meta.get('org_type') else ""
                hops = f"{meta.get('hops')}h" if meta.get('hops') else ""
                ip = meta.get('ip', 'Unknown')[:15]
                threat_color = self.get_threat_color(ping.threat_score)

                # Format: IP [org] type hops
                line_parts = [f"[{threat_color}]{ip}[/{threat_color}]"]
                if org:
                    line_parts.append(f"[cyan]{org[:12]}[/cyan]")
                if org_type:
                    line_parts.append(f"[dim]{org_type}[/dim]")
                if hops:
                    line_parts.append(f"[yellow]{hops}[/yellow]")

                overlay_lines.append("  " + " ".join(line_parts))

        overlay = "\n".join(overlay_lines)

        # Combine globe and overlay
        combined = Text()
        globe_lines = str(globe_text).split('\n')
        overlay_lines_split = overlay.split('\n')

        for i, line in enumerate(globe_lines):
            combined.append(line)
            # Add overlay on the right side
            if i < len(overlay_lines_split):
                padding = max(0, self.width - len(line))
                combined.append(' ' * padding)
                combined.append_text(Text.from_markup(overlay_lines_split[i]))
            combined.append('\n')

        return Panel(
            combined,
            title="[bold cyan]🌐 CobaltGraph 4D Threat Globe[/bold cyan]",
            subtitle="[dim]◀ ▶ rotate | ↑↓ tilt | +/- zoom | SPACE pause[/dim]",
            border_style="cyan"
        )

    def get_stats_summary(self) -> Dict:
        """Get current visualization statistics"""
        return {
            'rotation': self.state.rotation_y,
            'active_pings': len(self.active_pings),
            'total_pings': self.total_pings,
            'high_threats': self.high_threat_count,
            'heat_zones': len(self.heat_grid),
            'regions_tracked': len(self.region_threat_scores)
        }


class GlobeWidget:
    """
    Textual-compatible widget wrapper for the ASCII Globe

    Integrates with the CobaltGraph Enhanced Terminal UI
    """

    def __init__(self, width: int = 60, height: int = 25):
        self.globe = ASCIIGlobe(width=width, height=height)
        self.globe.state.rotation_x = 23.5  # Earth's axial tilt

    def add_connection_from_data(self, connection: Dict):
        """
        Add connection from CobaltGraph data format

        Args:
            connection: Dict with dst_lat, dst_lon, threat_score, org data, etc.
        """
        # Source is local system (approximate center of US)
        src_lat, src_lon = 39.8283, -98.5795

        dst_lat = connection.get('dst_lat', 0.0)
        dst_lon = connection.get('dst_lon', 0.0)
        threat_score = connection.get('threat_score', 0.0)

        # Include ASN/org/hop data in metadata for display
        org_display = connection.get('dst_org') or connection.get('dst_asn_name') or ""
        if connection.get('dst_asn') and not org_display:
            org_display = f"AS{connection.get('dst_asn')}"

        metadata = {
            'ip': connection.get('dst_ip', 'Unknown'),
            'port': connection.get('dst_port', 0),
            'country': connection.get('dst_country') or connection.get('country', 'Unknown'),
            'protocol': connection.get('protocol', 'TCP'),
            # ASN/Organization data
            'asn': connection.get('dst_asn'),
            'org': org_display,
            'org_type': connection.get('dst_org_type', ''),
            # Hop detection
            'hops': connection.get('hop_count'),
            'os': connection.get('os_fingerprint'),
            'trust': connection.get('org_trust_score'),
        }

        self.globe.add_connection(
            src_lat, src_lon,
            dst_lat, dst_lon,
            threat_score,
            metadata
        )

    def render(self) -> Panel:
        """Render the globe widget"""
        return self.globe.render_with_overlay()

    def update(self):
        """Update animation state"""
        self.globe.update()


# Demo/test mode
if __name__ == '__main__':
    import random

    console = Console()
    globe = ASCIIGlobe(width=70, height=30)
    globe.state.rotation_x = 23.5  # Earth tilt

    # Add some test connections
    test_destinations = [
        (40.7128, -74.0060, 0.8, "NYC"),
        (51.5074, -0.1278, 0.5, "London"),
        (35.6762, 139.6503, 0.3, "Tokyo"),
        (-33.8688, 151.2093, 0.6, "Sydney"),
        (55.7558, 37.6173, 0.9, "Moscow"),
        (25.2048, 55.2708, 0.4, "Dubai"),
    ]

    console.print("[bold cyan]CobaltGraph 4D ASCII Globe Demo[/bold cyan]")
    console.print("Press Ctrl+C to exit\n")

    try:
        frame = 0
        while True:
            # Add random connection periodically
            if frame % 30 == 0:
                dest = random.choice(test_destinations)
                globe.add_connection(
                    39.8283, -98.5795,  # US center
                    dest[0], dest[1],
                    dest[2],
                    {'city': dest[3]}
                )

            # Render and display
            console.clear()
            panel = globe.render_with_overlay()
            console.print(panel)

            time.sleep(0.1)
            frame += 1

    except KeyboardInterrupt:
        console.print("\n[yellow]Globe demo stopped[/yellow]")
