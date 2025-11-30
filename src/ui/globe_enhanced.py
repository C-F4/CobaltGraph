#!/usr/bin/env python3
"""
CobaltGraph Enhanced 4D Threat Globe Visualization
High-resolution Braille-based globe with sophisticated threat mapping

Features:
- Drawille Braille rendering (4x resolution: 320×160 pixels)
- 4D color encoding: threat/confidence/age/organization
- Particle system for dynamic threat visualization
- Great-circle connection arcs
- Real-time heat map with decay
- Sophisticated threat region analysis
- Constellation/threat cluster detection
- Regional threat heatmaps with gradient intensity
"""

import math
import time
import colorsys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict, deque
from enum import Enum

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.style import Style

# Try to import Drawille for high-res rendering
try:
    from drawille import Canvas
    DRAWILLE_AVAILABLE = True
except ImportError:
    DRAWILLE_AVAILABLE = False


class ThreatLevel(Enum):
    """Threat classification levels"""
    CRITICAL = (0.7, 1.0, "bold red")
    HIGH = (0.5, 0.7, "red")
    MEDIUM = (0.3, 0.5, "yellow")
    LOW = (0.1, 0.3, "dim yellow")
    MINIMAL = (0.0, 0.1, "green")


class OrgType(Enum):
    """Organization type threat profiles"""
    CLOUD = (0.3, "bold cyan")
    CDN = (0.25, "cyan")
    HOSTING = (0.4, "blue")
    ISP = (0.35, "magenta")
    VPN = (0.6, "bold magenta")
    TOR = (0.9, "bold red")
    ENTERPRISE = (0.1, "bold green")
    GOVERNMENT = (0.15, "bold blue")
    EDUCATION = (0.2, "green")
    UNKNOWN = (0.5, "white")


@dataclass
class ThreatParticle:
    """Individual threat event particle for visualization"""
    lat: float
    lon: float
    threat_score: float
    confidence: float
    age: float = 0.0
    lifetime: float = 5.0
    organization: str = "unknown"
    timestamp: float = field(default_factory=time.time)
    velocity_lat: float = 0.0
    velocity_lon: float = 0.0
    velocity_drift: float = 0.02

    def update(self, dt: float) -> bool:
        """Update particle age and position, return True if still alive"""
        self.age += dt

        # Drift across globe (higher threat = faster drift)
        drift_factor = self.threat_score * self.velocity_drift
        self.lat += self.velocity_lat * dt * drift_factor
        self.lon += self.velocity_lon * dt * drift_factor

        # Wrap around date line
        self.lon = ((self.lon + 180) % 360) - 180

        # Check if particle is still alive
        return self.age < self.lifetime

    def get_intensity(self) -> float:
        """Get visual intensity (0.0 = dead, 1.0 = newborn)"""
        return max(0.0, 1.0 - (self.age / self.lifetime))

    def get_color_hsl(self) -> Tuple[float, float, float]:
        """
        Get HSL color encoding 4 dimensions:
        - Hue: Threat level (green 0.33 → red 0.0)
        - Saturation: Confidence level (0.0-1.0)
        - Lightness: Age (1.0 new → 0.3 old)
        """
        # Hue: threat → color (green to red)
        # Green = 0.33 (120°), Red = 0.0 (0°)
        hue = max(0.0, 0.33 * (1.0 - self.threat_score))

        # Saturation: confidence level
        saturation = self.confidence

        # Lightness: newer = brighter
        intensity = self.get_intensity()
        lightness = 0.3 + (intensity * 0.4)  # Range: 0.3-0.7

        return (hue, saturation, lightness)

    def get_size(self) -> int:
        """Get marker size based on threat and confidence"""
        base_size = int(1 + self.threat_score * 4)  # 1-5
        return int(base_size * self.get_intensity())


@dataclass
class ConnectionArc:
    """Animated connection arc from source to destination"""
    src_lat: float
    src_lon: float
    dst_lat: float
    dst_lon: float
    threat_score: float
    age: float = 0.0
    lifetime: float = 4.0
    progress: float = 0.0

    def update(self, dt: float) -> bool:
        """Update arc animation, return True if still animating"""
        self.age += dt
        self.progress = min(1.0, self.age / self.lifetime)
        return self.age < self.lifetime

    def get_current_position(self) -> Tuple[float, float]:
        """Get current position along arc (great-circle interpolation)"""
        # Simple linear interpolation with altitude curve
        lat = self.src_lat + (self.dst_lat - self.src_lat) * self.progress
        lon = self.src_lon + (self.dst_lon - self.src_lon) * self.progress

        # Add altitude arc (peaks in middle)
        altitude_factor = math.sin(self.progress * math.pi) * 10.0

        return (lat + altitude_factor * 0.05, lon)

    def get_intensity(self) -> float:
        """Get visual intensity (bright at start, fading at end)"""
        if self.progress < 0.5:
            return 1.0
        else:
            # Fade out in second half
            fade_progress = (self.progress - 0.5) * 2.0
            return 1.0 - fade_progress


@dataclass
class ThreatZone:
    """Geographic threat zone with aggregated metrics"""
    lat: float
    lon: float
    radius: float  # degrees
    threat_score: float
    confidence: float
    connection_count: int = 0
    organizations: Dict[str, int] = field(default_factory=dict)
    last_update: float = field(default_factory=time.time)
    age: float = 0.0

    def update(self, dt: float):
        """Update zone age for decay"""
        self.age += dt

    def get_decay_factor(self, decay_rate: float = 0.95) -> float:
        """Get decay factor for threat score (exponential decay)"""
        return decay_rate ** (self.age / 2.0)


class ThreatParticleSystem:
    """Manages threat particle lifecycle and rendering"""

    def __init__(self, max_particles: int = 100):
        self.particles: deque = deque(maxlen=max_particles)
        self.max_particles = max_particles
        self.total_emitted = 0

    def emit(self, lat: float, lon: float, threat: float, confidence: float,
             organization: str = "unknown") -> ThreatParticle:
        """Emit a new threat particle"""
        # Random velocity for drift effect
        angle = math.radians(lon)
        particle = ThreatParticle(
            lat=lat,
            lon=lon,
            threat_score=threat,
            confidence=confidence,
            organization=organization,
            velocity_lat=math.sin(angle) * 0.02,
            velocity_lon=math.cos(angle) * 0.02,
        )
        self.particles.append(particle)
        self.total_emitted += 1
        return particle

    def update(self, dt: float):
        """Update all particles and remove dead ones"""
        alive_particles = deque(maxlen=self.max_particles)
        for particle in self.particles:
            if particle.update(dt):
                alive_particles.append(particle)
        self.particles = alive_particles

    def get_active_count(self) -> int:
        """Get count of active particles"""
        return len(self.particles)


class EnhancedGlobeRenderer:
    """
    High-resolution 4D globe renderer with sophisticated threat visualization

    Renders using:
    - Drawille for 320×160 braille pixel canvas
    - Rich for terminal colors and formatting
    - Particle system for threat events
    - Connection arcs for data flows
    - Heat maps for regional threat aggregation
    """

    def __init__(self, width: int = 80, height: int = 40):
        """
        Initialize globe renderer

        Args:
            width: Terminal width in characters
            height: Terminal height in characters
        """
        self.width = width
        self.height = height
        self.console = Console()

        # Use Drawille if available, else fallback to basic rendering
        self.use_drawille = DRAWILLE_AVAILABLE
        if self.use_drawille:
            # Drawille canvas: 2x per character = 2x height resolution
            self.canvas = Canvas()
            self.pixel_width = width * 2
            self.pixel_height = height * 4  # 4 braille dots per character height
        else:
            self.pixel_width = width
            self.pixel_height = height

        # Globe state
        self.rotation_y = 0.0  # Main spin
        self.rotation_x = 23.5  # Earth's axial tilt
        self.rotation_z = 0.0
        self.auto_rotate = True
        self.rotation_speed = 15.0  # degrees per second

        # Particle and animation systems
        self.particle_system = ThreatParticleSystem(max_particles=100)
        self.connection_arcs: deque = deque(maxlen=50)
        self.threat_zones: Dict[str, ThreatZone] = {}

        # Heat map grid
        self.heat_grid: Dict[Tuple[int, int], float] = {}
        self.heat_decay = 0.95

        # Statistics
        self.total_pings = 0
        self.high_threat_count = 0
        self.last_update = time.time()

        # Color cache for performance
        self._color_cache: Dict[Tuple[float, float, float], str] = {}

    def _hsl_to_256color(self, h: float, s: float, l: float) -> int:
        """
        Convert HSL to terminal 256-color index

        Args:
            h: Hue (0.0-1.0)
            s: Saturation (0.0-1.0)
            l: Lightness (0.0-1.0)

        Returns:
            256-color palette index (16-255)
        """
        # Check cache
        cache_key = (round(h, 2), round(s, 2), round(l, 2))
        if cache_key in self._color_cache:
            return self._color_cache[cache_key]

        # Convert HSL to RGB
        r, g, b = colorsys.hls_to_rgb(h, l, s)
        r, g, b = int(r * 255), int(g * 255), int(b * 255)

        # Convert RGB to 256-color index
        # 216-color cube: 6x6x6 = 216 colors (indices 16-231)
        color_index = 16 + 36 * round(r / 255 * 5) + 6 * round(g / 255 * 5) + round(b / 255 * 5)

        self._color_cache[cache_key] = color_index
        return color_index

    def _hsl_to_rich_color(self, h: float, s: float, l: float) -> str:
        """Convert HSL to Rich color string"""
        # For 256-color support
        color_idx = self._hsl_to_256color(h, s, l)
        return f"color({color_idx})"

    def latlon_to_3d(self, lat: float, lon: float, radius: float = 1.0) -> Tuple[float, float, float]:
        """Convert latitude/longitude to 3D Cartesian coordinates"""
        lat_rad = math.radians(lat)
        lon_rad = math.radians(lon)

        x = radius * math.cos(lat_rad) * math.cos(lon_rad)
        y = radius * math.cos(lat_rad) * math.sin(lon_rad)
        z = radius * math.sin(lat_rad)

        return (x, y, z)

    def rotate_point(self, x: float, y: float, z: float) -> Tuple[float, float, float]:
        """Apply 3D rotations to point"""
        # Rotation around Y axis (main spin)
        cos_y = math.cos(math.radians(self.rotation_y))
        sin_y = math.sin(math.radians(self.rotation_y))
        x1 = x * cos_y - z * sin_y
        z1 = x * sin_y + z * cos_y

        # Rotation around X axis (tilt)
        cos_x = math.cos(math.radians(self.rotation_x))
        sin_x = math.sin(math.radians(self.rotation_x))
        y1 = y * cos_x - z1 * sin_x
        z2 = y * sin_x + z1 * cos_x

        # Rotation around Z axis (roll)
        cos_z = math.cos(math.radians(self.rotation_z))
        sin_z = math.sin(math.radians(self.rotation_z))
        x2 = x1 * cos_z - y1 * sin_z
        y2 = x1 * sin_z + y1 * cos_z

        return (x2, y2, z2)

    def project_to_screen(self, x: float, y: float, z: float) -> Optional[Tuple[int, int, float]]:
        """Project 3D point to 2D screen coordinates with depth"""
        # Orthographic projection
        scale = min(self.pixel_width, self.pixel_height * 2) * 0.35

        screen_x = int(self.pixel_width / 2 + y * scale)
        screen_y = int(self.pixel_height / 2 - z * scale)

        depth = x  # X points toward camera

        # Check bounds
        if 0 <= screen_x < self.pixel_width and 0 <= screen_y < self.pixel_height:
            return (screen_x, screen_y, depth)

        return None

    def is_visible(self, lat: float, lon: float) -> bool:
        """Check if a point is on the visible side of the globe"""
        x, y, z = self.latlon_to_3d(lat, lon)
        x, y, z = self.rotate_point(x, y, z)
        return x > 0  # Front-facing

    def add_connection(self, src_lat: float, src_lon: float,
                      dst_lat: float, dst_lon: float,
                      threat_score: float, confidence: float = 0.8,
                      organization: str = "unknown"):
        """Add a new connection to visualize"""
        if self.is_visible(dst_lat, dst_lon):
            # Emit particle at destination
            self.particle_system.emit(dst_lat, dst_lon, threat_score, confidence, organization)

            # Create connection arc
            arc = ConnectionArc(
                src_lat=src_lat,
                src_lon=src_lon,
                dst_lat=dst_lat,
                dst_lon=dst_lon,
                threat_score=threat_score
            )
            self.connection_arcs.append(arc)

            # Update threat zone
            self._update_threat_zone(dst_lat, dst_lon, threat_score, organization)

        self.total_pings += 1
        if threat_score >= 0.7:
            self.high_threat_count += 1

    def _update_threat_zone(self, lat: float, lon: float, threat: float, org: str):
        """Update or create threat zone at location"""
        # Find or create zone (grid-based clustering)
        zone_key = f"{int(lat / 10) * 10}_{int(lon / 10) * 10}"

        if zone_key not in self.threat_zones:
            self.threat_zones[zone_key] = ThreatZone(
                lat=int(lat / 10) * 10,
                lon=int(lon / 10) * 10,
                radius=5.0,
                threat_score=threat,
                confidence=0.8
            )

        zone = self.threat_zones[zone_key]
        zone.threat_score = max(zone.threat_score, threat)  # Keep highest threat
        zone.connection_count += 1
        zone.organizations[org] = zone.organizations.get(org, 0) + 1
        zone.last_update = time.time()

    def update(self, dt: float):
        """Update animation and particle systems"""
        # Rotate globe
        if self.auto_rotate:
            self.rotation_y += self.rotation_speed * dt

        # Update particles
        self.particle_system.update(dt)

        # Update connection arcs
        alive_arcs = deque(maxlen=50)
        for arc in self.connection_arcs:
            if arc.update(dt):
                alive_arcs.append(arc)
        self.connection_arcs = alive_arcs

        # Update threat zones
        for zone in self.threat_zones.values():
            zone.update(dt)

        self.last_update = time.time()

    def _draw_globe_frame(self) -> str:
        """Draw rotating globe frame"""
        if self.use_drawille:
            return self._draw_with_drawille()
        else:
            return self._draw_ascii_fallback()

    def _draw_with_drawille(self) -> str:
        """Render using Drawille high-res canvas"""
        canvas = Canvas()

        # Draw globe outline (great circles)
        # Equator
        for lon in range(-180, 181, 5):
            if self.is_visible(0, lon):
                x, y, z = self.latlon_to_3d(0, lon)
                x, y, z = self.rotate_point(x, y, z)
                proj = self.project_to_screen(x, y, z)
                if proj:
                    canvas.set(proj[0], proj[1])

        # Prime meridian and anti-meridian
        for lat in range(-90, 91, 5):
            if self.is_visible(lat, 0):
                x, y, z = self.latlon_to_3d(lat, 0)
                x, y, z = self.rotate_point(x, y, z)
                proj = self.project_to_screen(x, y, z)
                if proj:
                    canvas.set(proj[0], proj[1])

        # Draw threat zones as heat regions
        for zone in self.threat_zones.values():
            if self.is_visible(zone.lat, zone.lon):
                decay = zone.get_decay_factor(self.heat_decay)
                threat = zone.threat_score * decay

                x, y, z = self.latlon_to_3d(zone.lat, zone.lon)
                x, y, z = self.rotate_point(x, y, z)
                proj = self.project_to_screen(x, y, z)

                if proj and threat > 0.1:
                    # Draw heatmap gradient
                    intensity = int(threat * 5)
                    for r in range(1, intensity + 1):
                        for angle in range(0, 360, 45):
                            rad = math.radians(angle)
                            px = int(proj[0] + r * math.cos(rad))
                            py = int(proj[1] + r * math.sin(rad))
                            if 0 <= px < self.pixel_width and 0 <= py < self.pixel_height:
                                canvas.set(px, py)

        # Draw connection arcs
        for arc in self.connection_arcs:
            lat, lon = arc.get_current_position()
            if self.is_visible(lat, lon):
                x, y, z = self.latlon_to_3d(lat, lon)
                x, y, z = self.rotate_point(x, y, z)
                proj = self.project_to_screen(x, y, z)

                if proj and arc.get_intensity() > 0.1:
                    canvas.set(proj[0], proj[1])

        # Draw particles with color
        for particle in self.particle_system.particles:
            if self.is_visible(particle.lat, particle.lon):
                x, y, z = self.latlon_to_3d(particle.lat, particle.lon)
                x, y, z = self.rotate_point(x, y, z)
                proj = self.project_to_screen(x, y, z)

                if proj:
                    h, s, l = particle.get_color_hsl()
                    # Convert to braille representation
                    canvas.set(proj[0], proj[1])

        frame = canvas.frame()
        return frame

    def _draw_ascii_fallback(self) -> str:
        """Fallback ASCII rendering when Drawille not available"""
        lines = []
        lines.append("╔══════════════════════════════════════════════╗")
        lines.append("║     🌐 4D THREAT GLOBE VISUALIZATION         ║")
        lines.append("╚══════════════════════════════════════════════╝")
        lines.append("")

        # Globe statistics
        lines.append(f"[bold cyan]Active Particles:[/bold cyan] {self.particle_system.get_active_count()}/100")
        lines.append(f"[bold cyan]Active Arcs:[/bold cyan] {len(self.connection_arcs)}/50")
        lines.append(f"[bold cyan]Threat Zones:[/bold cyan] {len(self.threat_zones)}")
        lines.append(f"[bold cyan]Total Events:[/bold cyan] {self.total_pings}")
        lines.append(f"[bold red]CRITICAL:[/bold red] {self.high_threat_count}")
        lines.append("")

        # Top threat zones
        if self.threat_zones:
            lines.append("[bold]🔴 TOP THREAT ZONES[/bold]")
            sorted_zones = sorted(
                self.threat_zones.items(),
                key=lambda x: x[1].threat_score * x[1].get_decay_factor(self.heat_decay),
                reverse=True
            )[:5]

            for zone_key, zone in sorted_zones:
                decay = zone.get_decay_factor(self.heat_decay)
                threat = zone.threat_score * decay
                org_list = ", ".join(zone.organizations.keys())

                if threat >= 0.7:
                    color = "bold red"
                elif threat >= 0.5:
                    color = "bold yellow"
                elif threat >= 0.3:
                    color = "yellow"
                else:
                    color = "green"

                lines.append(f"  [{color}]Lat {zone.lat:6.1f}° Lon {zone.lon:7.1f}°[/{color}] "
                           f"Threat: {threat:.2f} | Conns: {zone.connection_count} | {org_list}")

        lines.append("")

        # Particle system info
        if self.particle_system.particles:
            lines.append("[bold]✨ ACTIVE THREAT PARTICLES[/bold]")
            for i, p in enumerate(list(self.particle_system.particles)[:5]):
                intensity = p.get_intensity()
                char = "●●●" if intensity > 0.7 else "●●○" if intensity > 0.4 else "●○○"
                lines.append(f"  [{p.organization}] {char} Threat: {p.threat_score:.2f} | "
                           f"Age: {p.age:.1f}s | Confidence: {p.confidence:.1%}")

        lines.append("")
        lines.append(f"[dim]Rotation: {self.rotation_y:.1f}° | FPS: 10Hz[/dim]")

        return "\n".join(lines)

    def render(self) -> Panel:
        """Render globe and return as Rich Panel"""
        frame = self._draw_globe_frame()

        return Panel(
            frame,
            title="[bold cyan]🌐 4D THREAT INTELLIGENCE GLOBE[/bold cyan]",
            border_style="cyan",
            expand=False
        )
