#!/usr/bin/env python3
"""
CobaltGraph ASCII Visual Globe
True ASCII art rendering of a rotating threat globe with visible continents,
animated threat markers, and connection flows.

This is a simplified, visual-first implementation that prioritizes
seeing an actual globe on screen over advanced features.
"""

import math
import time
from collections import deque
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


@dataclass
class ThreatMarker:
    """A threat event marker on the globe"""
    lat: float
    lon: float
    threat: float
    age: float = 0.0
    lifetime: float = 4.0
    org_type: str = "unknown"

    def is_alive(self) -> bool:
        return self.age < self.lifetime

    def get_intensity(self) -> float:
        """0.0 (dead) to 1.0 (newborn)"""
        return max(0.0, 1.0 - (self.age / self.lifetime))

    def get_char(self) -> str:
        """Get character based on threat level and intensity"""
        intensity = self.get_intensity()

        if self.threat >= 0.8:
            return "●" if intensity > 0.5 else "◐"
        elif self.threat >= 0.6:
            return "◉" if intensity > 0.5 else "◌"
        elif self.threat >= 0.4:
            return "○" if intensity > 0.3 else "·"
        else:
            return "·"

    def get_color(self) -> str:
        """Get color based on threat level"""
        if self.threat >= 0.8:
            return "bold red"
        elif self.threat >= 0.6:
            return "red"
        elif self.threat >= 0.4:
            return "yellow"
        elif self.threat >= 0.2:
            return "dim yellow"
        else:
            return "green"


@dataclass
class ConnectionLine:
    """Animated line between two threat locations"""
    src_lat: float
    src_lon: float
    dst_lat: float
    dst_lon: float
    threat: float
    age: float = 0.0
    lifetime: float = 3.0

    def is_alive(self) -> bool:
        return self.age < self.lifetime

    def get_progress(self) -> float:
        """0.0 to 1.0"""
        return self.age / self.lifetime

    def get_current_position(self) -> Tuple[float, float]:
        """Get position along line"""
        progress = self.get_progress()
        lat = self.src_lat + (self.dst_lat - self.src_lat) * progress
        lon = self.src_lon + (self.dst_lon - self.src_lon) * progress
        return (lat, lon)


class ASCIIVisualGlobe:
    """
    ASCII Art globe with real visual representation
    Draws continents, threat markers, and connection lines
    """

    def __init__(self, width: int = 80, height: int = 25):
        self.width = width
        self.height = height
        self.rotation = 0.0
        self.rotation_speed = 0.5  # degrees per update

        # Threat markers and connections
        self.markers: deque = deque(maxlen=30)
        self.connections: deque = deque(maxlen=20)

        # Canvas
        self.canvas: List[List[str]] = []
        self._init_canvas()

        # Statistics
        self.total_threats = 0
        self.critical_count = 0

    def _init_canvas(self):
        """Initialize empty canvas"""
        self.canvas = [[' ' for _ in range(self.width)] for _ in range(self.height)]

    def _clear_canvas(self):
        """Clear canvas for next frame"""
        self.canvas = [[' ' for _ in range(self.width)] for _ in range(self.height)]

    def latlon_to_screen(self, lat: float, lon: float) -> Optional[Tuple[int, int]]:
        """
        Convert latitude/longitude to screen coordinates
        Accounts for globe rotation
        """
        # Apply rotation
        rotated_lon = lon + self.rotation
        if rotated_lon > 180:
            rotated_lon -= 360
        if rotated_lon < -180:
            rotated_lon += 360

        # Only show front hemisphere
        if rotated_lon < -90 or rotated_lon > 90:
            return None

        # Convert to screen coordinates
        # Latitude: -90 to 90 → top to bottom
        # Longitude: -90 to 90 → left to right (only visible side)

        x = int((rotated_lon + 90) / 180 * (self.width - 1))
        y = int((90 - lat) / 180 * (self.height - 1))

        # Bounds check
        if 0 <= x < self.width and 0 <= y < self.height:
            return (x, y)
        return None

    def _draw_continents(self):
        """Draw simplified continent outlines using ASCII art"""
        # Simplified coastlines (lat, lon) for major landmasses
        continents = [
            # North America
            [(70, -170), (70, -100), (50, -95), (40, -120), (25, -110), (20, -90)],
            # South America
            [(10, -75), (0, -70), (-20, -65), (-40, -70), (-50, -75)],
            # Europe
            [(60, -10), (70, 0), (70, 40), (50, 45), (40, -10)],
            # Africa
            [(35, -10), (35, 50), (0, 55), (-15, 50), (-35, 20)],
            # Asia
            [(70, 40), (70, 180), (50, 150), (35, 100), (25, 90), (30, 50)],
            # Australia
            [(-10, 110), (-10, 155), (-40, 155), (-40, 110)],
        ]

        # Draw continents as lines
        for continent in continents:
            for i in range(len(continent) - 1):
                lat1, lon1 = continent[i]
                lat2, lon2 = continent[i + 1]
                self._draw_line(lat1, lon1, lat2, lon2, "▓")

    def _draw_line(self, lat1: float, lon1: float, lat2: float, lon2: float, char: str):
        """Draw line between two lat/lon points"""
        steps = 20
        for i in range(steps + 1):
            t = i / steps
            lat = lat1 + (lat2 - lat1) * t
            lon = lon1 + (lon2 - lon1) * t

            pos = self.latlon_to_screen(lat, lon)
            if pos:
                x, y = pos
                self.canvas[y][x] = char

    def _draw_grid(self):
        """Draw latitude/longitude grid"""
        # Draw equator
        for lon in range(-90, 91, 10):
            pos = self.latlon_to_screen(0, lon)
            if pos:
                x, y = pos
                if self.canvas[y][x] == ' ':
                    self.canvas[y][x] = '·'

        # Draw prime meridian
        for lat in range(-90, 91, 10):
            pos = self.latlon_to_screen(lat, 0)
            if pos:
                x, y = pos
                if self.canvas[y][x] == ' ':
                    self.canvas[y][x] = '·'

    def add_threat(self, lat: float, lon: float, threat: float, org_type: str = "unknown"):
        """Add a new threat marker"""
        marker = ThreatMarker(lat=lat, lon=lon, threat=threat, org_type=org_type)
        self.markers.append(marker)
        self.total_threats += 1
        if threat >= 0.7:
            self.critical_count += 1

    def add_connection(self, src_lat: float, src_lon: float,
                      dst_lat: float, dst_lon: float, threat: float):
        """Add a connection line between two points"""
        conn = ConnectionLine(src_lat, src_lon, dst_lat, dst_lon, threat)
        self.connections.append(conn)

    def update(self, dt: float = 0.1):
        """Update animation state"""
        # Rotate globe
        self.rotation += self.rotation_speed

        # Update markers
        alive_markers = deque(maxlen=30)
        for marker in self.markers:
            marker.age += dt
            if marker.is_alive():
                alive_markers.append(marker)
        self.markers = alive_markers

        # Update connections
        alive_connections = deque(maxlen=20)
        for conn in self.connections:
            conn.age += dt
            if conn.is_alive():
                alive_connections.append(conn)
        self.connections = alive_connections

    def _draw_markers(self):
        """Draw threat markers on globe"""
        for marker in self.markers:
            pos = self.latlon_to_screen(marker.lat, marker.lon)
            if pos:
                x, y = pos
                char = marker.get_char()
                color = marker.get_color()

                # Store with color info
                if char != ' ':
                    self.canvas[y][x] = f"[{color}]{char}[/{color}]"

    def _draw_connections(self):
        """Draw connection lines on globe"""
        for conn in self.connections:
            lat, lon = conn.get_current_position()
            pos = self.latlon_to_screen(lat, lon)

            if pos:
                x, y = pos
                progress = conn.get_progress()

                if progress < 0.5:
                    char = "→"
                    color = "bold yellow"
                else:
                    char = "•"
                    color = "dim yellow"

                if self.canvas[y][x] == ' ':
                    self.canvas[y][x] = f"[{color}]{char}[/{color}]"

    def render(self) -> Panel:
        """Render globe to Panel"""
        self._clear_canvas()

        # Draw globe features
        self._draw_continents()
        self._draw_grid()
        self._draw_connections()
        self._draw_markers()

        # Convert canvas to text
        lines = []
        for row in self.canvas:
            line = ''.join(row)
            lines.append(line)

        content = '\n'.join(lines)

        # Add statistics footer
        stats = f"\n[dim]Rotation: {self.rotation:.0f}° | Threats: {self.total_threats} | Critical: {self.critical_count} | Active: {len(self.markers)}[/dim]"

        return Panel(
            content + stats,
            title="[bold cyan]🌐 THREAT GLOBE[/bold cyan]",
            border_style="cyan",
            expand=False
        )


class SimpleGlobeRenderer:
    """
    Wrapper that provides a simple but visual globe
    Falls back gracefully
    """

    def __init__(self, width: int = 80, height: int = 25):
        self.globe = ASCIIVisualGlobe(width, height)

    def add_connection(self, src_lat: float, src_lon: float,
                      dst_lat: float, dst_lon: float,
                      threat: float, confidence: float = 0.8,
                      organization: str = "unknown"):
        """Add connection to globe"""
        # Add threat marker at destination
        self.globe.add_threat(dst_lat, dst_lon, threat, organization)

        # Add connection line
        self.globe.add_connection(src_lat, src_lon, dst_lat, dst_lon, threat)

    def update(self, dt: float = 0.1):
        """Update animation"""
        self.globe.update(dt)

    def render(self) -> Panel:
        """Render to panel"""
        return self.globe.render()
