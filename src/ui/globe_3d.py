#!/usr/bin/env python3
"""
CobaltGraph 3D Globe Visualization with Matplotlib

Renders a true 3D globe with:
- Landmass outlines and continental shapes
- Threat heatmaps with geographic accuracy
- Connection arcs with great-circle paths
- Sixel output for modern terminal rendering
- Fallback to ASCII for unsupported terminals

Requirements:
- matplotlib>=3.9.0
- numpy>=2.1.0
- cartopy (optional, for detailed coastlines)
"""

import math
import io
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

# Check for matplotlib
try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    from mpl_toolkits.mplot3d import Axes3D
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Check for sixel support
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


def check_sixel_support() -> bool:
    """Check if terminal supports sixel graphics"""
    term = os.environ.get('TERM', '')
    term_program = os.environ.get('TERM_PROGRAM', '')

    # Known sixel-supporting terminals
    sixel_terminals = ['xterm', 'mlterm', 'yaft', 'wezterm', 'foot', 'contour']
    sixel_programs = ['iTerm.app', 'WezTerm', 'Contour', 'mintty']

    if any(t in term.lower() for t in sixel_terminals):
        return True
    if any(p in term_program for p in sixel_programs):
        return True

    # Check COLORTERM for modern terminals
    colorterm = os.environ.get('COLORTERM', '')
    if 'truecolor' in colorterm or '24bit' in colorterm:
        # Might support sixel - try a test
        return False  # Be conservative

    return False


SIXEL_SUPPORTED = check_sixel_support()


# Simplified continent outlines (lat, lon pairs for polygon vertices)
# These are approximate for performance
CONTINENT_OUTLINES = {
    'north_america': [
        (72, -170), (72, -100), (60, -95), (50, -125), (48, -123),
        (32, -117), (25, -110), (20, -105), (15, -90), (10, -85),
        (10, -80), (25, -80), (30, -82), (45, -65), (50, -55),
        (60, -45), (65, -40), (72, -60), (72, -170)
    ],
    'south_america': [
        (12, -70), (5, -80), (-5, -80), (-15, -75), (-25, -70),
        (-35, -70), (-45, -75), (-55, -70), (-55, -65), (-50, -60),
        (-35, -55), (-25, -45), (-5, -35), (5, -50), (10, -60), (12, -70)
    ],
    'europe': [
        (72, -10), (72, 40), (65, 45), (55, 60), (45, 40),
        (35, 35), (35, -10), (40, -10), (45, 0), (50, 5),
        (55, 10), (60, 5), (65, -5), (72, -10)
    ],
    'africa': [
        (37, -10), (35, 35), (30, 35), (15, 50), (10, 45),
        (-5, 40), (-15, 40), (-25, 35), (-35, 20), (-35, 15),
        (-30, 30), (-15, 15), (5, -5), (15, -20), (35, -10), (37, -10)
    ],
    'asia': [
        (72, 40), (72, 180), (65, 180), (55, 165), (45, 145),
        (35, 140), (30, 120), (20, 110), (5, 105), (-10, 120),
        (10, 100), (25, 90), (30, 80), (25, 65), (35, 50),
        (45, 40), (55, 60), (65, 45), (72, 40)
    ],
    'australia': [
        (-10, 115), (-20, 115), (-35, 115), (-40, 145), (-35, 155),
        (-25, 155), (-15, 145), (-10, 140), (-10, 115)
    ],
}

# Major cities for reference markers
MAJOR_CITIES = {
    'New York': (40.7, -74.0),
    'London': (51.5, -0.1),
    'Tokyo': (35.7, 139.7),
    'Sydney': (-33.9, 151.2),
    'Moscow': (55.8, 37.6),
    'Dubai': (25.2, 55.3),
    'Singapore': (1.3, 103.8),
    'São Paulo': (-23.6, -46.6),
    'Mumbai': (19.1, 72.9),
    'Beijing': (39.9, 116.4),
    'Lagos': (6.5, 3.4),
    'Cairo': (30.0, 31.2),
}


@dataclass
class GlobeConnection:
    """Connection to visualize on globe"""
    src_lat: float
    src_lon: float
    dst_lat: float
    dst_lon: float
    threat_score: float
    timestamp: float
    metadata: Dict = field(default_factory=dict)


class Globe3D:
    """
    3D Globe renderer using Matplotlib

    Features:
    - True 3D sphere with rotation
    - Continental outlines
    - Threat heatmap overlay
    - Great-circle connection arcs
    - Sixel or ASCII output
    """

    def __init__(self, width: int = 80, height: int = 40, dpi: int = 10):
        self.width = width
        self.height = height
        self.dpi = dpi

        # Figure size in inches
        self.fig_width = width / dpi
        self.fig_height = height / dpi

        # Globe state
        self.rotation_y = 0.0  # Longitude rotation
        self.rotation_x = 23.5  # Tilt (Earth's axial tilt)
        self.rotation_speed = 10.0  # Degrees per second

        # Data
        self.connections: List[GlobeConnection] = []
        self.max_connections = 50
        self.connection_lifetime = 8.0

        # Heatmap grid (10-degree cells)
        self.heat_grid: Dict[Tuple[int, int], float] = {}
        self.heat_decay = 0.95

        # Animation state
        self.last_update = time.time()
        self.frame = 0

        # Cached sphere mesh
        self._sphere_x = None
        self._sphere_y = None
        self._sphere_z = None
        self._init_sphere_mesh()

    def _init_sphere_mesh(self, resolution: int = 30):
        """Pre-calculate sphere mesh for performance"""
        u = np.linspace(0, 2 * np.pi, resolution)
        v = np.linspace(0, np.pi, resolution)

        self._sphere_x = np.outer(np.cos(u), np.sin(v))
        self._sphere_y = np.outer(np.sin(u), np.sin(v))
        self._sphere_z = np.outer(np.ones(np.size(u)), np.cos(v))

    def latlon_to_3d(self, lat: float, lon: float, radius: float = 1.0) -> Tuple[float, float, float]:
        """Convert lat/lon to 3D Cartesian coordinates"""
        lat_rad = np.radians(lat)
        lon_rad = np.radians(lon + self.rotation_y)

        x = radius * np.cos(lat_rad) * np.cos(lon_rad)
        y = radius * np.cos(lat_rad) * np.sin(lon_rad)
        z = radius * np.sin(lat_rad)

        return (x, y, z)

    def add_connection(self, src_lat: float, src_lon: float,
                       dst_lat: float, dst_lon: float,
                       threat_score: float, metadata: Optional[Dict] = None):
        """Add a connection to visualize"""
        conn = GlobeConnection(
            src_lat=src_lat,
            src_lon=src_lon,
            dst_lat=dst_lat,
            dst_lon=dst_lon,
            threat_score=threat_score,
            timestamp=time.time(),
            metadata=metadata or {}
        )

        self.connections.append(conn)

        # Update heatmap at destination
        grid_lat = int(dst_lat / 10) * 10
        grid_lon = int(dst_lon / 10) * 10
        key = (grid_lat, grid_lon)
        current = self.heat_grid.get(key, 0.0)
        self.heat_grid[key] = min(1.0, current + threat_score * 0.3)

        # Trim old connections
        if len(self.connections) > self.max_connections:
            self.connections = self.connections[-self.max_connections:]

    def update(self, dt: Optional[float] = None):
        """Update animation state"""
        current_time = time.time()
        if dt is None:
            dt = current_time - self.last_update
        self.last_update = current_time

        # Rotate globe
        self.rotation_y += self.rotation_speed * dt
        if self.rotation_y >= 360:
            self.rotation_y -= 360

        # Clean old connections
        self.connections = [c for c in self.connections
                          if current_time - c.timestamp < self.connection_lifetime]

        # Decay heatmap
        for key in list(self.heat_grid.keys()):
            self.heat_grid[key] *= self.heat_decay
            if self.heat_grid[key] < 0.01:
                del self.heat_grid[key]

        self.frame += 1

    def _get_threat_color(self, score: float) -> str:
        """Get color for threat score"""
        if score >= 0.8:
            return '#ff0000'  # Red
        elif score >= 0.6:
            return '#ff6600'  # Orange
        elif score >= 0.4:
            return '#ffff00'  # Yellow
        elif score >= 0.2:
            return '#00ff00'  # Green
        else:
            return '#00ffff'  # Cyan

    def _draw_great_circle_arc(self, ax, src_lat: float, src_lon: float,
                                dst_lat: float, dst_lon: float,
                                color: str, num_points: int = 20):
        """Draw a great circle arc between two points"""
        # Convert to radians
        lat1, lon1 = np.radians(src_lat), np.radians(src_lon + self.rotation_y)
        lat2, lon2 = np.radians(dst_lat), np.radians(dst_lon + self.rotation_y)

        # Interpolate along great circle
        d = np.arccos(np.sin(lat1) * np.sin(lat2) +
                     np.cos(lat1) * np.cos(lat2) * np.cos(lon2 - lon1))

        if d < 0.001:  # Same point
            return

        xs, ys, zs = [], [], []
        for i in range(num_points + 1):
            f = i / num_points
            A = np.sin((1 - f) * d) / np.sin(d)
            B = np.sin(f * d) / np.sin(d)

            x = A * np.cos(lat1) * np.cos(lon1) + B * np.cos(lat2) * np.cos(lon2)
            y = A * np.cos(lat1) * np.sin(lon1) + B * np.cos(lat2) * np.sin(lon2)
            z = A * np.sin(lat1) + B * np.sin(lat2)

            # Add altitude for arc effect
            arc_height = 0.1 * np.sin(f * np.pi)
            norm = np.sqrt(x**2 + y**2 + z**2)
            x *= (1 + arc_height) / norm
            y *= (1 + arc_height) / norm
            z *= (1 + arc_height) / norm

            # Only add if on visible side
            if y > -0.2:  # Slightly behind is okay
                xs.append(x)
                ys.append(y)
                zs.append(z)

        if len(xs) > 1:
            ax.plot(xs, ys, zs, color=color, linewidth=1.5, alpha=0.8)

    def render_matplotlib(self) -> Optional[bytes]:
        """Render globe using matplotlib, return PNG bytes"""
        if not MATPLOTLIB_AVAILABLE:
            return None

        self.update()

        # Create figure
        fig = plt.figure(figsize=(self.fig_width, self.fig_height),
                        facecolor='black', dpi=self.dpi * 8)
        ax = fig.add_subplot(111, projection='3d', facecolor='black')

        # Set view angle
        ax.view_init(elev=self.rotation_x, azim=0)

        # Draw sphere wireframe
        ax.plot_wireframe(self._sphere_x, self._sphere_y, self._sphere_z,
                         color='#1a3a5a', linewidth=0.3, alpha=0.5)

        # Draw continental outlines
        for continent, outline in CONTINENT_OUTLINES.items():
            xs, ys, zs = [], [], []
            for lat, lon in outline:
                x, y, z = self.latlon_to_3d(lat, lon, radius=1.01)
                if y > -0.1:  # Only visible side
                    xs.append(x)
                    ys.append(y)
                    zs.append(z)
            if len(xs) > 2:
                ax.plot(xs, ys, zs, color='#2ecc71', linewidth=1.0, alpha=0.7)

        # Draw heatmap points
        for (grid_lat, grid_lon), intensity in self.heat_grid.items():
            if intensity < 0.1:
                continue
            x, y, z = self.latlon_to_3d(grid_lat, grid_lon, radius=1.02)
            if y > 0:  # Only visible side
                color = self._get_threat_color(intensity)
                ax.scatter([x], [y], [z], c=color, s=intensity * 50, alpha=0.6)

        # Draw connection arcs
        current_time = time.time()
        for conn in self.connections:
            age = current_time - conn.timestamp
            if age > self.connection_lifetime:
                continue

            progress = min(1.0, age / (self.connection_lifetime * 0.5))
            color = self._get_threat_color(conn.threat_score)

            self._draw_great_circle_arc(
                ax, conn.src_lat, conn.src_lon,
                conn.dst_lat, conn.dst_lon,
                color=color
            )

            # Draw destination marker
            if progress >= 0.5:
                x, y, z = self.latlon_to_3d(conn.dst_lat, conn.dst_lon, radius=1.03)
                if y > 0:
                    ax.scatter([x], [y], [z], c=color, s=30, marker='o', alpha=0.9)

        # Draw origin marker (US center)
        x, y, z = self.latlon_to_3d(39.8, -98.5, radius=1.02)
        ax.scatter([x], [y], [z], c='cyan', s=50, marker='D')

        # Set axis properties
        ax.set_xlim([-1.3, 1.3])
        ax.set_ylim([-1.3, 1.3])
        ax.set_zlim([-1.3, 1.3])
        ax.set_axis_off()

        # Tight layout
        plt.tight_layout(pad=0)

        # Render to bytes
        buf = io.BytesIO()
        fig.savefig(buf, format='png', facecolor='black',
                   bbox_inches='tight', pad_inches=0)
        plt.close(fig)

        buf.seek(0)
        return buf.read()

    def render_ascii(self, width: int = 60, height: int = 25) -> str:
        """Render globe as ASCII art (fallback)"""
        self.update()

        # Character buffer
        buffer = [[' ' for _ in range(width)] for _ in range(height)]

        cx, cy = width // 2, height // 2
        radius = min(width // 2, height) * 0.8

        # Draw globe outline
        for angle in range(0, 360, 3):
            rad = math.radians(angle)
            x = int(cx + radius * math.cos(rad))
            y = int(cy + radius * 0.5 * math.sin(rad))
            if 0 <= x < width and 0 <= y < height:
                buffer[y][x] = '○'

        # Draw grid lines
        for lat in range(-60, 90, 30):
            for lon in range(0, 360, 10):
                lat_rad = math.radians(lat)
                lon_rad = math.radians(lon + self.rotation_y)

                x3d = math.cos(lat_rad) * math.cos(lon_rad)
                y3d = math.cos(lat_rad) * math.sin(lon_rad)
                z3d = math.sin(lat_rad)

                if y3d > 0:  # Visible side
                    sx = int(cx + x3d * radius)
                    sy = int(cy - z3d * radius * 0.5)
                    if 0 <= sx < width and 0 <= sy < height and buffer[sy][sx] == ' ':
                        buffer[sy][sx] = '·'

        # Draw heatmap zones
        for (grid_lat, grid_lon), intensity in self.heat_grid.items():
            if intensity < 0.1:
                continue

            lat_rad = math.radians(grid_lat)
            lon_rad = math.radians(grid_lon + self.rotation_y)

            x3d = math.cos(lat_rad) * math.cos(lon_rad)
            y3d = math.cos(lat_rad) * math.sin(lon_rad)
            z3d = math.sin(lat_rad)

            if y3d > 0:
                sx = int(cx + x3d * radius)
                sy = int(cy - z3d * radius * 0.5)
                if 0 <= sx < width and 0 <= sy < height:
                    if intensity >= 0.7:
                        buffer[sy][sx] = '█'
                    elif intensity >= 0.4:
                        buffer[sy][sx] = '▓'
                    else:
                        buffer[sy][sx] = '░'

        # Draw connection trails
        current_time = time.time()
        for conn in self.connections[-20:]:
            age = current_time - conn.timestamp
            if age > self.connection_lifetime:
                continue

            progress = min(1.0, age / (self.connection_lifetime * 0.5))

            # Draw arc points
            for i in range(int(10 * progress)):
                t = i / 10
                lat = conn.src_lat + (conn.dst_lat - conn.src_lat) * t
                lon = conn.src_lon + (conn.dst_lon - conn.src_lon) * t

                lat_rad = math.radians(lat)
                lon_rad = math.radians(lon + self.rotation_y)

                x3d = math.cos(lat_rad) * math.cos(lon_rad)
                y3d = math.cos(lat_rad) * math.sin(lon_rad)
                z3d = math.sin(lat_rad)

                if y3d > 0:
                    sx = int(cx + x3d * radius)
                    sy = int(cy - z3d * radius * 0.5)
                    if 0 <= sx < width and 0 <= sy < height:
                        if i == int(10 * progress) - 1:
                            buffer[sy][sx] = '●'
                        else:
                            buffer[sy][sx] = '○'

        # Draw origin marker
        lat_rad = math.radians(39.8)
        lon_rad = math.radians(-98.5 + self.rotation_y)
        x3d = math.cos(lat_rad) * math.cos(lon_rad)
        y3d = math.cos(lat_rad) * math.sin(lon_rad)
        z3d = math.sin(lat_rad)

        if y3d > 0:
            sx = int(cx + x3d * radius)
            sy = int(cy - z3d * radius * 0.5)
            if 0 <= sx < width and 0 <= sy < height:
                buffer[sy][sx] = '◆'

        return '\n'.join(''.join(row) for row in buffer)

    def render(self, use_sixel: bool = True) -> str:
        """Render globe, using sixel if available"""
        if use_sixel and MATPLOTLIB_AVAILABLE and PIL_AVAILABLE and SIXEL_SUPPORTED:
            png_data = self.render_matplotlib()
            if png_data:
                return self._png_to_sixel(png_data)

        # Fallback to ASCII
        return self.render_ascii()

    def _png_to_sixel(self, png_data: bytes) -> str:
        """Convert PNG to sixel escape sequence"""
        try:
            img = Image.open(io.BytesIO(png_data))
            img = img.convert('P', palette=Image.ADAPTIVE, colors=256)

            # Simple sixel conversion (basic implementation)
            # For production, use libsixel or python-sixel
            width, height = img.size
            pixels = list(img.getdata())
            palette = img.getpalette()

            # Start sixel sequence
            output = '\x1bPq'

            # Add palette
            for i in range(256):
                if palette:
                    r = palette[i * 3] * 100 // 255
                    g = palette[i * 3 + 1] * 100 // 255
                    b = palette[i * 3 + 2] * 100 // 255
                    output += f'#{i};2;{r};{g};{b}'

            # Add pixel data (simplified)
            for y in range(0, height, 6):
                for color in range(256):
                    row_data = ''
                    for x in range(width):
                        sixel_val = 0
                        for dy in range(6):
                            if y + dy < height:
                                idx = (y + dy) * width + x
                                if idx < len(pixels) and pixels[idx] == color:
                                    sixel_val |= (1 << dy)
                        if sixel_val:
                            row_data += chr(63 + sixel_val)
                        else:
                            row_data += '?'
                    if any(c != '?' for c in row_data):
                        output += f'#{color}{row_data}$'
                output += '-'

            output += '\x1b\\'
            return output

        except Exception:
            return self.render_ascii()

    def get_stats(self) -> Dict:
        """Get current visualization statistics"""
        return {
            'rotation': self.rotation_y,
            'connections': len(self.connections),
            'heat_zones': len(self.heat_grid),
            'frame': self.frame,
            'matplotlib': MATPLOTLIB_AVAILABLE,
            'sixel': SIXEL_SUPPORTED,
        }


# Demo mode
if __name__ == '__main__':
    import random

    globe = Globe3D(width=80, height=40)

    test_locations = [
        (40.7, -74.0),   # NYC
        (51.5, -0.1),    # London
        (35.7, 139.7),   # Tokyo
        (55.8, 37.6),    # Moscow
        (-33.9, 151.2),  # Sydney
    ]

    print("\033[2J")  # Clear screen
    print("CobaltGraph 3D Globe Demo")
    print(f"Matplotlib: {MATPLOTLIB_AVAILABLE}, Sixel: {SIXEL_SUPPORTED}")
    print("Press Ctrl+C to exit\n")

    try:
        for frame in range(500):
            if frame % 10 == 0:
                loc = random.choice(test_locations)
                globe.add_connection(
                    39.8, -98.5,  # US center
                    loc[0] + random.uniform(-5, 5),
                    loc[1] + random.uniform(-5, 5),
                    random.uniform(0.2, 0.9)
                )

            print("\033[H", end='')  # Home cursor
            print(globe.render(use_sixel=False))  # ASCII for demo

            stats = globe.get_stats()
            print(f"\nRotation: {stats['rotation']:.0f}° | Connections: {stats['connections']} | Heat zones: {stats['heat_zones']}")

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\nDemo stopped")
