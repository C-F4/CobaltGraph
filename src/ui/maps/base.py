"""
Base Map Class
==============

Abstract base class defining the interface for all map implementations.
Provides common functionality for threat visualization, unknown location
tracking, and coordinate conversion.

All map types (flat, rotating globe, simple globe) inherit from this class
to ensure consistent behavior across the UI.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Tuple, List, Dict, Set
from collections import deque

from rich.panel import Panel

from .utils import (
    int_to_roman,
    get_threat_char,
    get_threat_color,
    get_org_color,
    normalize_coordinates,
    is_unknown_location,
)

logger = logging.getLogger(__name__)


@dataclass
class ThreatMarker:
    """
    Represents a threat marker on the map.

    Attributes:
        lat: Latitude coordinate
        lon: Longitude coordinate
        threat_score: Threat level from 0.0 (safe) to 1.0 (critical)
        org_type: Organization type (cloud, isp, tor, etc.)
        ip: IP address string
        age: Time since marker was added (for fade effects)
    """
    lat: float
    lon: float
    threat_score: float
    org_type: str = "unknown"
    ip: str = ""
    age: float = 0.0

    @property
    def char(self) -> str:
        """Get display character for this threat level."""
        return get_threat_char(self.threat_score)

    @property
    def color(self) -> str:
        """Get color style for this threat level."""
        return get_threat_color(self.threat_score)

    @property
    def org_color(self) -> str:
        """Get color style for organization type."""
        return get_org_color(self.org_type)


@dataclass
class ConnectionArc:
    """
    Represents a connection arc between two points.

    Used for visualizing traffic flow on rotating globe views.

    Attributes:
        src_lat: Source latitude
        src_lon: Source longitude
        dst_lat: Destination latitude
        dst_lon: Destination longitude
        threat_score: Threat level of the connection
        org_type: Organization type of destination
        ip: Destination IP address
        age: Time since connection was added
    """
    src_lat: float
    src_lon: float
    dst_lat: float
    dst_lon: float
    threat_score: float
    org_type: str = "unknown"
    ip: str = ""
    age: float = 0.0


class BaseMap(ABC):
    """
    Abstract base class for all map implementations.

    Provides common interface and shared functionality for:
    - Threat marker management
    - Unknown location tracking (displayed as Roman numerals)
    - Coordinate conversion
    - Animation state management

    Subclasses must implement:
    - render() -> Panel
    - latlon_to_screen(lat, lon) -> Optional[Tuple[int, int]]
    """

    # Map type identifier (override in subclasses)
    MAP_TYPE: str = "BASE"

    # Status indicators
    STATUS_OK = "OK"
    STATUS_DEGRADED = "DEGRADED"
    STATUS_FALLBACK = "FALLBACK"

    def __init__(self, width: int = 60, height: int = 15, max_threats: int = 50):
        """
        Initialize the base map.

        Args:
            width: Canvas width in characters
            height: Canvas height in characters
            max_threats: Maximum number of threat markers to track
        """
        self.width = width
        self.height = height

        # Threat tracking
        self.threats: deque = deque(maxlen=max_threats)
        self.threat_map: Dict[Tuple[int, int], ThreatMarker] = {}

        # Unknown location tracking
        self._unknown_ips: Set[str] = set()
        self._unknown_count: int = 0

        # Animation state
        self.time_elapsed: float = 0.0
        self.frame_count: int = 0
        self.paused: bool = False

        # Status tracking
        self._status: str = self.STATUS_OK
        self._init_error: Optional[str] = None

        logger.debug(f"Initialized {self.MAP_TYPE} map: {width}x{height}")

    # =========================================================================
    # ABSTRACT METHODS (must be implemented by subclasses)
    # =========================================================================

    @abstractmethod
    def render(self) -> Panel:
        """
        Render the map as a Rich Panel.

        Returns:
            Rich Panel containing the rendered map visualization
        """
        pass

    @abstractmethod
    def latlon_to_screen(self, lat: float, lon: float) -> Optional[Tuple[int, int]]:
        """
        Convert latitude/longitude to screen coordinates.

        Args:
            lat: Latitude (-90 to 90)
            lon: Longitude (-180 to 180)

        Returns:
            Tuple of (x, y) screen coordinates, or None if off-screen
        """
        pass

    # =========================================================================
    # THREAT MANAGEMENT
    # =========================================================================

    def add_threat(self, lat: float, lon: float, ip: str = "",
                   threat_score: float = 0.5, org_type: str = "unknown") -> bool:
        """
        Add a threat marker to the map.

        Automatically filters out unknown (0, 0) locations and tracks them
        separately for display in the status line.

        Args:
            lat: Latitude coordinate
            lon: Longitude coordinate
            ip: IP address string
            threat_score: Threat level from 0.0 to 1.0
            org_type: Organization type

        Returns:
            True if marker was added, False if filtered (unknown location)
        """
        # Filter unknown locations
        if is_unknown_location(lat, lon):
            if ip:
                self._unknown_ips.add(ip)
                self._unknown_count = len(self._unknown_ips)
            return False

        # Normalize coordinates - use equality check: "FLAT" is flat, everything else is globe
        projection = "flat" if self.MAP_TYPE == "FLAT" else "globe"
        lat, lon = normalize_coordinates(lat, lon, projection=projection)

        # Create and store marker
        marker = ThreatMarker(
            lat=lat,
            lon=lon,
            threat_score=threat_score,
            org_type=org_type.lower(),
            ip=ip,
        )
        self.threats.append(marker)

        # Update position lookup
        screen_pos = self.latlon_to_screen(lat, lon)
        if screen_pos:
            self.threat_map[screen_pos] = marker

        return True

    def clear_threats(self) -> None:
        """Clear all threat markers and reset unknown tracking."""
        self.threats.clear()
        self.threat_map.clear()
        self._unknown_ips.clear()
        self._unknown_count = 0

    def set_unknown_count(self, count: int) -> None:
        """
        Manually set the unknown location count.

        Used when filtering is done externally (e.g., in panel widget).

        Args:
            count: Number of IPs with unknown locations
        """
        self._unknown_count = count

    def get_threat_at(self, x: int, y: int) -> Optional[ThreatMarker]:
        """
        Get threat marker at screen position.

        Args:
            x: Screen X coordinate
            y: Screen Y coordinate

        Returns:
            ThreatMarker at position, or None
        """
        return self.threat_map.get((x, y))

    # =========================================================================
    # ANIMATION & STATE
    # =========================================================================

    def update(self, dt: float = 0.1) -> None:
        """
        Update animation state.

        Args:
            dt: Delta time in seconds since last update
        """
        if self.paused:
            return

        self.time_elapsed += dt
        self.frame_count += 1

        # Age all threats
        for threat in self.threats:
            threat.age += dt

    def toggle_pause(self) -> bool:
        """
        Toggle pause state.

        Returns:
            New pause state
        """
        self.paused = not self.paused
        return self.paused

    def resize(self, width: int, height: int) -> None:
        """
        Resize the map canvas.

        Args:
            width: New width in characters
            height: New height in characters
        """
        self.width = max(20, width)
        self.height = max(8, height)
        self._on_resize()

    def _on_resize(self) -> None:
        """
        Called after resize. Override in subclasses for cache invalidation.
        """
        pass

    # =========================================================================
    # STATUS & DISPLAY HELPERS
    # =========================================================================

    def get_status_text(self) -> str:
        """
        Get status text for display in map corner.

        Returns:
            Status string like "[FLAT]" or "[GLOBE:DEGRADED]"
        """
        if self._status == self.STATUS_OK:
            status = f"[{self.MAP_TYPE}]"
        else:
            error_info = (self._init_error or "Unknown")[:12]
            status = f"[{self.MAP_TYPE}:{self._status}:{error_info}]"

        # Append unknown count if any
        if self._unknown_count > 0:
            status += f" Unk:{int_to_roman(self._unknown_count)}"

        return status

    def get_status_style(self) -> str:
        """
        Get Rich style for status text.

        Returns:
            Style string like "dim green" or "dim yellow"
        """
        if self._status == self.STATUS_OK:
            return "dim green"
        return "dim yellow"

    def get_stats(self) -> Dict:
        """
        Get map statistics for display.

        Returns:
            Dictionary with threat counts and timing info
        """
        threat_count = len(self.threats)
        critical = sum(1 for t in self.threats if t.threat_score >= 0.8)
        high = sum(1 for t in self.threats if 0.7 <= t.threat_score < 0.8)

        return {
            'total': threat_count,
            'critical': critical,
            'high': high,
            'unknown': self._unknown_count,
            'time': self.time_elapsed,
            'frames': self.frame_count,
            'paused': self.paused,
        }

    def format_stats_line(self) -> str:
        """
        Format statistics as a display line.

        Returns:
            Formatted stats string for panel footer
        """
        stats = self.get_stats()
        unknown_part = f" | Unk:{int_to_roman(stats['unknown'])}" if stats['unknown'] > 0 else ""

        return (
            f"Threats: {stats['total']} | "
            f"Critical: {stats['critical']} | "
            f"High: {stats['high']}{unknown_part}"
        )
