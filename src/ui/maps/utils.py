"""
Map Utilities Module
====================

Shared utility functions for all map implementations.
Provides common conversions, styling, and helper functions.
"""

import math
from typing import Tuple

# =============================================================================
# CONSTANTS
# =============================================================================

# Terminal character aspect ratio (width / height)
# Typical monospace fonts are ~2:1 height:width, so ratio ≈ 0.45-0.5
# Used to make globes appear circular instead of vertically elliptical
CHAR_ASPECT_RATIO = 0.45

# Miller projection bounds for normalization
_MILLER_MAX_LAT = 85  # degrees
_MILLER_MAX_LAT_RAD = math.radians(_MILLER_MAX_LAT)
_MILLER_Y_MAX = 1.25 * math.log(math.tan(math.pi / 4 + 0.4 * _MILLER_MAX_LAT_RAD))  # ~2.12
_MILLER_Y_RANGE = 2 * _MILLER_Y_MAX  # Total range from -85 to +85

# Threat level visual indicators with thresholds
THREAT_LEVELS = [
    ("●", "Critical", "bold red", 0.8),
    ("◉", "High", "bold yellow", 0.7),
    ("◯", "Medium", "yellow", 0.5),
    ("○", "Low", "cyan", 0.3),
    ("·", "Info", "green", 0.0),
]

# Organization type color mapping for trust visualization
ORG_TYPE_COLORS = {
    'cloud': 'cyan',
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

# Heatmap intensity gradient (high to low)
HEATMAP_GRADIENT = [
    ("█", "bold red"),
    ("▓", "red"),
    ("▒", "yellow"),
    ("░", "green"),
]


def int_to_roman(num: int) -> str:
    """
    Convert integer to Roman numeral representation.

    Used for displaying unknown connection counts in a compact format
    that doesn't clutter the map display.

    Args:
        num: Integer to convert (1-3999 for valid Roman numerals)

    Returns:
        Roman numeral string, or str(num) for out-of-range values

    Examples:
        >>> int_to_roman(3)
        'III'
        >>> int_to_roman(14)
        'XIV'
        >>> int_to_roman(0)
        '0'
    """
    if num <= 0 or num >= 4000:
        return str(num)

    values = [1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1]
    symbols = ['M', 'CM', 'D', 'CD', 'C', 'XC', 'L', 'XL', 'X', 'IX', 'V', 'IV', 'I']

    result = ''
    for i, value in enumerate(values):
        while num >= value:
            result += symbols[i]
            num -= value
    return result


def get_threat_char(score: float) -> str:
    """
    Get the display character for a threat score.

    Args:
        score: Threat score from 0.0 to 1.0

    Returns:
        Unicode character representing the threat level
    """
    for char, _, _, threshold in THREAT_LEVELS:
        if score >= threshold:
            return char
    return "·"


def get_threat_color(score: float) -> str:
    """
    Get the Rich color style for a threat score.

    Args:
        score: Threat score from 0.0 to 1.0

    Returns:
        Rich color style string
    """
    for _, _, color, threshold in THREAT_LEVELS:
        if score >= threshold:
            return color
    return "green"


def get_threat_style(score: float) -> Tuple[str, str]:
    """
    Get both character and color for a threat score.

    Args:
        score: Threat score from 0.0 to 1.0

    Returns:
        Tuple of (character, color_style)
    """
    return get_threat_char(score), get_threat_color(score)


def get_org_color(org_type: str) -> str:
    """
    Get color for an organization type.

    Args:
        org_type: Organization type string (cloud, isp, tor, etc.)

    Returns:
        Rich color style string
    """
    return ORG_TYPE_COLORS.get(org_type.lower(), 'dim white')


def clamp(value: float, min_val: float, max_val: float) -> float:
    """
    Clamp a value to a range.

    Args:
        value: Value to clamp
        min_val: Minimum allowed value
        max_val: Maximum allowed value

    Returns:
        Clamped value
    """
    return max(min_val, min(max_val, value))


def normalize_coordinates(lat: float, lon: float,
                          projection: str = "flat") -> Tuple[float, float]:
    """
    Normalize latitude and longitude to valid ranges.

    Args:
        lat: Latitude (-90 to 90)
        lon: Longitude (-180 to 180)
        projection: "flat" applies pole clamp (85°), "globe" allows full range (90°)

    Returns:
        Tuple of (normalized_lat, normalized_lon)
    """
    if projection == "flat":
        lat = clamp(lat, -85, 85)  # Avoid pole distortion in cylindrical projections
    else:
        lat = clamp(lat, -90, 90)  # Full range for orthographic globes

    lon = ((lon + 180) % 360) - 180  # Wrap longitude
    return lat, lon


# =============================================================================
# PROJECTION FUNCTIONS
# =============================================================================

def miller_projection(lat: float, lon: float) -> Tuple[float, float]:
    """
    Miller Cylindrical projection - reduces polar distortion.

    Formula:
        x = longitude (radians)
        y = 1.25 * ln(tan(pi/4 + 0.4 * latitude))

    Returns normalized (x, y) in range [0, 1].
    """
    lat_rad = math.radians(clamp(lat, -_MILLER_MAX_LAT, _MILLER_MAX_LAT))
    lon_rad = math.radians(lon)

    x = (lon_rad + math.pi) / (2 * math.pi)  # Normalize to [0, 1]

    # Miller formula
    y_raw = 1.25 * math.log(math.tan(math.pi / 4 + 0.4 * lat_rad))

    # Normalize y to [0, 1] using precomputed bounds
    y = (_MILLER_Y_MAX - y_raw) / _MILLER_Y_RANGE

    return (x, y)


def equirectangular_projection(lat: float, lon: float) -> Tuple[float, float]:
    """
    Simple linear projection (equirectangular).

    Returns normalized (x, y) in range [0, 1].
    """
    lat = clamp(lat, -85, 85)
    lon = ((lon + 180) % 360) - 180

    x = (lon + 180) / 360
    y = (90 - lat) / 180

    return (x, y)


def is_unknown_location(lat: float, lon: float) -> bool:
    """
    Check if coordinates represent an unknown location.

    The (0, 0) coordinate in the Gulf of Guinea is used as a placeholder
    for IPs without geolocation data. This function identifies such cases.

    Args:
        lat: Latitude
        lon: Longitude

    Returns:
        True if coordinates are (0, 0), indicating unknown location
    """
    return lat == 0.0 and lon == 0.0
