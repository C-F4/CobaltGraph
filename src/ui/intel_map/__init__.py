"""
CobaltGraph Intel Map Module
Geographic threat visualization components with multiple map types.

Components:
- IntelMapPanel: Unified panel with auto-fallback between map types
- IntelMapKey: Compact legend component for map visualization
- FlatWorldMap: 2D equirectangular projection map
- RotatingGlobe: 3D rotating globe visualization
- SimpleGlobe: Lightweight fallback globe

Usage:
    from src.ui.intel_map import IntelMapPanel, IntelMapKey

    # In dashboard compose:
    yield IntelMapPanel(id="intel_map")
"""

from .panel import IntelMapPanel
from .key import IntelMapKey, render_map_key
from .world_map import FlatWorldMap
from .globe_rotating import RotatingGlobe
from .globe_simple import SimpleGlobe

__all__ = [
    'IntelMapPanel',
    'IntelMapKey',
    'render_map_key',
    'FlatWorldMap',
    'RotatingGlobe',
    'SimpleGlobe',
]
