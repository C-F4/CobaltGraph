"""
CobaltGraph UI Module - Terminal Interface Components

ARCHITECTURE:
  Primary: C++ TUI (tui/) - High-performance native terminal interface
  Backend: Python IPC service (src/ipc/) - Data processing and streaming
  Legacy: Python TUI (this module) - Fallback Textual-based interface

This module provides the legacy Python TUI as a fallback when the
C++ TUI binary is not available.

Components:
- CobaltGraphDashboardEnhanced: Main dashboard (Textual-based)
- intel_map: Geographic threat visualization module
- FlatWorldMap: ASCII world map for threat visualization (legacy, use intel_map)
- BootSequence: Tactical boot animation

Usage:
  # Start with C++ TUI (auto-fallback to Python TUI)
  python3 start.py --mode device

  # Force legacy Python TUI
  python3 start.py --mode device --legacy
"""

# Import Enhanced Dashboard (main terminal interface)
try:
    from .dashboard_enhanced import CobaltGraphDashboardEnhanced
    DASHBOARD_AVAILABLE = True
except ImportError:
    CobaltGraphDashboardEnhanced = None
    DASHBOARD_AVAILABLE = False

# Import boot sequence
try:
    from .boot_sequence import boot_sequence
    BOOT_AVAILABLE = True
except ImportError:
    boot_sequence = None
    BOOT_AVAILABLE = False

# Import consolidated maps module (geographic visualization)
try:
    from .maps import FlatWorldMap, RotatingGlobe, SimpleGlobe, MapKey
    IntelMapKey = MapKey  # Alias for compatibility
    INTEL_MAP_AVAILABLE = True
except ImportError:
    FlatWorldMap = None
    RotatingGlobe = None
    SimpleGlobe = None
    MapKey = None
    IntelMapKey = None
    INTEL_MAP_AVAILABLE = False

# Import IntelMapPanel from panels module
try:
    from .panels import IntelMapPanel
except ImportError:
    IntelMapPanel = None

__all__ = [
    'CobaltGraphDashboardEnhanced',
    'DASHBOARD_AVAILABLE',
    'boot_sequence',
    'BOOT_AVAILABLE',
    'IntelMapPanel',
    'IntelMapKey',
    'MapKey',
    'FlatWorldMap',
    'RotatingGlobe',
    'SimpleGlobe',
    'INTEL_MAP_AVAILABLE',
]
