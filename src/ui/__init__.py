"""
CobaltGraph Dashboard - Enhanced Unified Threat Monitoring Interface

Active Components:
- CobaltGraphDashboardEnhanced: Primary dashboard (4-cell grid layout)
- ASCIIGlobe: High-resolution ASCII globe with threat heatmaps and trails
- Mode support: device (personal device security) and network (topology monitoring)

Features:
- Real-time threat scoring with confidence intervals
- Geographic threat visualization with animated connection trails
- Network topology and device discovery (mode-specific)
- High-density connection table with full enrichment
- Adaptive rendering for different terminal sizes

Deprecated (archived to archive/dashboards_deprecated/):
- dashboard_v2.py: Simple 2-cell layout (replaced by enhanced version)
- device_dashboard.py: Old device mode (integrated into enhanced)
- network_dashboard.py: Old network mode (integrated into enhanced)
- unified_dashboard.py: Base framework (now internal)
- globe_3d.py: 3D visualization (replaced by ascii_globe)
- boot_sequence.py: Legacy initialization
- reconnaissance_integration.py: Unused
"""

# Import Enhanced Dashboard (main terminal interface)
try:
    from .dashboard_enhanced import CobaltGraphDashboardEnhanced
    DASHBOARD_AVAILABLE = True
except ImportError as e:
    CobaltGraphDashboardEnhanced = None
    DASHBOARD_AVAILABLE = False

# Import ASCII globe component
try:
    from .ascii_globe import ASCIIGlobe, GlobeWidget
    GLOBE_AVAILABLE = True
except ImportError:
    ASCIIGlobe = None
    GlobeWidget = None
    GLOBE_AVAILABLE = False

__all__ = [
    # Main dashboard
    'CobaltGraphDashboardEnhanced',
    'DASHBOARD_AVAILABLE',
    # ASCII globe
    'ASCIIGlobe',
    'GlobeWidget',
    'GLOBE_AVAILABLE',
]
