#!/usr/bin/env python3
"""
Reconnaissance Integration Mixin & Guide

Provides a mixin class for seamless reconnaissance integration into
existing device and network dashboards. Also includes comprehensive
integration guide and keyboard shortcuts.

Usage:
    from src.ui.reconnaissance_integration import ReconnaissanceUIsMixin

    class YourModeDashboard(ReconnaissanceUIMixin, BaseReconnaissanceDashboard):
        def compose(self):
            yield from super().compose()  # Base framework
            # Add your mode-specific widgets
"""

import logging
from typing import Optional

from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Static

from src.ui.reconnaissance import (
    DeviceDiscoveryPanel,
    DeviceDetailPanel,
    DeviceThreatTimelinePanel,
    ActivityPatternPanel,
    PassiveFingerprintPanel,
    DeviceCorrelationPanel,
    NetworkTopologyPanel,
    InteractiveTopologyPanel,
)

logger = logging.getLogger(__name__)


class ReconnaissanceUIMixin:
    """
    Mixin class for adding reconnaissance UI to dashboards

    Provides:
    - Standard reconnaissance widget management
    - Keyboard shortcuts for reconnaissance views
    - Device drill-down navigation
    - Panel state management

    Usage:
        class MyDashboard(ReconnaissanceUIMixin, BaseReconnaissanceDashboard):
            pass

    Keyboard Shortcuts:
        D - Device discovery panel
        V - Device details view
        T - Threat timeline
        P - Passive fingerprinting
        C - Device correlation
        R - Reset view
    """

    # Standard reconnaissance keyboard bindings
    BINDINGS = [
        Binding("d", "show_discovery", "Devices", show=True),
        Binding("v", "show_details", "Details", show=True),
        Binding("t", "show_timeline", "Timeline", show=True),
        Binding("p", "show_fingerprint", "Fingerprint", show=True),
        Binding("c", "show_correlation", "Correlation", show=True),
        Binding("r", "reset_view", "Reset", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self, *args, **kwargs):
        """Initialize reconnaissance mixin"""
        super().__init__(*args, **kwargs)
        self.current_selected_device = None
        self.discovery_panel: Optional[DeviceDiscoveryPanel] = None
        self.detail_panel: Optional[DeviceDetailPanel] = None
        self.timeline_panel: Optional[DeviceThreatTimelinePanel] = None
        self.fingerprint_panel: Optional[PassiveFingerprintPanel] = None
        self.correlation_panel: Optional[DeviceCorrelationPanel] = None

    def create_reconnaissance_panels(self) -> dict:
        """
        Factory method to create reconnaissance UI panels

        Returns:
            Dictionary of reconnaissance panels keyed by name

        Usage:
            panels = self.create_reconnaissance_panels()
            for name, panel in panels.items():
                # Add panels to your layout
        """
        panels = {
            'discovery': DeviceDiscoveryPanel(self.recon_engine),
            'detail': DeviceDetailPanel(),
            'timeline': DeviceThreatTimelinePanel(),
            'fingerprint': PassiveFingerprintPanel(),
            'correlation': DeviceCorrelationPanel(self.recon_engine),
            'topology': NetworkTopologyPanel(),
            'interactive_topology': InteractiveTopologyPanel(self.recon_engine),
        }

        # Store references for easy access
        self.discovery_panel = panels['discovery']
        self.detail_panel = panels['detail']
        self.timeline_panel = panels['timeline']
        self.fingerprint_panel = panels['fingerprint']
        self.correlation_panel = panels['correlation']

        return panels

    def select_device(self, device_key: str) -> None:
        """
        Select a device for drill-down view

        Args:
            device_key: MAC address or IP address of device
        """
        device = self.recon_engine.get_device(device_key)
        if not device:
            logger.warning(f"Device not found: {device_key}")
            return

        self.current_selected_device = device

        # Update all relevant panels
        if self.detail_panel:
            self.detail_panel.select_device(device)
        if self.timeline_panel:
            self.timeline_panel.select_device(device)
        if self.fingerprint_panel:
            self.fingerprint_panel.select_device(device)
        if self.correlation_panel:
            self.correlation_panel.select_device(device)

        logger.info(f"Selected device: {device_key}")

    def update_all_panels(self) -> None:
        """Refresh all reconnaissance panels with latest data"""
        if self.discovery_panel:
            self.discovery_panel.update_devices()

        if self.timeline_panel and self.current_selected_device:
            self.timeline_panel.select_device(self.current_selected_device)

        # For topology panels, pass connection data
        if hasattr(self, '_connection_cache'):
            if self.discovery_panel:
                # Topology would need connection data from dashboard
                pass

    # Action handlers for keyboard shortcuts

    def action_show_discovery(self) -> None:
        """Show device discovery panel (D)"""
        logger.info("Showing device discovery panel")
        if self.discovery_panel:
            self.discovery_panel.update_devices()

    def action_show_details(self) -> None:
        """Show device details panel (V)"""
        logger.info("Showing device details")
        if self.current_selected_device and self.detail_panel:
            self.detail_panel.select_device(self.current_selected_device)

    def action_show_timeline(self) -> None:
        """Show threat timeline (T)"""
        logger.info("Showing threat timeline")
        if self.current_selected_device and self.timeline_panel:
            self.timeline_panel.select_device(self.current_selected_device)

    def action_show_fingerprint(self) -> None:
        """Show passive fingerprinting (P)"""
        logger.info("Showing passive fingerprint")
        if self.current_selected_device and self.fingerprint_panel:
            self.fingerprint_panel.select_device(self.current_selected_device)

    def action_show_correlation(self) -> None:
        """Show device correlation (C)"""
        logger.info("Showing device correlation")
        if self.current_selected_device and self.correlation_panel:
            self.correlation_panel.select_device(self.current_selected_device)

    def action_reset_view(self) -> None:
        """Reset to default view (R)"""
        logger.info("Resetting view")
        self.current_selected_device = None
        self.update_all_panels()


# INTEGRATION GUIDE
INTEGRATION_GUIDE = """
╔════════════════════════════════════════════════════════════════════╗
║         CobaltGraph Reconnaissance Integration Guide              ║
╚════════════════════════════════════════════════════════════════════╝

### Architecture Overview

The reconnaissance system consists of:

1. **DeviceReconnaissanceEngine** (device_state.py)
   - Central device tracking and state machine
   - Per-device threat aggregation
   - Behavioral analysis
   - Works with both device and network modes

2. **Reconnaissance Panels** (discovery/, timeline/, fingerprint/, etc.)
   - Modular UI widgets for display
   - Can be composed into custom layouts
   - Theme-consistent styling (cyan/yellow/red)

3. **BaseReconnaissanceDashboard** (base_reconnaissance_dashboard.py)
   - Enhanced base class for mode dashboards
   - Integrates DeviceReconnaissanceEngine
   - Handles database querying and caching
   - 3-color theme framework

4. **ReconnaissanceUIMixin** (reconnaissance_integration.py)
   - Mixin for adding reconnaissance to existing dashboards
   - Standard keyboard shortcuts
   - Device drill-down navigation
   - Panel state management


### Integration Steps

#### Step 1: Inherit from Enhanced Base
Instead of BaseDashboard, inherit from BaseReconnaissanceDashboard:

    from src.ui.base_reconnaissance_dashboard import BaseReconnaissanceDashboard

    class YourDashboard(BaseReconnaissanceDashboard):
        pass

#### Step 2: Add Reconnaissance Mixin
Use the mixin to add standard reconnaissance capabilities:

    from src.ui.reconnaissance_integration import ReconnaissanceUIMixin

    class YourDashboard(ReconnaissanceUIMixin, BaseReconnaissanceDashboard):
        pass

#### Step 3: Create Reconnaissance Panels
Factory method handles panel creation:

    def compose(self):
        yield Header()

        # Create reconnaissance panels
        panels = self.create_reconnaissance_panels()

        # Create your layout using panels
        with Horizontal():
            yield panels['discovery']
            yield panels['detail']
            yield panels['timeline']

        yield Footer()

#### Step 4: Handle Device Selection
When user clicks on a device, select it:

    self.select_device("00:1A:2B:3C:4D:5E")  # by MAC
    # or
    self.select_device("192.168.1.100")  # by IP

#### Step 5: Update Panels on Events
When pipeline sends new connections:

    def _on_connection_event(self, event):
        super()._on_connection_event(event)  # Base class handles recon
        self.update_all_panels()  # Refresh visible panels


### Available Panels

1. **DeviceDiscoveryPanel**
   - Real-time device inventory
   - Sort by threat/activity/name/role
   - Filter by state (active/idle/offline)
   - Keyboard: S (sort), F (filter)

2. **DeviceDetailPanel**
   - Single device drill-down
   - Identity, state, threat metrics
   - Timeline and passive fingerprinting
   - Risk flags and analyst notes

3. **DeviceThreatTimelinePanel**
   - Threat score sparkline
   - Hourly activity bar chart
   - Anomaly detection display

4. **ActivityPatternPanel**
   - Activity statistics
   - Peak hour detection
   - Periodic activity (beaconing)
   - Protocol distribution

5. **PassiveFingerprintPanel**
   - TTL-based OS detection
   - Hop count analysis
   - MAC vendor information
   - Port usage patterns

6. **DeviceCorrelationPanel**
   - Similar device clustering
   - Shared destination analysis
   - Family/vendor grouping

7. **NetworkTopologyPanel**
   - Device→destination flows
   - Top devices and destinations
   - Threat color coding

8. **InteractiveTopologyPanel**
   - Expandable device tree
   - Real-time activity indicators
   - Click to drill-down

9. **TopologyHeatmapPanel**
   - Device↔destination matrix
   - Threat intensity heatmap


### Keyboard Shortcuts (Standard)

| Key | Action | Panel |
|-----|--------|-------|
| D   | Show device discovery | DeviceDiscoveryPanel |
| V   | Show device details | DeviceDetailPanel |
| T   | Show threat timeline | DeviceThreatTimelinePanel |
| P   | Show fingerprinting | PassiveFingerprintPanel |
| C   | Show correlation | DeviceCorrelationPanel |
| R   | Reset view | All panels |
| Q   | Quit | All |

Within DeviceDiscoveryPanel:
| S   | Sort (cycle threat→activity→name→role) | Discovery |
| F   | Filter by state | Discovery |


### Theme Colors (3-Color Palette)

Primary: Cyan ($cyan)
- Used for headers, primary UI elements
- Device names, panel titles

Warning: Yellow ($yellow)
- Medium threat levels (0.3-0.6)
- Caution states (IDLE devices)
- Important information

Danger: Red ($red)
- High threat (>0.7)
- Critical states (OFFLINE > 30min)
- Severe anomalies


### Example: Device Mode Dashboard

    from src.ui.reconnaissance_integration import ReconnaissanceUIMixin
    from src.ui.base_reconnaissance_dashboard import BaseReconnaissanceDashboard
    from textual.containers import Vertical, Horizontal
    from textual.widgets import Header, Footer

    class DeviceDashboardWithRecon(ReconnaissanceUIMixin, BaseReconnaissanceDashboard):
        def compose(self):
            yield Header()

            panels = self.create_reconnaissance_panels()

            with Horizontal():
                with Vertical(id="left"):
                    yield panels['discovery']
                    yield panels['timeline']

                with Vertical(id="right"):
                    yield panels['detail']
                    yield panels['fingerprint']
                    yield panels['correlation']

            yield Footer()


### Example: Network Mode Dashboard

    class NetworkDashboardWithRecon(ReconnaissanceUIMixin, BaseReconnaissanceDashboard):
        def __init__(self, **kwargs):
            super().__init__(mode="network", **kwargs)

        def compose(self):
            yield Header()

            panels = self.create_reconnaissance_panels()

            with Vertical():
                with Horizontal():
                    yield panels['topology']
                    yield panels['interactive_topology']

                with Horizontal():
                    yield panels['discovery']
                    yield panels['detail']

            yield Footer()


### Data Flow

```
Pipeline Event
    ↓
BaseReconnaissanceDashboard._on_connection_event()
    ↓
DeviceReconnaissanceEngine.process_connection()
    ↓
DeviceReconRecord created/updated
    ↓
ReconnaissanceUIMixin.update_all_panels()
    ↓
UI Panels rendered with latest data
```


### Performance Considerations

- Device limit: 10,000 (configurable)
- Activity TTL: 3600 seconds (1 hour)
- Database cache: 2 seconds
- UI refresh: 1 second
- Connection buffer: 100 most recent
- Device summary recalc: every data refresh


### Extending the System

1. **Add Custom Metrics**
   - Extend DeviceReconRecord dataclass
   - Update DeviceReconnaissanceEngine.process_connection()

2. **Create Custom Panels**
   - Inherit from Static
   - Receive DeviceReconRecord in select_device()
   - Use 3-color theme colors

3. **Add Custom Keyboard Shortcuts**
   - Override BINDINGS in dashboard
   - Add action_* methods
   - Bind to action_* implementations


### Debugging

Enable detailed logging:

    import logging
    logging.getLogger('src.ui.reconnaissance').setLevel(logging.DEBUG)

Check device state:

    devices = dashboard.get_device_records()
    for device in devices:
        print(device.to_dict())

Monitor engine stats:

    summary = dashboard.recon_engine.get_device_summary()
    print(summary)
"""

if __name__ == "__main__":
    print(INTEGRATION_GUIDE)
