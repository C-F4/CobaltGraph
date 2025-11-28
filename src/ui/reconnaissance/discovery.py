#!/usr/bin/env python3
"""
Device Discovery Panel

Real-time device inventory with:
- State indicators (online/idle/offline)
- Threat level color coding
- Live MAC learning animation
- Sortable by threat, activity, vendor
"""

import logging
from typing import Optional

from rich.text import Text
from textual.widgets import Static, DataTable

from src.ui.reconnaissance.device_state import DeviceState, DeviceReconnaissanceEngine

logger = logging.getLogger(__name__)


class DeviceDiscoveryPanel(Static):
    """
    Real-time device discovery and inventory panel

    Features:
    - Active device list with state indicators
    - Threat level color coding
    - Real-time MAC learning animation
    - Sortable by threat, activity, vendor
    - Live status updates (🟢 online, 🟡 idle, ⚫ offline)
    """

    DEFAULT_CSS = """
    DeviceDiscoveryPanel {
        border: solid $primary;
        height: 100%;
        width: 100%;
        overflow: hidden;
    }

    DeviceDiscoveryPanel DataTable {
        height: 100%;
    }
    """

    def __init__(self, engine: DeviceReconnaissanceEngine, **kwargs):
        super().__init__(**kwargs)
        self.engine = engine
        self.table: Optional[DataTable] = None
        self.sort_by = "threat"
        self.filter_state: Optional[DeviceState] = None

    def compose(self):
        """Create discovery table"""
        table = DataTable(show_cursor=True, show_header=True)
        table.add_columns(
            "Status",
            "MAC / IP",
            "Vendor",
            "Threat",
            "Role",
            "Connections",
            "Last Seen",
        )
        self.table = table
        yield table

    def update_devices(self) -> None:
        """Update device list from engine"""
        if not self.table:
            return

        self.table.clear()

        devices = self.engine.get_devices(
            filter_state=self.filter_state,
            sort_by=self.sort_by,
            limit=20
        )

        for device in devices:
            # State indicator
            if device.state == DeviceState.ACTIVE:
                status = "🟢"
            elif device.state == DeviceState.IDLE:
                status = "🟡"
            elif device.state == DeviceState.OFFLINE:
                status = "⚫"
            else:
                status = "⚪"

            # MAC or IP
            device_id = device.mac_address or device.primary_ip

            # Threat color
            threat = device.threat_score
            if threat >= 0.8:
                threat_style = "bold red"
            elif threat >= 0.6:
                threat_style = "bold yellow"
            elif threat >= 0.3:
                threat_style = "yellow"
            else:
                threat_style = "green"

            threat_text = Text(f"{threat:.2f}", style=threat_style)

            # Last activity
            from datetime import datetime
            time_since = datetime.now().timestamp() - device.last_seen
            if time_since < 60:
                last_seen = f"{int(time_since)}s ago"
            elif time_since < 3600:
                last_seen = f"{int(time_since/60)}m ago"
            else:
                last_seen = f"{int(time_since/3600)}h ago"

            self.table.add_row(
                status,
                device_id,
                device.vendor or "-",
                threat_text,
                device.inferred_role.value.replace("_", " "),
                str(device.metrics.total_connections),
                last_seen,
            )

    def cycle_sort(self) -> None:
        """Cycle sort order"""
        sorts = ["threat", "activity", "name", "role"]
        current_idx = sorts.index(self.sort_by)
        self.sort_by = sorts[(current_idx + 1) % len(sorts)]
        self.update_devices()

    def toggle_filter(self) -> None:
        """Toggle state filter"""
        states = [None, DeviceState.ACTIVE, DeviceState.IDLE, DeviceState.OFFLINE]
        current_idx = states.index(self.filter_state)
        self.filter_state = states[(current_idx + 1) % len(states)]
        self.update_devices()
