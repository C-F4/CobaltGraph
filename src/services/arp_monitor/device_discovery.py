"""
CobaltGraph Device Discovery Service
Integrates ARP monitoring with database and OUI lookup

Phase 0: Automatic device inventory with vendor identification
"""

import logging
import time
from typing import Optional, Dict
from datetime import datetime

from .arp_listener import ARPMonitor, ARPPacket
from src.services.database import PostgreSQLDatabase

logger = logging.getLogger(__name__)


class DeviceDiscoveryService:
    """
    Device discovery service - Phase 0

    Responsibilities:
    - Monitor ARP packets for device discovery
    - Maintain device inventory in database
    - Emit device_discovered events
    - Track device online/offline status
    - Integrate with OUI vendor lookup (Task 0.3)
    """

    def __init__(
        self,
        database: PostgreSQLDatabase,
        oui_lookup=None,  # Will be added in Task 0.3
        interface: Optional[str] = None,
        socketio=None,  # SocketIO instance for real-time updates (Task 0.6)
    ):
        """
        Initialize device discovery service

        Args:
            database: PostgreSQL database instance
            oui_lookup: OUI vendor lookup service (optional, Task 0.3)
            interface: Network interface to monitor (None = all)
            socketio: SocketIO instance for real-time updates (optional, Task 0.6)
        """
        self.db = database
        self.oui_lookup = oui_lookup
        self.socketio = socketio  # Store SocketIO instance
        self.arp_monitor = ARPMonitor(interface=interface)

        # Device tracking (in-memory cache)
        self.known_devices = {}  # mac -> last_seen timestamp

        # Statistics
        self.stats = {
            "devices_discovered": 0,
            "devices_updated": 0,
            "arp_packets_processed": 0,
            "database_writes": 0,
            "errors": 0,
        }

        # Set ARP callback
        self.arp_monitor.set_device_discovered_callback(self._on_device_discovered)

    def _on_device_discovered(
        self, mac_address: str, ip_address: str, arp_packet: ARPPacket
    ):
        """
        Callback when ARP monitor discovers a device

        Args:
            mac_address: Device MAC address
            ip_address: Device IP address
            arp_packet: Parsed ARP packet
        """
        try:
            self.stats["arp_packets_processed"] += 1

            # Check if this is a new device
            is_new_device = mac_address not in self.known_devices

            # Resolve vendor (Task 0.3 integration)
            vendor = None
            if self.oui_lookup:
                vendor = self.oui_lookup.lookup(mac_address)

            # Prepare device data
            device_data = {
                "mac_address": mac_address,
                "ip_address": ip_address,
                "vendor": vendor,
                "device_type": "unknown",  # Enhanced in Phase 1
                "metadata": {
                    "discovery_method": "arp",
                    "arp_operation": arp_packet.operation_name,
                    "last_arp_timestamp": datetime.now().isoformat(),
                },
            }

            # Add/update device in database
            try:
                self.db.add_device(device_data)
                self.stats["database_writes"] += 1

                if is_new_device:
                    self.stats["devices_discovered"] += 1
                    logger.info(
                        f"🆕 Device discovered: {mac_address} ({ip_address}) "
                        f"{f'[{vendor}]' if vendor else ''}"
                    )

                    # Log device_discovered event (Task 0.4)
                    self._log_device_event(
                        mac_address, "discovered", new_value=ip_address
                    )

                    # Emit WebSocket event for new device (Task 0.6)
                    if self.socketio:
                        try:
                            self.socketio.emit_device_discovered(device_data)
                        except Exception as e:
                            logger.warning(f"Failed to emit device_discovered: {e}")

                else:
                    self.stats["devices_updated"] += 1
                    logger.debug(
                        f"🔄 Device updated: {mac_address} ({ip_address})"
                    )

                    # Emit WebSocket event for updated device (Task 0.6)
                    if self.socketio:
                        try:
                            self.socketio.emit_device_updated(device_data)
                        except Exception as e:
                            logger.warning(f"Failed to emit device_updated: {e}")

                # Update in-memory cache
                self.known_devices[mac_address] = time.time()

            except Exception as e:
                logger.error(f"Database error for device {mac_address}: {e}")
                self.stats["errors"] += 1

        except Exception as e:
            logger.error(f"Error in device discovery callback: {e}")
            self.stats["errors"] += 1

    def _log_device_event(
        self,
        mac_address: str,
        event_type: str,
        old_value: Optional[str] = None,
        new_value: Optional[str] = None,
    ):
        """
        Log device event to audit trail

        Args:
            mac_address: Device MAC address
            event_type: Event type (discovered, active, idle, offline, ip_changed)
            old_value: Previous value (optional)
            new_value: New value (optional)
        """
        try:
            event_data = {
                "device_mac": mac_address,
                "event_type": event_type,
                "old_value": old_value,
                "new_value": new_value,
                "metadata": {"timestamp": datetime.now().isoformat()},
            }

            self.db.log_device_event(event_data)
            logger.debug(f"Event logged: {event_type} for {mac_address}")

        except Exception as e:
            logger.warning(f"Failed to log event {event_type} for {mac_address}: {e}")

    def start(self):
        """Start device discovery service"""
        logger.info("▶️  Starting device discovery service...")

        # Start ARP monitor
        self.arp_monitor.start()

        logger.info("✅ Device discovery service started")

    def stop(self):
        """Stop device discovery service"""
        logger.info("⏹️  Stopping device discovery service...")

        # Stop ARP monitor
        self.arp_monitor.stop()

        # Log final statistics
        logger.info(f"📊 Device discovery stats: {self.stats}")
        logger.info("✅ Device discovery service stopped")

    def get_stats(self) -> Dict:
        """Get service statistics"""
        arp_stats = self.arp_monitor.get_stats()

        return {
            **self.stats,
            "arp_monitor": arp_stats,
            "known_devices_count": len(self.known_devices),
        }

    def is_running(self) -> bool:
        """Check if service is running"""
        return self.arp_monitor.is_running()

    def get_discovered_devices(self) -> Dict:
        """Get list of discovered devices (from database)"""
        try:
            devices = self.db.get_devices(limit=1000)
            return {
                "total": len(devices),
                "devices": devices,
            }
        except Exception as e:
            logger.error(f"Failed to get discovered devices: {e}")
            return {"total": 0, "devices": [], "error": str(e)}


# ==============================================================================
# TEST MODE
# ==============================================================================

if __name__ == "__main__":
    """
    Test device discovery service
    Usage: sudo python3 device_discovery.py
    """
    import sys
    import os

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    print("=" * 60)
    print("CobaltGraph Device Discovery Service - Test Mode")
    print("=" * 60)
    print()

    # Check root
    if os.geteuid() != 0:
        print("❌ Error: Requires root privileges")
        print("   Run with: sudo python3 device_discovery.py")
        sys.exit(1)

    # Note: This test requires a configured PostgreSQL database
    print("⚠️  Note: This test requires PostgreSQL to be configured")
    print("   Config file: config/database.conf")
    print()

    try:
        # Initialize database
        db = PostgreSQLDatabase()
        print("✅ Database connected")

        # Initialize service
        service = DeviceDiscoveryService(database=db)

        # Start service
        service.start()

        # Monitor status
        print("\n🎧 Listening for ARP packets... (Ctrl+C to stop)\n")

        while True:
            time.sleep(10)
            stats = service.get_stats()
            print(
                f"📊 Stats: {stats['devices_discovered']} discovered, "
                f"{stats['devices_updated']} updates, "
                f"{stats['arp_packets_processed']} ARP packets processed"
            )

    except FileNotFoundError as e:
        print(f"❌ Config error: {e}")
        print("   Please configure config/database.conf first")
        sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n⏹️  Stopping service...")
        service.stop()

        # Show discovered devices
        result = service.get_discovered_devices()
        print(f"\n📋 Discovered {result['total']} devices")

        sys.exit(0)

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
