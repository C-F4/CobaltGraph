#!/usr/bin/env python3
"""
CobaltGraph ARP Monitor - Passive Device Discovery
Phase 0: Automatic device inventory via ARP packet monitoring

Listens for ARP broadcasts on the network and automatically discovers devices.
Completely passive - no active scanning or probing.

ARP Packet Structure (28 bytes after Ethernet header):
    0-1:    Hardware Type (1 = Ethernet)
    2-3:    Protocol Type (0x0800 = IPv4)
    4:      Hardware Address Length (6 for MAC)
    5:      Protocol Address Length (4 for IPv4)
    6-7:    Operation (1 = request, 2 = reply)
    8-13:   Sender Hardware Address (MAC)
    14-17:  Sender Protocol Address (IP)
    18-23:  Target Hardware Address (MAC)
    24-27:  Target Protocol Address (IP)
"""

import socket
import struct
import logging
import threading
import time
from typing import Dict, Optional, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


class ARPPacket:
    """Parsed ARP packet"""

    def __init__(self, raw_data: bytes):
        """
        Parse ARP packet from raw bytes

        Args:
            raw_data: Raw packet data (must include Ethernet + ARP headers)
        """
        if len(raw_data) < 42:  # Ethernet (14) + ARP (28)
            raise ValueError(f"Packet too short for ARP: {len(raw_data)} bytes")

        # Ethernet header (14 bytes)
        eth_header = struct.unpack("!6s6sH", raw_data[:14])
        self.eth_src_mac = self._format_mac(eth_header[1])
        self.eth_dst_mac = self._format_mac(eth_header[0])
        self.eth_type = eth_header[2]

        # ARP header (28 bytes)
        arp_header = raw_data[14:42]

        # Parse ARP fields
        hw_type, proto_type, hw_len, proto_len, operation = struct.unpack(
            "!HHBBH", arp_header[:8]
        )

        self.operation = operation  # 1 = request, 2 = reply
        self.operation_name = "request" if operation == 1 else "reply"

        # Sender (source)
        self.sender_mac = self._format_mac(arp_header[8:14])
        self.sender_ip = socket.inet_ntoa(arp_header[14:18])

        # Target (destination)
        self.target_mac = self._format_mac(arp_header[18:24])
        self.target_ip = socket.inet_ntoa(arp_header[24:28])

    @staticmethod
    def _format_mac(mac_bytes: bytes) -> str:
        """Format MAC address as AA:BB:CC:DD:EE:FF"""
        return ":".join(f"{b:02X}" for b in mac_bytes)

    def to_dict(self) -> Dict:
        """Convert to dictionary for logging/events"""
        return {
            "operation": self.operation_name,
            "sender_mac": self.sender_mac,
            "sender_ip": self.sender_ip,
            "target_mac": self.target_mac,
            "target_ip": self.target_ip,
            "timestamp": datetime.now().isoformat(),
        }

    def __str__(self):
        return (
            f"ARP {self.operation_name}: "
            f"{self.sender_ip} ({self.sender_mac}) -> {self.target_ip}"
        )


class ARPMonitor:
    """
    Passive ARP packet monitor for device discovery

    Listens to ARP broadcast traffic and extracts device MAC/IP pairs.
    Completely passive - does not send any packets.
    """

    # EtherType for ARP
    ARP_ETHERTYPE = 0x0806

    def __init__(self, interface: Optional[str] = None):
        """
        Initialize ARP monitor

        Args:
            interface: Network interface to monitor (None = all interfaces)
        """
        self.interface = interface
        self.running = False
        self.listener_thread = None
        self.packet_count = 0
        self.device_discovered_callback: Optional[Callable] = None

        # Statistics
        self.stats = {
            "packets_received": 0,
            "arp_requests": 0,
            "arp_replies": 0,
            "devices_discovered": 0,
            "errors": 0,
        }

    def set_device_discovered_callback(self, callback: Callable):
        """
        Set callback function for device discovery

        Callback signature: callback(mac_address: str, ip_address: str, packet: ARPPacket)
        """
        self.device_discovered_callback = callback

    def _create_socket(self):
        """
        Create raw socket for ARP monitoring

        Requires root/admin privileges
        """
        try:
            # Create raw socket (protocol = 0x0806 for ARP)
            # AF_PACKET = Linux raw packet interface
            # SOCK_RAW = raw protocol access
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(self.ARP_ETHERTYPE)
            )

            # Bind to specific interface if specified
            if self.interface:
                sock.bind((self.interface, 0))

            logger.info(f"✅ ARP socket created (interface: {self.interface or 'all'})")
            return sock

        except PermissionError:
            error_msg = "ARP monitoring requires root privileges. Run with sudo."
            logger.error(error_msg)
            raise PermissionError(error_msg)

        except OSError as e:
            error_msg = f"Failed to create ARP socket: {e}"
            logger.error(error_msg)
            raise OSError(error_msg)

    def _process_packet(self, raw_data: bytes):
        """
        Process received ARP packet

        Args:
            raw_data: Raw packet bytes
        """
        try:
            self.stats["packets_received"] += 1

            # Parse ARP packet
            arp = ARPPacket(raw_data)

            # Update statistics
            if arp.operation == 1:
                self.stats["arp_requests"] += 1
            elif arp.operation == 2:
                self.stats["arp_replies"] += 1

            logger.debug(f"ARP packet: {arp}")

            # Emit device discovered events for sender (source)
            # The sender is always a real device on the network
            if self.device_discovered_callback and arp.sender_mac != "00:00:00:00:00:00":
                self.device_discovered_callback(
                    arp.sender_mac, arp.sender_ip, arp
                )
                self.stats["devices_discovered"] += 1

            # For ARP replies, the target is also confirmed
            if arp.operation == 2 and arp.target_mac != "00:00:00:00:00:00":
                if self.device_discovered_callback:
                    self.device_discovered_callback(
                        arp.target_mac, arp.target_ip, arp
                    )

        except ValueError as e:
            # Packet parsing error (likely not ARP or malformed)
            logger.debug(f"Packet parsing error: {e}")
            self.stats["errors"] += 1

        except Exception as e:
            logger.error(f"Error processing ARP packet: {e}")
            self.stats["errors"] += 1

    def _listen_loop(self):
        """Main listening loop (runs in separate thread)"""
        logger.info("🎧 ARP listener started")

        try:
            sock = self._create_socket()

            while self.running:
                try:
                    # Receive packet (blocking, 64KB buffer)
                    raw_data, addr = sock.recvfrom(65535)
                    self._process_packet(raw_data)

                except socket.timeout:
                    # Timeout is normal, just continue
                    continue

                except Exception as e:
                    if self.running:
                        logger.error(f"Error in listen loop: {e}")
                        time.sleep(1)  # Avoid tight error loop

        except Exception as e:
            logger.error(f"Fatal error in ARP listener: {e}")
            self.running = False

        finally:
            if sock:
                sock.close()
            logger.info("🎧 ARP listener stopped")

    def start(self):
        """Start ARP monitoring in background thread"""
        if self.running:
            logger.warning("ARP monitor already running")
            return

        self.running = True
        self.listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.listener_thread.start()

        logger.info(f"▶️  ARP monitor started (interface: {self.interface or 'all'})")

    def stop(self):
        """Stop ARP monitoring"""
        if not self.running:
            return

        logger.info("⏹️  Stopping ARP monitor...")
        self.running = False

        if self.listener_thread:
            self.listener_thread.join(timeout=5)

        logger.info(f"✅ ARP monitor stopped. Stats: {self.stats}")

    def get_stats(self) -> Dict:
        """Get monitoring statistics"""
        return self.stats.copy()

    def is_running(self) -> bool:
        """Check if monitor is running"""
        return self.running


# ==============================================================================
# TEST MODE
# ==============================================================================

if __name__ == "__main__":
    """
    Test ARP monitor standalone
    Usage: sudo python3 arp_listener.py
    """
    import sys

    # Setup logging for test mode
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    print("=" * 60)
    print("CobaltGraph ARP Monitor - Test Mode")
    print("=" * 60)
    print()
    print("This will passively listen for ARP packets and display devices.")
    print("Press Ctrl+C to stop.")
    print()

    # Check root privileges
    import os

    if os.geteuid() != 0:
        print("❌ Error: ARP monitoring requires root privileges")
        print("   Run with: sudo python3 arp_listener.py")
        sys.exit(1)

    # Device callback for testing
    discovered_devices = {}

    def on_device_discovered(mac: str, ip: str, packet: ARPPacket):
        """Callback when device is discovered"""
        if mac not in discovered_devices:
            discovered_devices[mac] = {"ips": set(), "first_seen": datetime.now()}
            print(f"🆕 New device: {mac} -> {ip}")
        else:
            if ip not in discovered_devices[mac]["ips"]:
                print(f"🔄 IP change: {mac} -> {ip}")

        discovered_devices[mac]["ips"].add(ip)
        discovered_devices[mac]["last_seen"] = datetime.now()

    # Create and start monitor
    monitor = ARPMonitor()
    monitor.set_device_discovered_callback(on_device_discovered)

    try:
        monitor.start()

        # Status updates every 10 seconds
        while True:
            time.sleep(10)
            stats = monitor.get_stats()
            print(
                f"\n📊 Stats: {stats['packets_received']} packets, "
                f"{stats['arp_requests']} requests, "
                f"{stats['arp_replies']} replies, "
                f"{len(discovered_devices)} devices"
            )

    except KeyboardInterrupt:
        print("\n\n⏹️  Stopping...")
        monitor.stop()

        # Print summary
        print("\n" + "=" * 60)
        print("DISCOVERED DEVICES")
        print("=" * 60)
        for mac, info in sorted(discovered_devices.items()):
            ips = ", ".join(sorted(info["ips"]))
            print(f"{mac:17s} -> {ips}")
        print("=" * 60)

        sys.exit(0)
