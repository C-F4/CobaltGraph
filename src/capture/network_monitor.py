#!/usr/bin/env python3
"""
CobaltGraph Network Monitor - Network-Wide Passive Intelligence
Transforms CobaltGraph from device tool to network security platform

Capabilities:
- Promiscuous mode packet capture (sees ALL network traffic)
- Device discovery and tracking via MAC addresses
- Network topology mapping
- Per-device threat scoring
- Works on entire network segment, not just this machine

Modes:
- device: Monitor only this machine's connections (default)
- network: Monitor entire network segment (requires promiscuous mode)
"""

import socket
import struct
import json
import sys
import time
import subprocess
import re
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, Set, Optional, List


class NetworkDevice:
    """Represents a discovered network device"""

    def __init__(self, mac_address: str):
        self.mac = mac_address
        self.ip_addresses: Set[str] = set()
        self.hostname: Optional[str] = None
        self.vendor: Optional[str] = None
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.packet_count = 0
        self.connection_count = 0
        self.threat_score = 0.0

    def update_activity(self, ip: Optional[str] = None):
        """Update device activity timestamp"""
        self.last_seen = time.time()
        self.packet_count += 1
        if ip and ip not in self.ip_addresses:
            self.ip_addresses.add(ip)

    def to_dict(self) -> Dict:
        """Convert device to dictionary for JSON serialization"""
        return {
            'mac': self.mac,
            'ip_addresses': list(self.ip_addresses),
            'hostname': self.hostname,
            'vendor': self.vendor,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'packet_count': self.packet_count,
            'connection_count': self.connection_count,
            'threat_score': self.threat_score,
            'is_active': (time.time() - self.last_seen) < 300  # Active in last 5 min
        }


class MACVendorResolver:
    """Resolve MAC addresses to vendor names"""

    # Common vendor OUI prefixes (first 3 bytes of MAC)
    # In production, use IEEE OUI database
    VENDOR_MAP = {
        '00:50:56': 'VMware',
        '00:0c:29': 'VMware',
        '00:05:69': 'VMware',
        '08:00:27': 'VirtualBox',
        '52:54:00': 'QEMU/KVM',
        '00:15:5d': 'Microsoft Hyper-V',
        '00:1c:42': 'Parallels',
        'dc:a6:32': 'Raspberry Pi',
        'b8:27:eb': 'Raspberry Pi',
        'e4:5f:01': 'Raspberry Pi',
        '28:cd:c1': 'Raspberry Pi',
        '00:50:f2': 'Microsoft',
        '00:1b:63': 'Apple',
        '00:25:00': 'Apple',
        '00:26:bb': 'Apple',
        'ac:de:48': 'Apple',
        'f0:18:98': 'Apple',
        '3c:07:54': 'Roku',
        '00:04:20': 'Roku',
        'b0:a7:37': 'Roku',
        'cc:6d:a0': 'Google',
        'f4:f5:d8': 'Google',
        '18:b4:30': 'Google Nest',
        '44:07:0b': 'Amazon Echo',
        '84:d6:d0': 'Amazon',
        'fc:a6:67': 'Amazon',
        '00:17:88': 'Philips Hue',
        '00:1c:b3': 'Netgear',
        '00:14:6c': 'Netgear',
        'a0:63:91': 'Netgear',
        '00:1d:7e': 'D-Link',
        '00:05:cd': 'D-Link',
        '00:0d:88': 'D-Link',
    }

    @staticmethod
    def resolve(mac: str) -> Optional[str]:
        """Resolve MAC address to vendor name"""
        # Normalize MAC format
        mac_normalized = mac.upper().replace('-', ':')

        # Check first 3 bytes (OUI)
        oui = ':'.join(mac_normalized.split(':')[:3])

        # Try exact match
        if oui in MACVendorResolver.VENDOR_MAP:
            return MACVendorResolver.VENDOR_MAP[oui]

        # Try lowercase variant
        oui_lower = oui.lower()
        if oui_lower in MACVendorResolver.VENDOR_MAP:
            return MACVendorResolver.VENDOR_MAP[oui_lower]

        return None


class NetworkMonitor:
    """
    Network-wide passive monitoring system

    Operates in two modes:
    - device: Monitor only this machine's connections
    - network: Monitor entire network segment (promiscuous mode)
    """

    def __init__(self, mode='device', interface=None):
        self.mode = mode
        self.interface = interface or self._detect_interface()
        self.running = False

        # Device tracking
        self.devices: Dict[str, NetworkDevice] = {}  # MAC -> NetworkDevice
        self.device_lock = None  # Would use threading.Lock() in threaded version

        # Connection tracking
        self.connections = deque(maxlen=1000)

        # Statistics
        self.total_packets = 0
        self.total_connections = 0
        self.start_time = time.time()

        print(f"[Network Monitor] Mode: {mode}", file=sys.stderr)
        print(f"[Network Monitor] Interface: {self.interface}", file=sys.stderr)

    def _detect_interface(self) -> str:
        """Auto-detect primary network interface"""
        try:
            # Try to get default route interface
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=2
            )

            # Parse: default via 192.168.1.1 dev eth0 ...
            match = re.search(r'dev\s+(\S+)', result.stdout)
            if match:
                interface = match.group(1)
                print(f"[Network Monitor] Auto-detected interface: {interface}", file=sys.stderr)
                return interface

        except Exception as e:
            print(f"[Network Monitor] Interface detection failed: {e}", file=sys.stderr)

        # Fallback to common interface names
        for iface in ['eth0', 'ens33', 'enp0s3', 'wlan0', 'wlp2s0']:
            try:
                # Check if interface exists
                result = subprocess.run(
                    ["ip", "link", "show", iface],
                    capture_output=True,
                    timeout=1
                )
                if result.returncode == 0:
                    print(f"[Network Monitor] Using interface: {iface}", file=sys.stderr)
                    return iface
            except:
                continue

        # Ultimate fallback
        print("[Network Monitor] WARNING: Using fallback interface 'eth0'", file=sys.stderr)
        return 'eth0'

    def enable_promiscuous_mode(self) -> bool:
        """
        Enable promiscuous mode on network interface
        Allows capturing ALL packets on network segment, not just those addressed to us

        Returns:
            True if successful, False otherwise
        """
        if self.mode != 'network':
            return True  # Not needed in device mode

        try:
            # Enable promiscuous mode using ip command
            result = subprocess.run(
                ["ip", "link", "set", self.interface, "promisc", "on"],
                capture_output=True,
                timeout=2
            )

            if result.returncode == 0:
                print(f"[Network Monitor] ✅ Promiscuous mode enabled on {self.interface}", file=sys.stderr)
                return True
            else:
                print(f"[Network Monitor] ❌ Failed to enable promiscuous mode: {result.stderr.decode()}", file=sys.stderr)
                print(f"[Network Monitor] Try: sudo ip link set {self.interface} promisc on", file=sys.stderr)
                return False

        except subprocess.TimeoutExpired:
            print("[Network Monitor] ❌ Timeout enabling promiscuous mode", file=sys.stderr)
            return False
        except Exception as e:
            print(f"[Network Monitor] ❌ Error enabling promiscuous mode: {e}", file=sys.stderr)
            return False

    def disable_promiscuous_mode(self):
        """Disable promiscuous mode on cleanup"""
        if self.mode != 'network':
            return

        try:
            subprocess.run(
                ["ip", "link", "set", self.interface, "promisc", "off"],
                capture_output=True,
                timeout=2
            )
            print(f"[Network Monitor] Promiscuous mode disabled on {self.interface}", file=sys.stderr)
        except:
            pass

    def parse_ethernet_frame(self, data: bytes) -> Optional[Dict]:
        """
        Parse Ethernet frame to extract MAC addresses

        Ethernet Frame Format:
        [Dest MAC: 6 bytes][Source MAC: 6 bytes][Type: 2 bytes][Payload]
        """
        if len(data) < 14:
            return None

        # Extract MAC addresses
        dest_mac_bytes = data[0:6]
        src_mac_bytes = data[6:12]
        eth_type = struct.unpack("!H", data[12:14])[0]

        # Format MAC addresses as XX:XX:XX:XX:XX:XX
        src_mac = ':'.join(f'{b:02x}' for b in src_mac_bytes)
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac_bytes)

        return {
            'src_mac': src_mac,
            'dest_mac': dest_mac,
            'eth_type': eth_type,
            'payload': data[14:]
        }

    def parse_ipv4_packet(self, data: bytes) -> Optional[Dict]:
        """Parse IPv4 packet from Ethernet payload"""
        if len(data) < 20:
            return None

        # IP header is at least 20 bytes
        version_ihl = data[0]
        version = version_ihl >> 4

        if version != 4:
            return None

        ihl = (version_ihl & 0xF) * 4  # Header length in bytes
        protocol = data[9]

        src_ip = socket.inet_ntoa(data[12:16])
        dest_ip = socket.inet_ntoa(data[16:20])

        result = {
            'protocol': protocol,
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'transport_data': data[ihl:]  # TCP/UDP/etc payload
        }

        # Parse TCP/UDP ports if available
        transport_data = data[ihl:]

        if protocol == 6 and len(transport_data) >= 4:  # TCP
            src_port = struct.unpack("!H", transport_data[0:2])[0]
            dest_port = struct.unpack("!H", transport_data[2:4])[0]
            result['src_port'] = src_port
            result['dest_port'] = dest_port
            result['protocol_name'] = 'TCP'

        elif protocol == 17 and len(transport_data) >= 4:  # UDP
            src_port = struct.unpack("!H", transport_data[0:2])[0]
            dest_port = struct.unpack("!H", transport_data[2:4])[0]
            result['src_port'] = src_port
            result['dest_port'] = dest_port
            result['protocol_name'] = 'UDP'
        else:
            result['protocol_name'] = f'Proto-{protocol}'

        return result

    def track_device(self, mac: str, ip: Optional[str] = None):
        """Track or update network device"""
        if mac not in self.devices:
            device = NetworkDevice(mac)

            # Try to resolve vendor
            vendor = MACVendorResolver.resolve(mac)
            if vendor:
                device.vendor = vendor

            self.devices[mac] = device
            print(f"[Network Monitor] 🆕 New device discovered: {mac} ({vendor or 'Unknown'})", file=sys.stderr)

        self.devices[mac].update_activity(ip)

    def process_packet(self, raw_data: bytes):
        """Process a captured network packet"""
        self.total_packets += 1

        # Parse Ethernet frame
        eth_frame = self.parse_ethernet_frame(raw_data)
        if not eth_frame:
            return

        # Track source device
        src_mac = eth_frame['src_mac']

        # Only process IPv4 packets (0x0800)
        if eth_frame['eth_type'] != 0x0800:
            return

        # Parse IP packet
        ip_packet = self.parse_ipv4_packet(eth_frame['payload'])
        if not ip_packet:
            return

        # Track device with IP
        self.track_device(src_mac, ip_packet['src_ip'])

        # Check if this is an external connection (not local network)
        dest_ip = ip_packet['dest_ip']
        src_ip = ip_packet['src_ip']

        # Skip localhost
        if dest_ip.startswith('127.') or src_ip.startswith('127.'):
            return

        # Skip link-local
        if dest_ip.startswith('169.254.') or src_ip.startswith('169.254.'):
            return

        # Only track outbound connections (to internet)
        # Local network: 10.x, 172.16-31.x, 192.168.x
        is_dest_local = (
            dest_ip.startswith('10.') or
            dest_ip.startswith('192.168.') or
            (dest_ip.startswith('172.') and 16 <= int(dest_ip.split('.')[1]) <= 31)
        )

        # Only emit if destination is external (internet)
        if not is_dest_local and 'dest_port' in ip_packet:
            self.total_connections += 1

            # Update device connection count
            if src_mac in self.devices:
                self.devices[src_mac].connection_count += 1

            # Emit connection event
            connection = {
                'type': 'connection',
                'timestamp': datetime.now().isoformat(),
                'src_mac': src_mac,
                'src_ip': src_ip,
                'dst_ip': dest_ip,
                'dst_port': ip_packet['dest_port'],
                'protocol': ip_packet.get('protocol_name', 'TCP'),
                'device_vendor': self.devices.get(src_mac, NetworkDevice('')).vendor,
                'metadata': {
                    'network_mode': self.mode,
                    'interface': self.interface
                }
            }

            print(json.dumps(connection), flush=True)
            self.connections.append(connection)

    def start_capture(self):
        """Start network packet capture"""
        self.running = True

        # Enable promiscuous mode if in network mode
        if self.mode == 'network':
            if not self.enable_promiscuous_mode():
                print("[Network Monitor] ⚠️  Running without promiscuous mode - may miss packets", file=sys.stderr)

        try:
            # Create raw socket
            # Protocol 0x0003 = ETH_P_ALL (capture all protocols)
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

            # Bind to specific interface if in network mode
            if self.mode == 'network':
                sock.bind((self.interface, 0))

            print(f"[Network Monitor] 🟢 Capture started on {self.interface}", file=sys.stderr)

            # Heartbeat counter
            heartbeat_counter = 0
            last_heartbeat = time.time()

            while self.running:
                # Receive packet (up to 65535 bytes)
                raw_data, addr = sock.recvfrom(65535)
                self.process_packet(raw_data)

                # Send heartbeat every 10 seconds
                if time.time() - last_heartbeat >= 10:
                    heartbeat_counter += 1
                    heartbeat = {
                        'type': 'heartbeat',
                        'timestamp': datetime.now().isoformat(),
                        'total_packets': self.total_packets,
                        'total_connections': self.total_connections,
                        'devices_discovered': len(self.devices),
                        'active_devices': sum(1 for d in self.devices.values() if (time.time() - d.last_seen) < 300),
                        'mode': self.mode,
                        'uptime': int(time.time() - self.start_time)
                    }
                    print(json.dumps(heartbeat), flush=True)
                    print(f"[Network Monitor] 💓 {self.total_packets} packets | {len(self.devices)} devices | {self.total_connections} connections", file=sys.stderr)
                    last_heartbeat = time.time()

        except PermissionError:
            print("[Network Monitor] ❌ ERROR: Requires root privileges", file=sys.stderr)
            print("[Network Monitor] Run with: sudo python3 network_monitor.py", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[Network Monitor] ❌ Capture error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
        finally:
            self.running = False
            if self.mode == 'network':
                self.disable_promiscuous_mode()

    def stop(self):
        """Stop network capture"""
        self.running = False
        if self.mode == 'network':
            self.disable_promiscuous_mode()


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='CobaltGraph Network Monitor - Network-Wide Intelligence')
    parser.add_argument(
        '--mode',
        choices=['device', 'network'],
        default='device',
        help='Monitoring mode: device (this machine only) or network (entire segment)'
    )
    parser.add_argument(
        '--interface',
        help='Network interface to monitor (auto-detect if not specified)'
    )

    args = parser.parse_args()

    print("=" * 60, file=sys.stderr)
    print("CobaltGraph Network Monitor - Network Security Platform", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print("", file=sys.stderr)

    if args.mode == 'network':
        print("⚠️  NETWORK MODE: Monitoring entire network segment", file=sys.stderr)
        print("   Requires: sudo privileges + promiscuous mode", file=sys.stderr)
        print("", file=sys.stderr)
    else:
        print("📱 DEVICE MODE: Monitoring this machine only", file=sys.stderr)
        print("", file=sys.stderr)

    monitor = NetworkMonitor(mode=args.mode, interface=args.interface)

    try:
        monitor.start_capture()
    except KeyboardInterrupt:
        print("\n[Network Monitor] Stopping...", file=sys.stderr)
        monitor.stop()

        # Print final statistics
        print("", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print("Final Statistics", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(f"Total Packets:     {monitor.total_packets}", file=sys.stderr)
        print(f"Total Connections: {monitor.total_connections}", file=sys.stderr)
        print(f"Devices Discovered: {len(monitor.devices)}", file=sys.stderr)
        print(f"Uptime:            {int(time.time() - monitor.start_time)}s", file=sys.stderr)

        if monitor.devices:
            print("", file=sys.stderr)
            print("Discovered Devices:", file=sys.stderr)
            for mac, device in sorted(monitor.devices.items(), key=lambda x: x[1].packet_count, reverse=True)[:10]:
                vendor = device.vendor or 'Unknown'
                ips = ', '.join(list(device.ip_addresses)[:3])
                print(f"  {mac} ({vendor}): {device.packet_count} packets, IPs: {ips}", file=sys.stderr)

        sys.exit(0)


if __name__ == "__main__":
    main()
