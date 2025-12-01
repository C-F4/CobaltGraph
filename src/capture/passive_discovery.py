#!/usr/bin/env python3
"""
PASSIVE device discovery - reads existing system state only.
NEVER sends any packets onto the network.

These tools read kernel caches that are populated by the system's
normal network operations (DHCP, DNS, routing, etc).

CobaltGraph Design Principle: The tool sees without being seen.
"""

import subprocess
import re
import shutil
from abc import ABC, abstractmethod
from typing import List, Dict


class PassiveCacheReader(ABC):
    """Base class for passive cache readers - READ ONLY operations."""

    @abstractmethod
    def name(self) -> str:
        """Return the name of this cache reader."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this reader's tool is available on the system."""
        ...

    @abstractmethod
    def read_cache(self) -> List[Dict]:
        """Read devices from the system cache. PASSIVE ONLY."""
        ...


class ArpCacheReader(PassiveCacheReader):
    """Reads kernel ARP cache - NO packets sent."""

    def name(self) -> str:
        return "arp-cache"

    def is_available(self) -> bool:
        return shutil.which("arp") is not None

    def read_cache(self) -> List[Dict]:
        """Read ARP cache populated by system's normal operations."""
        try:
            result = subprocess.run(
                ["arp", "-an"],  # -n avoids DNS lookups (passive)
                capture_output=True, text=True, timeout=5,
                check=False,
            )
            devices = []
            for line in result.stdout.splitlines():
                # Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
                match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)', line)
                if match and match.group(2) != "<incomplete>":
                    devices.append({
                        "ip": match.group(1),
                        "mac": match.group(2),
                        "source": "arp-cache"
                    })
            return devices
        except Exception:
            return []


class NeighborCacheReader(PassiveCacheReader):
    """Reads kernel neighbor cache via iproute2 - NO packets sent."""

    def name(self) -> str:
        return "ip-neighbor"

    def is_available(self) -> bool:
        return shutil.which("ip") is not None

    def read_cache(self) -> List[Dict]:
        """Read neighbor table populated by kernel's normal operations."""
        try:
            result = subprocess.run(
                ["ip", "-4", "neigh", "show"],  # IPv4 only, no probing
                capture_output=True, text=True, timeout=5,
                check=False,
            )
            devices = []
            for line in result.stdout.splitlines():
                parts = line.split()
                # Format: IP dev IFACE lladdr MAC STATE
                # Example: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                # Index:      0       1    2      3           4            5
                if len(parts) >= 6 and parts[3] == "lladdr":
                    state = parts[5] if len(parts) > 5 else ""
                    # Skip FAILED entries (no response ever received)
                    if state != "FAILED":
                        devices.append({
                            "ip": parts[0],
                            "mac": parts[4],
                            "state": state,
                            "source": "ip-neighbor"
                        })
            return devices
        except Exception:
            return []


def get_available_readers() -> List[PassiveCacheReader]:
    """Return list of available passive cache readers."""
    readers = [NeighborCacheReader(), ArpCacheReader()]
    return [r for r in readers if r.is_available()]


def read_known_devices() -> List[Dict]:
    """
    Read devices from system caches. PASSIVE ONLY.
    Returns devices the kernel already knows about from normal operations.

    This function NEVER sends any packets onto the network.
    """
    for reader in get_available_readers():
        devices = reader.read_cache()
        if devices:
            return devices
    return []


if __name__ == "__main__":
    # Test passive discovery
    print("CobaltGraph Passive Device Discovery")
    print("=" * 40)
    print("NOTE: This only reads existing kernel state - NO packets sent")
    print()

    readers = get_available_readers()
    print(f"Available readers: {[r.name() for r in readers]}")
    print()

    devices = read_known_devices()
    print(f"Devices in kernel cache: {len(devices)}")
    for d in devices:
        print(f"  {d['ip']:15s} {d['mac']:17s} ({d.get('state', 'N/A')})")
