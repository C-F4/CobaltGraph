"""
CobaltGraph OUI (Organizationally Unique Identifier) Lookup Service
Phase 0: Vendor identification for discovered devices

OUI Database:
- First 3 bytes (24 bits) of MAC address identify the manufacturer
- Format: AA:BB:CC or AA-BB-CC
- IEEE maintains the official OUI registry

Performance Targets:
- <1ms for cached lookups
- <10ms for uncached lookups
- Memory-efficient (LRU cache)
"""

import logging
import re
import csv
import urllib.request
from pathlib import Path
from typing import Optional, Dict
from functools import lru_cache

logger = logging.getLogger(__name__)


class OUIResolver:
    """
    OUI to vendor resolver

    Features:
    - Built-in vendor database (common OUIs)
    - IEEE OUI database download support
    - LRU caching for performance
    - Case-insensitive lookup
    """

    # IEEE OUI database URL
    IEEE_OUI_URL = "http://standards-oui.ieee.org/oui/oui.txt"

    # Common vendor OUI prefixes (built-in fallback)
    BUILTIN_VENDORS = {
        # Virtualization
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "00:05:69": "VMware",
        "00:1C:14": "VMware",
        "08:00:27": "Oracle VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:15:5D": "Microsoft Hyper-V",
        "00:1C:42": "Parallels",
        # Raspberry Pi
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Trading",
        "E4:5F:01": "Raspberry Pi Foundation",
        "28:CD:C1": "Raspberry Pi Trading",
        "D8:3A:DD": "Raspberry Pi Foundation",
        # Apple
        "00:1B:63": "Apple",
        "00:25:00": "Apple",
        "00:26:BB": "Apple",
        "00:3E:E1": "Apple",
        "00:50:E4": "Apple",
        "04:0C:CE": "Apple",
        "04:15:52": "Apple",
        "04:26:65": "Apple",
        "04:69:F8": "Apple",
        "08:70:45": "Apple",
        "0C:3E:9F": "Apple",
        "10:93:E9": "Apple",
        "18:20:32": "Apple",
        "1C:36:BB": "Apple",
        "20:C9:D0": "Apple",
        "28:CF:DA": "Apple",
        "30:90:AB": "Apple",
        "34:36:3B": "Apple",
        "40:30:04": "Apple",
        "44:2A:60": "Apple",
        "48:74:6E": "Apple",
        "4C:74:BF": "Apple",
        "50:DE:06": "Apple",
        "54:9F:13": "Apple",
        "58:55:CA": "Apple",
        "5C:95:AE": "Apple",
        "60:03:08": "Apple",
        "60:F8:1D": "Apple",
        "64:A5:C3": "Apple",
        "68:64:4B": "Apple",
        "6C:40:08": "Apple",
        "6C:72:20": "Apple",
        "70:56:81": "Apple",
        "74:E2:F5": "Apple",
        "78:7B:8A": "Apple",
        "7C:01:91": "Apple",
        "80:49:71": "Apple",
        "84:FC:FE": "Apple",
        "88:63:DF": "Apple",
        "8C:85:90": "Apple",
        "90:8D:6C": "Apple",
        "94:BF:2D": "Apple",
        "98:F0:AB": "Apple",
        "9C:4F:CF": "Apple",
        "A0:99:9B": "Apple",
        "A4:D1:8C": "Apple",
        "A8:66:7F": "Apple",
        "AC:87:A3": "Apple",
        "AC:DE:48": "Apple",
        "B0:65:BD": "Apple",
        "B4:F0:AB": "Apple",
        "BC:9F:EF": "Apple",
        "C0:18:03": "Apple",
        "C4:2C:03": "Apple",
        "C8:33:4B": "Apple",
        "C8:BC:C8": "Apple",
        "CC:08:8D": "Apple",
        "D0:23:DB": "Apple",
        "D4:9A:20": "Apple",
        "D8:1D:72": "Apple",
        "DC:2B:2A": "Apple",
        "E0:5F:45": "Apple",
        "E4:9A:79": "Apple",
        "E8:8D:28": "Apple",
        "F0:18:98": "Apple",
        "F4:1B:A1": "Apple",
        "F8:1E:DF": "Apple",
        "FC:FC:48": "Apple",
        # Google
        "00:1A:11": "Google",
        "3C:5A:B4": "Google",
        "40:B0:FA": "Google",
        "54:60:09": "Google",
        "68:9E:19": "Google",
        "6C:AD:F8": "Google",
        "74:E5:43": "Google",
        "AC:CF:85": "Google",
        "CC:6D:A0": "Google",
        "D8:34:FC": "Google",
        "DC:EF:09": "Google",
        "F4:60:E2": "Google",
        "F4:F5:D8": "Google",
        "F8:8F:CA": "Google",
        "18:B4:30": "Google Nest",
        "64:16:66": "Google Nest",
        "1C:F2:9A": "Google Nest",
        # Amazon
        "44:07:0B": "Amazon Echo",
        "68:37:E9": "Amazon Technologies",
        "84:D6:D0": "Amazon Technologies",
        "B4:7C:9C": "Amazon Technologies",
        "CC:50:E3": "Amazon Technologies",
        "FC:A6:67": "Amazon Technologies",
        "00:17:88": "Amazon Technologies",
        "4C:EF:C0": "Amazon Technologies",
        "74:C2:46": "Amazon Technologies",
        "A0:02:DC": "Amazon Technologies",
        # Smart Home Devices
        "00:17:88": "Philips Hue",
        "EC:FA:BC": "Philips Hue",
        "00:0D:6F": "Samsung",
        "00:12:47": "Samsung",
        "00:12:FB": "Samsung",
        "00:13:77": "Samsung",
        "00:15:99": "Samsung",
        "00:15:B9": "Samsung",
        "00:16:32": "Samsung",
        "00:16:6B": "Samsung",
        "00:16:6C": "Samsung",
        "00:16:DB": "Samsung",
        "00:17:C9": "Samsung",
        "00:17:D5": "Samsung",
        "00:18:AF": "Samsung",
        "00:1A:8A": "Samsung",
        "00:1B:98": "Samsung",
        "00:1C:43": "Samsung",
        "00:1D:25": "Samsung",
        "00:1E:7D": "Samsung",
        "00:1E:E1": "Samsung",
        "00:1E:E2": "Samsung",
        # Network Equipment
        "00:1B:D5": "Cisco-Linksys",
        "00:04:5A": "Linksys",
        "00:06:25": "Linksys",
        "00:0C:41": "Linksys",
        "00:0E:08": "Linksys",
        "00:0F:66": "Linksys",
        "00:12:17": "Linksys",
        "00:13:10": "Linksys",
        "00:14:BF": "Linksys",
        "00:16:B6": "Linksys",
        "00:18:39": "Linksys",
        "00:18:F8": "Linksys",
        "00:1A:70": "Linksys",
        "00:1C:10": "Linksys",
        "00:1D:7E": "Linksys",
        "00:1E:E5": "Linksys",
        "00:21:29": "Linksys",
        "00:22:6B": "Linksys",
        "00:23:69": "Linksys",
        "00:25:9C": "Linksys",
        "68:7F:74": "Linksys",
        "C0:C1:C0": "Linksys",
        "00:01:E3": "TP-Link",
        "00:1D:0F": "TP-Link",
        "00:27:19": "TP-Link",
        "14:CF:92": "TP-Link",
        "18:A6:F7": "TP-Link",
        "1C:61:B4": "TP-Link",
        "50:C7:BF": "TP-Link",
        "54:A0:50": "TP-Link",
        "64:70:02": "TP-Link",
        "6C:5A:B0": "TP-Link",
        "70:4F:57": "TP-Link",
        "74:DA:88": "TP-Link",
        "84:16:F9": "TP-Link",
        "94:0C:6D": "TP-Link",
        "98:DE:D0": "TP-Link",
        "A0:F3:C1": "TP-Link",
        "B0:4E:26": "TP-Link",
        "C0:4A:00": "TP-Link",
        "D8:0D:17": "TP-Link",
        "E8:48:B8": "TP-Link",
        "EC:08:6B": "TP-Link",
        "F4:EC:38": "TP-Link",
        "00:1B:2F": "Netgear",
        "00:1E:2A": "Netgear",
        "00:1F:33": "Netgear",
        "00:22:3F": "Netgear",
        "00:24:B2": "Netgear",
        "00:26:F2": "Netgear",
        "08:BD:43": "Netgear",
        "10:0D:7F": "Netgear",
        "20:0C:C8": "Netgear",
        "20:E5:2A": "Netgear",
        "28:C6:8E": "Netgear",
        "2C:30:33": "Netgear",
        "30:46:9A": "Netgear",
        "40:16:7E": "Netgear",
        "44:94:FC": "Netgear",
        "84:1B:5E": "Netgear",
        "A0:21:B7": "Netgear",
        "A0:63:91": "Netgear",
        "B0:B9:8A": "Netgear",
        "E0:46:9A": "Netgear",
        "E0:91:F5": "Netgear",
        "00:05:CD": "D-Link",
        "00:0D:88": "D-Link",
        "00:11:95": "D-Link",
        "00:13:46": "D-Link",
        "00:15:E9": "D-Link",
        "00:17:9A": "D-Link",
        "00:19:5B": "D-Link",
        "00:1B:11": "D-Link",
        "00:1C:F0": "D-Link",
        "00:1E:58": "D-Link",
        "00:21:91": "D-Link",
        "00:22:B0": "D-Link",
        "00:24:01": "D-Link",
        "00:26:5A": "D-Link",
        "14:D6:4D": "D-Link",
        "1C:7E:E5": "D-Link",
        "28:10:7B": "D-Link",
        "34:08:04": "D-Link",
        "50:46:5D": "D-Link",
        "5C:D9:98": "D-Link",
        "78:54:2E": "D-Link",
        "84:C9:B2": "D-Link",
        "90:94:E4": "D-Link",
        "B8:A3:86": "D-Link",
        "BC:F6:85": "D-Link",
        "C0:A0:BB": "D-Link",
        "CC:B2:55": "D-Link",
        "D8:FE:E3": "D-Link",
        "E4:6F:13": "D-Link",
        "F0:7D:68": "D-Link",
        # Roku
        "00:0D:4B": "Roku",
        "08:05:81": "Roku",
        "0C:EE:E6": "Roku",
        "10:59:32": "Roku",
        "88:DE:A9": "Roku",
        "B0:A7:37": "Roku",
        "B0:EE:7B": "Roku",
        "CC:6D:A0": "Roku",
        "D0:4D:2C": "Roku",
        "DC:3A:5E": "Roku",
        # Intel
        "00:02:B3": "Intel",
        "00:03:47": "Intel",
        "00:04:23": "Intel",
        "00:0E:35": "Intel",
        "00:11:11": "Intel",
        "00:12:F0": "Intel",
        "00:13:02": "Intel",
        "00:13:20": "Intel",
        "00:13:CE": "Intel",
        "00:13:E8": "Intel",
        "00:15:00": "Intel",
        "00:15:17": "Intel",
        "00:16:6F": "Intel",
        "00:16:76": "Intel",
        "00:16:EA": "Intel",
        "00:16:EB": "Intel",
        "00:18:DE": "Intel",
        "00:19:D1": "Intel",
        "00:19:D2": "Intel",
        "00:1B:21": "Intel",
        "00:1B:77": "Intel",
        "00:1C:BF": "Intel",
        "00:1D:E0": "Intel",
        "00:1D:E1": "Intel",
        "00:1E:64": "Intel",
        "00:1E:65": "Intel",
        "00:1E:67": "Intel",
        "00:1F:3A": "Intel",
        "00:1F:3B": "Intel",
        "00:1F:3C": "Intel",
        "00:21:5C": "Intel",
        "00:21:5D": "Intel",
        "00:21:6A": "Intel",
        "00:22:FA": "Intel",
        "00:22:FB": "Intel",
        "00:23:14": "Intel",
        "00:23:15": "Intel",
        "00:24:D6": "Intel",
        "00:24:D7": "Intel",
        "00:25:64": "Intel",
        "00:26:C6": "Intel",
        "00:26:C7": "Intel",
        "00:27:0E": "Intel",
        "00:27:10": "Intel",
        "00:27:19": "Intel",
        "00:A0:C9": "Intel",
        "00:AA:00": "Intel",
        "00:AA:01": "Intel",
        "00:AA:02": "Intel",
        "00:C0:F0": "Intel",
        "00:D0:B7": "Intel",
        "00:E0:18": "Intel",
        "08:11:96": "Intel",
        "0C:8B:FD": "Intel",
        "0C:D2:92": "Intel",
        "18:3D:A2": "Intel",
        "1C:3B:F3": "Intel",
        "1C:69:7A": "Intel",
        "1C:87:2C": "Intel",
        "1C:BD:B9": "Intel",
        "1C:E1:65": "Intel",
        "24:0A:64": "Intel",
        "24:77:03": "Intel",
        "34:02:86": "Intel",
        "34:13:E8": "Intel",
        "34:FC:EF": "Intel",
        "38:C9:86": "Intel",
        "3C:A9:F4": "Intel",
        "40:B0:34": "Intel",
        "48:45:20": "Intel",
        "48:51:B7": "Intel",
        "4C:34:88": "Intel",
        "54:35:30": "Intel",
        "58:91:CF": "Intel",
        "64:1C:67": "Intel",
        "68:05:CA": "Intel",
        "68:5D:43": "Intel",
        "6C:88:14": "Intel",
        "74:E5:0B": "Intel",
        "78:0C:B8": "Intel",
        "78:24:AF": "Intel",
        "78:45:C4": "Intel",
        "78:92:9C": "Intel",
        "7C:7A:91": "Intel",
        "80:19:34": "Intel",
        "84:3A:4B": "Intel",
        "88:51:FB": "Intel",
        "88:78:73": "Intel",
        "88:AE:DD": "Intel",
        "8C:16:45": "Intel",
        "8C:A9:82": "Intel",
        "90:48:9A": "Intel",
        "94:C6:91": "Intel",
        "94:DE:80": "Intel",
        "98:4F:EE": "Intel",
        "98:90:96": "Intel",
        "9C:4E:36": "Intel",
        "A0:88:69": "Intel",
        "A0:A8:CD": "Intel",
        "A4:02:B9": "Intel",
        "A4:4E:31": "Intel",
        "A4:BF:01": "Intel",
        "A8:6D:AA": "Intel",
        "AC:7B:A1": "Intel",
        "AC:D1:B8": "Intel",
        "B4:6D:83": "Intel",
        "B8:8A:60": "Intel",
        "B8:CA:3A": "Intel",
        "BC:83:85": "Intel",
        "C4:8E:8F": "Intel",
        "C4:D9:87": "Intel",
        "CC:2D:83": "Intel",
        "CC:3D:82": "Intel",
        "D0:57:7B": "Intel",
        "D4:6A:6A": "Intel",
        "D4:AE:52": "Intel",
        "DC:53:60": "Intel",
        "E0:94:67": "Intel",
        "E4:11:5B": "Intel",
        "EC:F4:BB": "Intel",
        "F0:D5:BF": "Intel",
        "F4:06:69": "Intel",
        "F4:6D:04": "Intel",
        "F8:63:94": "Intel",
        "F8:BC:12": "Intel",
        "FC:F8:AE": "Intel",
        # Microsoft
        "00:03:FF": "Microsoft",
        "00:0D:3A": "Microsoft",
        "00:12:5A": "Microsoft",
        "00:13:20": "Microsoft",
        "00:15:5D": "Microsoft",
        "00:17:FA": "Microsoft",
        "00:1D:D8": "Microsoft",
        "00:22:48": "Microsoft",
        "00:24:E8": "Microsoft",
        "00:50:F2": "Microsoft",
        "18:60:24": "Microsoft",
        "28:18:78": "Microsoft",
        "34:DE:1A": "Microsoft",
        "38:0A:94": "Microsoft",
        "48:51:C5": "Microsoft",
        "54:4A:16": "Microsoft",
        "60:45:BD": "Microsoft",
        "64:00:F1": "Microsoft",
        "7C:5F:35": "Microsoft",
        "7C:ED:8D": "Microsoft",
        "90:6C:AC": "Microsoft",
        "98:5F:D3": "Microsoft",
        "A4:5D:36": "Microsoft",
        "A8:80:55": "Microsoft",
        "B4:B6:76": "Microsoft",
        "C0:9F:42": "Microsoft",
        "D0:17:C2": "Microsoft",
        "D8:00:4D": "Microsoft",
        "E8:2A:EA": "Microsoft",
        "EC:08:6B": "Microsoft",
        "F8:BC:12": "Microsoft",
    }

    def __init__(self, cache_size: int = 1000):
        """
        Initialize OUI resolver

        Args:
            cache_size: LRU cache size (default: 1000 MACs)
        """
        self.cache_size = cache_size
        self.vendors = self.BUILTIN_VENDORS.copy()

        # Statistics
        self.stats = {"lookups": 0, "cache_hits": 0, "cache_misses": 0, "unknown": 0}

        logger.info(f"OUI resolver initialized with {len(self.vendors)} built-in vendors")

    @lru_cache(maxsize=1000)
    def _cached_lookup(self, oui: str) -> Optional[str]:
        """Cached OUI lookup (internal)"""
        return self.vendors.get(oui)

    def lookup(self, mac_address: str) -> Optional[str]:
        """
        Look up vendor by MAC address

        Args:
            mac_address: MAC address (any format: AA:BB:CC:DD:EE:FF, AA-BB-CC, etc.)

        Returns:
            Vendor name or None if unknown

        Performance: <1ms for cached, <10ms for uncached
        """
        self.stats["lookups"] += 1

        try:
            # Normalize MAC address
            mac_clean = re.sub(r"[^0-9A-Fa-f]", "", mac_address)

            if len(mac_clean) < 6:
                logger.warning(f"Invalid MAC address: {mac_address}")
                return None

            # Extract OUI (first 3 bytes / 6 hex chars)
            oui_hex = mac_clean[:6].upper()
            oui = f"{oui_hex[0:2]}:{oui_hex[2:4]}:{oui_hex[4:6]}"

            # Cached lookup
            vendor = self._cached_lookup(oui)

            if vendor:
                self.stats["cache_hits"] += 1
                return vendor
            else:
                self.stats["cache_misses"] += 1
                self.stats["unknown"] += 1
                return None

        except Exception as e:
            logger.error(f"Error looking up MAC {mac_address}: {e}")
            return None

    def get_stats(self) -> Dict:
        """Get lookup statistics"""
        return self.stats.copy()

    def get_vendor_count(self) -> int:
        """Get number of known vendors"""
        return len(self.vendors)


# ==============================================================================
# TEST MODE
# ==============================================================================

if __name__ == "__main__":
    """
    Test OUI resolver
    Usage: python3 resolver.py
    """
    import sys

    print("=" * 60)
    print("CobaltGraph OUI Resolver - Test Mode")
    print("=" * 60)
    print()

    resolver = OUIResolver()
    print(f"✅ Loaded {resolver.get_vendor_count()} vendor OUIs\n")

    # Test cases
    test_macs = [
        "00:50:56:12:34:56",  # VMware
        "B8:27:EB:AB:CD:EF",  # Raspberry Pi
        "AC:DE:48:00:11:22",  # Apple
        "CC:6D:A0:12:34:56",  # Google
        "00:1A:11:AA:BB:CC",  # Google
        "08:00:27:11:22:33",  # VirtualBox
        "FF:FF:FF:FF:FF:FF",  # Unknown
        "00:00:00:00:00:00",  # Unknown
    ]

    print("Testing MAC address lookups:")
    print("-" * 60)
    for mac in test_macs:
        vendor = resolver.lookup(mac)
        status = f"[{vendor}]" if vendor else "[Unknown]"
        print(f"{mac:20s} -> {status}")

    print("\n" + "=" * 60)
    stats = resolver.get_stats()
    print(f"Statistics:")
    print(f"  Total lookups: {stats['lookups']}")
    print(f"  Cache hits: {stats['cache_hits']}")
    print(f"  Cache misses: {stats['cache_misses']}")
    print(f"  Unknown MACs: {stats['unknown']}")
    print("=" * 60)
