#!/usr/bin/env python3
"""
IEEE OUI Database Lookup Service
Provides MAC vendor resolution using official IEEE MA-L/MA-M/MA-S databases

Features:
- Downloads and parses IEEE OUI CSV files
- Supports MA-L (24-bit), MA-M (28-bit), and MA-S (36-bit) assignments
- LRU cache with TTL for fast lookups
- Pickle storage for fast loading
- On-demand database updates (not at startup)
"""

import csv
import io
import logging
import os
import pickle
import re
import time
from collections import OrderedDict
from pathlib import Path
from threading import RLock
from typing import Dict, Optional, Tuple

import requests
from requests.exceptions import RequestException, Timeout

logger = logging.getLogger(__name__)


class LRUCache:
    """Thread-safe LRU cache with TTL"""

    def __init__(self, max_size: int = 10000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: OrderedDict = OrderedDict()
        self.timestamps: Dict[str, float] = {}
        self._lock = RLock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[str]:
        """Get from cache if exists and not expired"""
        with self._lock:
            if key not in self.cache:
                self.misses += 1
                return None

            if time.time() - self.timestamps.get(key, 0) > self.ttl_seconds:
                del self.cache[key]
                del self.timestamps[key]
                self.misses += 1
                return None

            self.cache.move_to_end(key)
            self.hits += 1
            return self.cache[key]

    def put(self, key: str, value: str):
        """Add to cache with LRU eviction"""
        with self._lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            else:
                if len(self.cache) >= self.max_size:
                    evict_count = self.max_size // 5
                    for _ in range(evict_count):
                        if self.cache:
                            oldest = next(iter(self.cache))
                            del self.cache[oldest]
                            self.timestamps.pop(oldest, None)

            self.cache[key] = value
            self.timestamps[key] = time.time()

    def get_stats(self) -> Dict:
        """Get cache statistics"""
        with self._lock:
            total = self.hits + self.misses
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": self.hits / max(total, 1),
            }


class OUIDatabase:
    """
    IEEE OUI lookup with MA-L/MA-M/MA-S support

    Priority order for lookups: MA-S (36-bit) -> MA-M (28-bit) -> MA-L (24-bit)
    This ensures the most specific match is returned first.
    """

    OUI_DATA_DIR = "data/oui"

    OUI_URLS = {
        "ma_l": "https://standards-oui.ieee.org/oui/oui.csv",       # ~180K entries
        "ma_m": "https://standards-oui.ieee.org/oui28/mam.csv",     # ~1.5K entries
        "ma_s": "https://standards-oui.ieee.org/oui36/oui36.csv",   # ~500 entries
    }

    # Fallback vendor map for common prefixes when database not available
    FALLBACK_VENDORS = {
        "00:50:56": "VMware",
        "00:0c:29": "VMware",
        "00:05:69": "VMware",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:15:5d": "Microsoft Hyper-V",
        "00:1c:42": "Parallels",
        "dc:a6:32": "Raspberry Pi",
        "b8:27:eb": "Raspberry Pi",
        "e4:5f:01": "Raspberry Pi",
        "28:cd:c1": "Raspberry Pi",
        "d8:3a:dd": "Raspberry Pi",
        "2c:cf:67": "Raspberry Pi",
        "00:50:f2": "Microsoft",
        "00:1b:63": "Apple",
        "00:25:00": "Apple",
        "00:26:bb": "Apple",
        "ac:de:48": "Apple",
        "f0:18:98": "Apple",
        "3c:22:fb": "Apple",
        "a4:83:e7": "Apple",
        "3c:07:54": "Roku",
        "00:04:20": "Roku",
        "b0:a7:37": "Roku",
        "cc:6d:a0": "Google",
        "f4:f5:d8": "Google",
        "18:b4:30": "Google Nest",
        "44:07:0b": "Amazon Echo",
        "84:d6:d0": "Amazon",
        "fc:a6:67": "Amazon",
        "00:17:88": "Philips Hue",
        "00:1c:b3": "Netgear",
        "00:14:6c": "Netgear",
        "a0:63:91": "Netgear",
        "00:1d:7e": "D-Link",
        "00:05:cd": "D-Link",
        "00:0d:88": "D-Link",
        "00:1e:58": "D-Link",
        "00:23:69": "Cisco",
        "00:24:14": "Cisco",
        "00:25:45": "Cisco",
        "00:1a:2b": "Cisco",
        "00:0c:85": "Cisco",
        "88:71:b1": "Intel",
        "00:1e:64": "Intel",
        "00:1f:3b": "Intel",
        "00:22:fa": "Intel",
        "00:24:d7": "Intel",
        "48:2c:6a": "Intel",
        "d4:3d:7e": "Intel",
        "00:1a:4a": "Qumranet/KVM",
        "00:16:3e": "Xen",
    }

    def __init__(self, cache_size: int = 10000, cache_ttl: int = 3600):
        """
        Initialize OUI database

        Args:
            cache_size: Maximum cache entries
            cache_ttl: Cache TTL in seconds
        """
        self._cache = LRUCache(max_size=cache_size, ttl_seconds=cache_ttl)
        self._lock = RLock()

        # Database storage: prefix -> vendor name
        self._ma_l: Dict[str, str] = {}  # 24-bit OUI
        self._ma_m: Dict[str, str] = {}  # 28-bit OUI
        self._ma_s: Dict[str, str] = {}  # 36-bit OUI

        self._initialized = False
        self._last_update: Optional[float] = None

        # Ensure data directory exists
        Path(self.OUI_DATA_DIR).mkdir(parents=True, exist_ok=True)

    def initialize(self) -> bool:
        """
        Load OUI database from local pickle files

        Returns:
            True if database loaded successfully
        """
        if self._initialized:
            return True

        with self._lock:
            loaded = False

            # Try to load cached pickle files
            for db_type in ["ma_l", "ma_m", "ma_s"]:
                pkl_path = Path(self.OUI_DATA_DIR) / f"{db_type}.pkl"
                if pkl_path.exists():
                    try:
                        with open(pkl_path, "rb") as f:
                            data = pickle.load(f)
                            if db_type == "ma_l":
                                self._ma_l = data
                            elif db_type == "ma_m":
                                self._ma_m = data
                            elif db_type == "ma_s":
                                self._ma_s = data
                            loaded = True
                            logger.debug(f"Loaded {len(data)} entries from {pkl_path}")
                    except Exception as e:
                        logger.warning(f"Failed to load {pkl_path}: {e}")

            # Check for last update timestamp
            update_file = Path(self.OUI_DATA_DIR) / "last_update.txt"
            if update_file.exists():
                try:
                    self._last_update = float(update_file.read_text().strip())
                except (ValueError, IOError):
                    pass

            if loaded:
                total = len(self._ma_l) + len(self._ma_m) + len(self._ma_s)
                logger.info(f"OUI database initialized: {total} entries")
                self._initialized = True
                return True

            # No cached data - use fallback
            logger.info("OUI database not cached, using fallback vendors")
            self._initialized = True
            return True

    def update_database(self) -> bool:
        """
        Download and parse IEEE OUI CSV files

        This downloads all three databases (MA-L, MA-M, MA-S), parses them,
        and stores as pickle files for fast loading.

        Returns:
            True if update successful
        """
        logger.info("Updating OUI database from IEEE...")

        session = requests.Session()
        session.headers.update({"User-Agent": "CobaltGraph/1.0"})

        success = True

        for db_type, url in self.OUI_URLS.items():
            try:
                logger.info(f"Downloading {db_type} from {url}...")
                response = session.get(url, timeout=60)
                response.raise_for_status()

                # Parse CSV
                data = self._parse_oui_csv(response.text, db_type)

                if data:
                    # Store in memory
                    with self._lock:
                        if db_type == "ma_l":
                            self._ma_l = data
                        elif db_type == "ma_m":
                            self._ma_m = data
                        elif db_type == "ma_s":
                            self._ma_s = data

                    # Save to pickle
                    pkl_path = Path(self.OUI_DATA_DIR) / f"{db_type}.pkl"
                    with open(pkl_path, "wb") as f:
                        pickle.dump(data, f)

                    logger.info(f"Saved {len(data)} {db_type} entries to {pkl_path}")
                else:
                    logger.warning(f"No entries parsed from {db_type}")
                    success = False

            except RequestException as e:
                logger.error(f"Failed to download {db_type}: {e}")
                success = False
            except Exception as e:
                logger.error(f"Error processing {db_type}: {e}")
                success = False

        # Update timestamp
        if success:
            self._last_update = time.time()
            update_file = Path(self.OUI_DATA_DIR) / "last_update.txt"
            update_file.write_text(str(self._last_update))
            logger.info("OUI database update complete")

        self._initialized = True
        return success

    def _parse_oui_csv(self, csv_content: str, db_type: str) -> Dict[str, str]:
        """
        Parse IEEE OUI CSV format

        Format: Registry,Assignment,Organization Name,Organization Address
        Example: MA-L,00C08D,Mitsubishi Electric Corporation,...

        Args:
            csv_content: Raw CSV content
            db_type: Database type (ma_l, ma_m, ma_s)

        Returns:
            Dictionary mapping prefix to vendor name
        """
        result = {}

        try:
            reader = csv.reader(io.StringIO(csv_content))

            # Skip header row
            next(reader, None)

            for row in reader:
                if len(row) >= 3:
                    # Assignment is hex string (e.g., "00C08D" for MA-L)
                    assignment = row[1].strip().upper()
                    org_name = row[2].strip()

                    if assignment and org_name:
                        # Convert to normalized format based on type
                        if db_type == "ma_l":
                            # 24-bit: 6 hex chars -> XX:XX:XX
                            if len(assignment) == 6:
                                prefix = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}".lower()
                                result[prefix] = org_name
                        elif db_type == "ma_m":
                            # 28-bit: 7 hex chars -> XX:XX:XX:X (first 7 nibbles)
                            if len(assignment) >= 7:
                                # Store as XX:XX:XX:X0 with mask
                                prefix = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}:{assignment[6]}".lower()
                                result[prefix] = org_name
                        elif db_type == "ma_s":
                            # 36-bit: 9 hex chars -> XX:XX:XX:XX:X
                            if len(assignment) >= 9:
                                prefix = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}:{assignment[6:8]}:{assignment[8]}".lower()
                                result[prefix] = org_name

        except csv.Error as e:
            logger.error(f"CSV parsing error: {e}")
        except Exception as e:
            logger.error(f"Error parsing OUI data: {e}")

        return result

    def resolve(self, mac: str) -> Optional[str]:
        """
        Resolve MAC address to vendor name

        Priority: MA-S (36-bit) -> MA-M (28-bit) -> MA-L (24-bit) -> Fallback

        Args:
            mac: MAC address in any common format

        Returns:
            Vendor name or None if not found
        """
        if not mac:
            return None

        # Normalize MAC format: lowercase, colon-separated
        mac_normalized = mac.lower().replace("-", ":").replace(".", ":")

        # Remove any extra characters, ensure proper format
        parts = mac_normalized.split(":")
        if len(parts) == 1 and len(mac_normalized) == 12:
            # Handle XXXXXXXXXXXX format
            parts = [mac_normalized[i:i+2] for i in range(0, 12, 2)]
        elif len(parts) == 3 and all(len(p) == 4 for p in parts):
            # Handle XXXX.XXXX.XXXX format
            hex_str = "".join(parts)
            parts = [hex_str[i:i+2] for i in range(0, 12, 2)]

        if len(parts) < 3:
            return None

        mac_normalized = ":".join(parts[:6])

        # Check cache first
        cached = self._cache.get(mac_normalized)
        if cached is not None:
            return cached if cached != "" else None

        # Initialize if needed
        if not self._initialized:
            self.initialize()

        vendor = None

        with self._lock:
            # Try MA-S (36-bit) - most specific
            if len(parts) >= 5 and self._ma_s:
                prefix_36 = f"{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}:{parts[4][0]}"
                vendor = self._ma_s.get(prefix_36)

            # Try MA-M (28-bit)
            if not vendor and len(parts) >= 4 and self._ma_m:
                prefix_28 = f"{parts[0]}:{parts[1]}:{parts[2]}:{parts[3][0]}"
                vendor = self._ma_m.get(prefix_28)

            # Try MA-L (24-bit)
            if not vendor and self._ma_l:
                prefix_24 = f"{parts[0]}:{parts[1]}:{parts[2]}"
                vendor = self._ma_l.get(prefix_24)

            # Try fallback vendors
            if not vendor:
                prefix_24 = f"{parts[0]}:{parts[1]}:{parts[2]}"
                # Try both lowercase and uppercase in fallback
                vendor = self.FALLBACK_VENDORS.get(prefix_24)
                if not vendor:
                    vendor = self.FALLBACK_VENDORS.get(prefix_24.upper())

        # Cache result (empty string for not found to cache negative lookups)
        self._cache.put(mac_normalized, vendor or "")

        return vendor

    def get_stats(self) -> Dict:
        """Get database statistics"""
        with self._lock:
            return {
                "ma_l_entries": len(self._ma_l),
                "ma_m_entries": len(self._ma_m),
                "ma_s_entries": len(self._ma_s),
                "total_entries": len(self._ma_l) + len(self._ma_m) + len(self._ma_s),
                "fallback_entries": len(self.FALLBACK_VENDORS),
                "last_update": self._last_update,
                "cache": self._cache.get_stats(),
            }

    def needs_update(self, max_age_days: int = 30) -> bool:
        """Check if database needs updating"""
        if not self._last_update:
            return True
        age_seconds = time.time() - self._last_update
        return age_seconds > (max_age_days * 86400)


# Global instance for convenience
_oui_db: Optional[OUIDatabase] = None


def get_oui_database() -> OUIDatabase:
    """Get or create global OUI database instance"""
    global _oui_db
    if _oui_db is None:
        _oui_db = OUIDatabase()
        _oui_db.initialize()
    return _oui_db


def resolve_mac_vendor(mac: str) -> Optional[str]:
    """Convenience function for quick MAC vendor lookup"""
    return get_oui_database().resolve(mac)


if __name__ == "__main__":
    # Test the service
    logging.basicConfig(level=logging.INFO)

    db = OUIDatabase()
    print("Initializing OUI database...")
    db.initialize()

    # Test lookups with fallback data
    test_macs = [
        "dc:a6:32:00:00:00",  # Raspberry Pi
        "00:50:56:ab:cd:ef",  # VMware
        "00:0c:29:12:34:56",  # VMware
        "f0:18:98:11:22:33",  # Apple
        "00:17:88:aa:bb:cc",  # Philips Hue
        "aa:bb:cc:dd:ee:ff",  # Unknown
    ]

    print("\nTest lookups (fallback data):")
    for mac in test_macs:
        vendor = db.resolve(mac)
        print(f"  {mac} -> {vendor or 'Unknown'}")

    print("\nStats:", db.get_stats())

    # Optionally update database
    if db.needs_update():
        print("\nDatabase needs update. Run with --update to download.")
    else:
        print(f"\nDatabase last updated: {db._last_update}")
