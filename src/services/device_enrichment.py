#!/usr/bin/env python3
"""
Device Enrichment Service
Passive enrichment of discovered network devices

Features:
- Hostname resolution via system DNS cache (passive, no active probing)
- LRU caching with TTL for performance
- Integration with ASN lookup for device IPs
- No active network probing (mDNS, NetBIOS, ARP scans)
"""

import logging
import socket
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    """Enriched device information"""
    mac: str = ""
    hostname: Optional[str] = None
    ip_addresses: Set[str] = field(default_factory=set)
    vendor: Optional[str] = None

    # Enrichment data
    primary_hostname: Optional[str] = None
    hostnames: Dict[str, str] = field(default_factory=dict)  # ip -> hostname

    # Metadata
    enrichment_timestamp: float = 0.0
    cached: bool = False

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "mac": self.mac,
            "hostname": self.primary_hostname or self.hostname,
            "ip_addresses": list(self.ip_addresses),
            "vendor": self.vendor,
            "hostnames": self.hostnames,
            "enrichment_timestamp": self.enrichment_timestamp,
        }


class LRUCache:
    """Simple LRU cache with TTL support"""

    def __init__(self, max_size: int = 5000, ttl: int = 3600):
        self.max_size = max_size
        self.ttl = ttl
        self.cache: OrderedDict = OrderedDict()
        self.timestamps: Dict[str, float] = {}

    def get(self, key: str) -> Optional[str]:
        """Get value from cache if not expired"""
        if key not in self.cache:
            return None

        # Check TTL
        if time.time() - self.timestamps.get(key, 0) > self.ttl:
            self.cache.pop(key, None)
            self.timestamps.pop(key, None)
            return None

        # Move to end (most recently used)
        self.cache.move_to_end(key)
        return self.cache[key]

    def set(self, key: str, value: str):
        """Set value in cache with current timestamp"""
        # Remove oldest if at capacity
        while len(self.cache) >= self.max_size:
            oldest = next(iter(self.cache))
            self.cache.pop(oldest)
            self.timestamps.pop(oldest, None)

        self.cache[key] = value
        self.timestamps[key] = time.time()
        self.cache.move_to_end(key)

    def __len__(self):
        return len(self.cache)


class DeviceEnrichment:
    """
    Passive device enrichment service.

    Uses only passive techniques:
    - socket.gethostbyaddr() for reverse DNS (uses OS cache)
    - No active network probing
    - No mDNS/NetBIOS queries
    - No ARP scans
    """

    def __init__(
        self,
        cache_size: int = 5000,
        cache_ttl: int = 3600,
        dns_timeout: float = 1.0,
        asn_lookup = None
    ):
        """
        Initialize device enrichment service.

        Args:
            cache_size: Maximum cached hostnames
            cache_ttl: Cache TTL in seconds
            dns_timeout: DNS lookup timeout
            asn_lookup: Optional ASNLookup instance for org data
        """
        self.hostname_cache = LRUCache(max_size=cache_size, ttl=cache_ttl)
        self.dns_timeout = dns_timeout
        self.asn_lookup = asn_lookup

        # Track failed lookups to avoid repeated attempts
        self._failed_ips: Dict[str, float] = {}
        self._failed_ttl = 300  # Retry failed lookups after 5 minutes

        # Stats
        self.stats = {
            "hostname_lookups": 0,
            "hostname_hits": 0,
            "hostname_misses": 0,
            "hostname_failures": 0,
        }

        logger.info(
            f"DeviceEnrichment initialized (cache_size={cache_size}, "
            f"ttl={cache_ttl}s, timeout={dns_timeout}s)"
        )

    def resolve_hostname(self, ip: str) -> Optional[str]:
        """
        Resolve IP to hostname using system DNS resolver.

        This is passive - it uses the OS DNS cache and does not
        perform active network probing.

        Args:
            ip: IP address to resolve

        Returns:
            Hostname if resolved, None otherwise
        """
        if not ip or not self._is_valid_ip(ip):
            return None

        # Skip private IP ranges that won't resolve externally
        if self._is_local_ip(ip):
            return None

        self.stats["hostname_lookups"] += 1

        # Check cache first
        cached = self.hostname_cache.get(ip)
        if cached:
            self.stats["hostname_hits"] += 1
            return cached

        # Check if recently failed
        if ip in self._failed_ips:
            if time.time() - self._failed_ips[ip] < self._failed_ttl:
                return None
            del self._failed_ips[ip]

        # Perform lookup
        try:
            # Set socket timeout for this lookup
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.dns_timeout)

            try:
                hostname, _, _ = socket.gethostbyaddr(ip)

                # Cache successful result
                self.hostname_cache.set(ip, hostname)
                self.stats["hostname_misses"] += 1

                logger.debug(f"Resolved {ip} -> {hostname}")
                return hostname

            finally:
                socket.setdefaulttimeout(old_timeout)

        except (socket.herror, socket.gaierror, socket.timeout, OSError) as e:
            # Mark as failed to avoid repeated lookups
            self._failed_ips[ip] = time.time()
            self.stats["hostname_failures"] += 1
            logger.debug(f"Hostname resolution failed for {ip}: {e}")
            return None

    def enrich_device(self, ip: str, mac: str = None) -> Dict:
        """
        Enrich a device IP with all available passive data.

        Args:
            ip: Device IP address
            mac: Optional MAC address

        Returns:
            Dict with hostname and enrichment data
        """
        result = {
            "ip": ip,
            "mac": mac,
            "hostname": None,
            "asn": None,
            "org": None,
            "org_type": None,
            "trust_score": 0.5,
        }

        # Hostname resolution (passive via OS DNS cache)
        hostname = self.resolve_hostname(ip)
        if hostname:
            result["hostname"] = hostname

        # ASN/Organization lookup if available
        if self.asn_lookup and not self._is_local_ip(ip):
            try:
                asn_info = self.asn_lookup.lookup(ip)
                if asn_info and asn_info.asn > 0:
                    result["asn"] = asn_info.asn
                    result["org"] = asn_info.organization
                    result["org_type"] = asn_info.org_type.value if hasattr(asn_info.org_type, 'value') else str(asn_info.org_type)
                    result["trust_score"] = asn_info.trust_score
            except Exception as e:
                logger.debug(f"ASN lookup failed for {ip}: {e}")

        return result

    def enrich_device_batch(self, ips: list) -> Dict[str, Dict]:
        """
        Enrich multiple device IPs.

        Args:
            ips: List of IP addresses

        Returns:
            Dict mapping IP -> enrichment data
        """
        results = {}
        for ip in ips:
            results[ip] = self.enrich_device(ip)
        return results

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False

    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is a local/private address"""
        if not ip:
            return True

        # Common private ranges
        if ip.startswith(('10.', '192.168.', '127.', '0.')):
            return True

        # 172.16.0.0 - 172.31.255.255
        if ip.startswith('172.'):
            try:
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
            except (ValueError, IndexError):
                pass

        # Link-local
        if ip.startswith('169.254.'):
            return True

        return False

    def get_stats(self) -> Dict:
        """Get enrichment statistics"""
        return {
            **self.stats,
            "cache_size": len(self.hostname_cache),
            "failed_ips_tracked": len(self._failed_ips),
        }

    def clear_cache(self):
        """Clear all caches"""
        self.hostname_cache.cache.clear()
        self.hostname_cache.timestamps.clear()
        self._failed_ips.clear()
        logger.info("DeviceEnrichment cache cleared")
