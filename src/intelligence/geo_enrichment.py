"""
CobaltGraph Geographic Enrichment
IP geolocation and organization lookup

Services:
- ip-api.com (free, no API key required)
- ipinfo.io (alternative)
- MaxMind GeoLite2 (future)

Features:
- Geographic coordinates
- Country/city information
- ISP/organization data
- Reverse DNS lookup
"""

import logging
import requests
from typing import Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

class GeoEnrichment:
    """
    Geographic enrichment for IP addresses

    Uses public APIs to enrich IP addresses with:
    - Latitude/Longitude
    - Country/City
    - Organization/ISP
    """

    def __init__(self, max_workers: int = 8):
        """
        Initialize geo enrichment

        Args:
            max_workers: Number of concurrent API workers
        """
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        logger.info(f"🌍 Geo enrichment initialized with {max_workers} workers")

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        """
        Lookup geolocation for single IP

        Args:
            ip: IP address to lookup

        Returns:
            Dict with geo data or None if failed
        """
        try:
            # Use ip-api.com (free, no key required)
            response = requests.get(
                f'http://ip-api.com/json/{ip}',
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'city': data.get('city'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'org': data.get('org', data.get('isp')),
                        'as': data.get('as'),
                    }

        except Exception as e:
            logger.debug(f"Geo lookup failed for {ip}: {e}")

        return None

    def lookup_batch(self, ips: list) -> Dict[str, Dict]:
        """
        Lookup multiple IPs concurrently

        Args:
            ips: List of IP addresses

        Returns:
            Dict mapping IP -> geo data
        """
        results = {}

        # Submit all lookups
        futures = {
            self.executor.submit(self.lookup_ip, ip): ip
            for ip in ips
        }

        # Collect results as they complete
        for future in as_completed(futures):
            ip = futures[future]
            try:
                geo_data = future.result()
                if geo_data:
                    results[ip] = geo_data
            except Exception as e:
                logger.error(f"Batch lookup error for {ip}: {e}")

        return results

    def reverse_dns(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup

        Args:
            ip: IP address

        Returns:
            Hostname or None
        """
        try:
            import socket
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return None

    def shutdown(self):
        """Shutdown worker pool"""
        self.executor.shutdown(wait=True)

    def __del__(self):
        """Cleanup on deletion"""
        try:
            self.shutdown()
        except:
            pass
