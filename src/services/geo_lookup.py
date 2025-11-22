#!/usr/bin/env python3
"""
Geo Lookup Service - Clean Minimal Version
IP geolocation using free ip-api.com service
"""

import requests
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class GeoLookup:
    """
    Minimal IP geolocation service
    Uses free ip-api.com (no API key required)
    """

    def __init__(self, config):
        """Initialize geo lookup"""
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CobaltGraph/1.0'})
        self.cache = {}  # Simple in-memory cache

    def lookup(self, ip_address: str) -> Dict:
        """
        Lookup IP geolocation

        Returns dict with:
        - country: Country code (e.g., 'US')
        - country_name: Full country name
        - city: City name
        - region: Region/state
        - latitude: Latitude coordinate
        - longitude: Longitude coordinate
        - isp: Internet service provider
        """
        # Check cache
        if ip_address in self.cache:
            return self.cache[ip_address]

        result = {
            'country': 'Unknown',
            'country_name': 'Unknown',
            'city': 'Unknown',
            'region': '',
            'latitude': 0.0,
            'longitude': 0.0,
            'isp': 'Unknown'
        }

        try:
            # Query ip-api.com (free, no key required)
            url = f"http://ip-api.com/json/{ip_address}"
            response = self.session.get(url, timeout=3)

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result = {
                        'country': data.get('countryCode', 'Unknown'),
                        'country_name': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', ''),
                        'latitude': data.get('lat', 0.0),
                        'longitude': data.get('lon', 0.0),
                        'isp': data.get('isp', 'Unknown')
                    }

                    # Cache result
                    self.cache[ip_address] = result

        except Exception as e:
            logger.debug(f"Geo lookup failed for {ip_address}: {e}")

        return result
