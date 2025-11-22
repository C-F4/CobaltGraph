#!/usr/bin/env python3
"""
CobaltGraph IP Reputation Module
Integrates with external threat intelligence services for IP reputation lookups

Supported Services:
- VirusTotal (https://www.virustotal.com)
- AbuseIPDB (https://www.abuseipdb.com)

Features:
- Fallback chain (try services in priority order)
- Rate limiting (avoid hitting API limits)
- Caching (reduce API calls)
- Configurable thresholds
"""

import time
import requests
from typing import Dict, Optional, Tuple
from collections import defaultdict
from datetime import datetime, timedelta


class RateLimiter:
    """Simple rate limiter to avoid hitting API limits"""

    def __init__(self, max_requests_per_minute: int = 4):
        self.max_requests = max_requests_per_minute
        self.requests = defaultdict(list)

    def can_request(self, service: str) -> bool:
        """Check if we can make a request to this service"""
        now = datetime.now()
        cutoff = now - timedelta(minutes=1)

        # Clean old requests
        self.requests[service] = [
            req_time for req_time in self.requests[service]
            if req_time > cutoff
        ]

        # Check if under limit
        return len(self.requests[service]) < self.max_requests

    def record_request(self, service: str):
        """Record that we made a request"""
        self.requests[service].append(datetime.now())

    def wait_if_needed(self, service: str):
        """Wait if we're hitting rate limits"""
        if not self.can_request(service):
            # Wait until the oldest request expires
            oldest = min(self.requests[service])
            wait_until = oldest + timedelta(minutes=1)
            wait_seconds = (wait_until - datetime.now()).total_seconds()

            if wait_seconds > 0:
                time.sleep(wait_seconds + 0.1)  # Add small buffer


class IPReputationCache:
    """Simple in-memory cache for IP reputation lookups"""

    def __init__(self, ttl_seconds: int = 86400):
        self.cache = {}
        self.ttl = ttl_seconds

    def get(self, ip: str, service: str) -> Optional[Dict]:
        """Get cached result if available and not expired"""
        key = f"{service}:{ip}"

        if key in self.cache:
            result, timestamp = self.cache[key]
            age = time.time() - timestamp

            if age < self.ttl:
                return result

            # Expired, remove
            del self.cache[key]

        return None

    def set(self, ip: str, service: str, result: Dict):
        """Cache a result"""
        key = f"{service}:{ip}"
        self.cache[key] = (result, time.time())

    def clear(self):
        """Clear all cached results"""
        self.cache.clear()


class VirusTotalClient:
    """VirusTotal API v3 client for IP reputation lookups"""

    def __init__(self, api_key: str, cache_ttl: int = 86400, malicious_threshold: int = 2):
        self.api_key = api_key
        self.cache = IPReputationCache(ttl_seconds=cache_ttl)
        self.malicious_threshold = malicious_threshold
        self.base_url = "https://www.virustotal.com/api/v3"

    def check_ip(self, ip: str) -> Optional[Tuple[float, Dict]]:
        """
        Check IP reputation on VirusTotal

        Returns:
            Tuple of (threat_score, details) or None if lookup fails
            threat_score: 0.0-1.0 (0=clean, 1=malicious)
            details: Dict with reputation info
        """
        # Check cache first
        cached = self.cache.get(ip, 'virustotal')
        if cached:
            return cached

        # Make API request
        headers = {
            'x-apikey': self.api_key
        }

        try:
            response = requests.get(
                f"{self.base_url}/ip_addresses/{ip}",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)

                total_vendors = malicious + suspicious + harmless + undetected

                # Calculate threat score (0.0-1.0)
                if total_vendors == 0:
                    threat_score = 0.0
                else:
                    # Weight: malicious=1.0, suspicious=0.5
                    weighted_score = (malicious + (suspicious * 0.5)) / total_vendors
                    threat_score = min(1.0, weighted_score * 2)  # Scale up

                # Check threshold
                is_malicious = malicious >= self.malicious_threshold

                details = {
                    'source': 'virustotal',
                    'malicious_vendors': malicious,
                    'suspicious_vendors': suspicious,
                    'total_vendors': total_vendors,
                    'is_malicious': is_malicious,
                    'threat_score': threat_score,
                    'raw_data': stats
                }

                result = (threat_score, details)

                # Cache result
                self.cache.set(ip, 'virustotal', result)

                return result

            elif response.status_code == 404:
                # IP not found in VT database (not necessarily bad)
                result = (0.0, {
                    'source': 'virustotal',
                    'is_malicious': False,
                    'threat_score': 0.0,
                    'note': 'IP not found in VirusTotal database'
                })
                self.cache.set(ip, 'virustotal', result)
                return result

            elif response.status_code == 429:
                # Rate limited
                return None

            else:
                # Other error
                return None

        except requests.RequestException:
            return None


class AbuseIPDBClient:
    """AbuseIPDB API v2 client for IP reputation lookups"""

    def __init__(self, api_key: str, cache_ttl: int = 86400, confidence_threshold: int = 75):
        self.api_key = api_key
        self.cache = IPReputationCache(ttl_seconds=cache_ttl)
        self.confidence_threshold = confidence_threshold
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def check_ip(self, ip: str) -> Optional[Tuple[float, Dict]]:
        """
        Check IP reputation on AbuseIPDB

        Returns:
            Tuple of (threat_score, details) or None if lookup fails
            threat_score: 0.0-1.0 (0=clean, 1=malicious)
            details: Dict with reputation info
        """
        # Check cache first
        cached = self.cache.get(ip, 'abuseipdb')
        if cached:
            return cached

        # Make API request
        headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }

        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,  # Check reports from last 90 days
            'verbose': ''
        }

        try:
            response = requests.get(
                f"{self.base_url}/check",
                headers=headers,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json().get('data', {})

                confidence_score = data.get('abuseConfidenceScore', 0)  # 0-100
                total_reports = data.get('totalReports', 0)
                is_whitelisted = data.get('isWhitelisted', False)
                usage_type = data.get('usageType', 'Unknown')

                # Convert to 0.0-1.0 scale
                threat_score = confidence_score / 100.0

                # Override for whitelisted IPs
                if is_whitelisted:
                    threat_score = 0.0

                # Check threshold
                is_malicious = confidence_score >= self.confidence_threshold

                details = {
                    'source': 'abuseipdb',
                    'confidence_score': confidence_score,
                    'total_reports': total_reports,
                    'is_whitelisted': is_whitelisted,
                    'usage_type': usage_type,
                    'is_malicious': is_malicious,
                    'threat_score': threat_score,
                    'country_code': data.get('countryCode', 'Unknown'),
                    'isp': data.get('isp', 'Unknown')
                }

                result = (threat_score, details)

                # Cache result
                self.cache.set(ip, 'abuseipdb', result)

                return result

            elif response.status_code == 429:
                # Rate limited
                return None

            else:
                # Other error
                return None

        except requests.RequestException:
            return None


class IPReputationManager:
    """
    Manages IP reputation lookups with multiple services

    Features:
    - Priority-based fallback chain
    - Rate limiting
    - Caching
    - Configurable thresholds
    """

    def __init__(self, config: Dict):
        """
        Initialize reputation manager from configuration

        Args:
            config: Configuration dict from config_loader
        """
        self.config = config

        # Initialize clients
        self.virustotal = None
        self.abuseipdb = None

        if config.get('virustotal_enabled') and config.get('virustotal_api_key'):
            self.virustotal = VirusTotalClient(
                api_key=config['virustotal_api_key'],
                cache_ttl=config.get('virustotal_cache_ttl', 86400),
                malicious_threshold=config.get('virustotal_malicious_threshold', 2)
            )

        if config.get('abuseipdb_enabled') and config.get('abuseipdb_api_key'):
            self.abuseipdb = AbuseIPDBClient(
                api_key=config['abuseipdb_api_key'],
                cache_ttl=config.get('abuseipdb_cache_ttl', 86400),
                confidence_threshold=config.get('abuseipdb_confidence_threshold', 75)
            )

        # Parse priority chain
        priority_str = config.get('threat_priority', 'virustotal,abuseipdb,local')
        self.priority = [s.strip() for s in priority_str.split(',')]

        # Rate limiter
        self.rate_limiter = None
        if config.get('enable_rate_limiting', True):
            self.rate_limiter = RateLimiter(
                max_requests_per_minute=config.get('max_requests_per_minute', 4)
            )

        self.fallback_to_local = config.get('fallback_to_local', True)

    def check_ip(self, ip: str) -> Tuple[float, Dict]:
        """
        Check IP reputation using configured services

        Args:
            ip: IP address to check

        Returns:
            Tuple of (threat_score, details)
            threat_score: 0.0-1.0 (0=clean, 1=malicious)
            details: Dict with reputation info from all sources
        """
        all_details = {
            'ip': ip,
            'sources_checked': [],
            'sources_failed': [],
            'threat_scores': {}
        }

        # Try each service in priority order
        for service in self.priority:
            if service == 'virustotal' and self.virustotal:
                # Rate limit check
                if self.rate_limiter:
                    self.rate_limiter.wait_if_needed('virustotal')

                result = self.virustotal.check_ip(ip)

                if self.rate_limiter:
                    self.rate_limiter.record_request('virustotal')

                if result:
                    threat_score, details = result
                    all_details['sources_checked'].append('virustotal')
                    all_details['threat_scores']['virustotal'] = threat_score
                    all_details['virustotal'] = details

                    # Return first successful result
                    return threat_score, all_details
                else:
                    all_details['sources_failed'].append('virustotal')

            elif service == 'abuseipdb' and self.abuseipdb:
                # Rate limit check
                if self.rate_limiter:
                    self.rate_limiter.wait_if_needed('abuseipdb')

                result = self.abuseipdb.check_ip(ip)

                if self.rate_limiter:
                    self.rate_limiter.record_request('abuseipdb')

                if result:
                    threat_score, details = result
                    all_details['sources_checked'].append('abuseipdb')
                    all_details['threat_scores']['abuseipdb'] = threat_score
                    all_details['abuseipdb'] = details

                    # Return first successful result
                    return threat_score, all_details
                else:
                    all_details['sources_failed'].append('abuseipdb')

            elif service == 'local':
                # Fallback to local scoring (basic port-based)
                threat_score = self._local_threat_score(ip)
                all_details['sources_checked'].append('local')
                all_details['threat_scores']['local'] = threat_score
                all_details['local'] = {
                    'source': 'local',
                    'threat_score': threat_score,
                    'note': 'Basic local threat scoring (no external lookup)'
                }
                return threat_score, all_details

        # All services failed
        if self.fallback_to_local:
            threat_score = self._local_threat_score(ip)
            all_details['sources_checked'].append('local_fallback')
            all_details['threat_scores']['local_fallback'] = threat_score
            all_details['local_fallback'] = {
                'source': 'local_fallback',
                'threat_score': threat_score,
                'note': 'All external services failed, using local scoring'
            }
            return threat_score, all_details
        else:
            # Return unknown (neutral score)
            return 0.5, all_details

    def _local_threat_score(self, ip: str) -> float:
        """
        Basic local threat scoring (fallback)

        This is a simple heuristic-based scoring.
        Override this method for custom local scoring logic.
        """
        # Default: treat unknown IPs as low threat
        return 0.2


# Convenience function for integration
def create_reputation_manager(config: Dict) -> IPReputationManager:
    """Create IP reputation manager from config"""
    return IPReputationManager(config)


if __name__ == "__main__":
    # Test the module
    from config_loader import load_config

    config = load_config(verbose=False)

    print("Testing IP Reputation Module")
    print("=" * 50)

    manager = IPReputationManager(config)

    # Test with a known malicious IP (ScanNet)
    test_ips = [
        "8.8.8.8",  # Google DNS (clean)
        "1.1.1.1",  # Cloudflare DNS (clean)
    ]

    for test_ip in test_ips:
        print(f"\nChecking IP: {test_ip}")
        threat_score, details = manager.check_ip(test_ip)
        print(f"  Threat Score: {threat_score:.2f}")
        print(f"  Sources Checked: {details['sources_checked']}")
        print(f"  Sources Failed: {details['sources_failed']}")
        print(f"  Details: {details}")
