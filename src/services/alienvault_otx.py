"""
AlienVault OTX (Open Threat Exchange) Service for CobaltGraph

OTX is a community-sourced threat intelligence platform with "pulses"
containing IOCs contributed by security researchers worldwide.

Usage:
    otx = AlienVaultOTXService(api_key="your_key")
    result = otx.check_ip("1.2.3.4")
    if result.pulse_count > 0:
        print(f"Found in {result.pulse_count} pulses")
        print(f"Tags: {result.tags}")
"""

import json
import logging
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional
from urllib.parse import quote

logger = logging.getLogger(__name__)


@dataclass
class OTXResult:
    """Result from AlienVault OTX lookup"""
    indicator: str
    indicator_type: str  # IPv4, domain, hostname, FileHash-*, URL

    # Pulse information
    pulse_count: int = 0
    pulses: List[Dict] = field(default_factory=list)

    # Tags aggregated from all pulses
    tags: List[str] = field(default_factory=list)

    # Timeline
    first_seen: str = ""
    last_seen: str = ""

    # Reputation
    reputation: int = 0  # 0-100, higher is worse
    asn: str = ""
    country: str = ""

    # Related indicators
    related_count: int = 0

    # Metadata
    cached: bool = False
    error: str = ""


@dataclass
class OTXPulse:
    """Information about an OTX pulse"""
    pulse_id: str
    name: str
    description: str = ""
    author: str = ""
    tags: List[str] = field(default_factory=list)
    targeted_countries: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    attack_ids: List[str] = field(default_factory=list)  # MITRE ATT&CK
    created: str = ""
    modified: str = ""


class AlienVaultOTXService:
    """
    AlienVault OTX API integration

    Features:
    - IP reputation lookup
    - Domain/hostname lookup
    - File hash lookup
    - Pulse information (community threat intel)
    - Caching with TTL
    """

    # API endpoints
    BASE_URL = "https://otx.alienvault.com/api/v1"

    # Rate limiting (OTX is generous but we should be polite)
    RATE_LIMIT = 100  # requests per minute

    # Cache settings
    CACHE_TTL = 3600  # 1 hour
    CACHE_SIZE = 10000

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_ttl: int = 3600,
    ):
        """
        Initialize AlienVault OTX service

        Args:
            api_key: OTX API key (required for full access)
            cache_ttl: Cache TTL in seconds
        """
        self.api_key = api_key
        self.cache_ttl = cache_ttl

        # Cache
        self._cache: Dict[str, tuple] = {}  # key -> (result, timestamp)
        self._cache_lock = Lock()

        # Rate limiting
        self._request_times: List[float] = []
        self._rate_lock = Lock()

        # Statistics
        self.stats = {
            "lookups": 0,
            "cache_hits": 0,
            "api_calls": 0,
            "pulse_matches": 0,
            "errors": 0,
        }

        logger.info(
            f"AlienVaultOTXService initialized "
            f"(api_key={'present' if api_key else 'none'})"
        )

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits"""
        with self._rate_lock:
            now = time.time()
            cutoff = now - 60  # Last minute

            # Remove old timestamps
            self._request_times = [t for t in self._request_times if t > cutoff]

            if len(self._request_times) >= self.RATE_LIMIT:
                return False

            return True

    def _record_request(self):
        """Record a request for rate limiting"""
        with self._rate_lock:
            self._request_times.append(time.time())

    def _get_cached(self, key: str) -> Optional[OTXResult]:
        """Get result from cache if valid"""
        with self._cache_lock:
            if key in self._cache:
                result, timestamp = self._cache[key]
                if time.time() - timestamp < self.cache_ttl:
                    self.stats["cache_hits"] += 1
                    result.cached = True
                    return result
                else:
                    del self._cache[key]
        return None

    def _set_cached(self, key: str, result: OTXResult):
        """Store result in cache"""
        with self._cache_lock:
            # Evict old entries if needed
            if len(self._cache) >= self.CACHE_SIZE:
                sorted_items = sorted(
                    self._cache.items(),
                    key=lambda x: x[1][1]
                )
                for old_key, _ in sorted_items[:len(self._cache) // 5]:
                    del self._cache[old_key]

            self._cache[key] = (result, time.time())

    def check_ip(self, ip: str) -> OTXResult:
        """
        Check IP address against OTX

        Args:
            ip: IP address to check

        Returns:
            OTXResult with pulse and reputation information
        """
        self.stats["lookups"] += 1

        cache_key = f"ipv4:{ip}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        result = self._query_indicator("IPv4", ip)
        self._set_cached(cache_key, result)

        if result.pulse_count > 0:
            self.stats["pulse_matches"] += 1

        return result

    def check_domain(self, domain: str) -> OTXResult:
        """
        Check domain against OTX

        Args:
            domain: Domain name to check

        Returns:
            OTXResult with pulse and reputation information
        """
        self.stats["lookups"] += 1

        cache_key = f"domain:{domain}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        result = self._query_indicator("domain", domain)
        self._set_cached(cache_key, result)

        if result.pulse_count > 0:
            self.stats["pulse_matches"] += 1

        return result

    def check_hostname(self, hostname: str) -> OTXResult:
        """
        Check hostname against OTX

        Args:
            hostname: Hostname to check

        Returns:
            OTXResult with pulse and reputation information
        """
        self.stats["lookups"] += 1

        cache_key = f"hostname:{hostname}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        result = self._query_indicator("hostname", hostname)
        self._set_cached(cache_key, result)

        if result.pulse_count > 0:
            self.stats["pulse_matches"] += 1

        return result

    def check_hash(self, file_hash: str, hash_type: str = "auto") -> OTXResult:
        """
        Check file hash against OTX

        Args:
            file_hash: File hash to check
            hash_type: md5, sha1, sha256, or auto (detect from length)

        Returns:
            OTXResult with pulse and malware information
        """
        self.stats["lookups"] += 1

        # Auto-detect hash type
        if hash_type == "auto":
            hash_len = len(file_hash)
            if hash_len == 32:
                hash_type = "FileHash-MD5"
            elif hash_len == 40:
                hash_type = "FileHash-SHA1"
            elif hash_len == 64:
                hash_type = "FileHash-SHA256"
            else:
                return OTXResult(
                    indicator=file_hash,
                    indicator_type="unknown",
                    error="Unknown hash type"
                )
        else:
            hash_type = f"FileHash-{hash_type.upper()}"

        cache_key = f"{hash_type}:{file_hash}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        result = self._query_indicator(hash_type, file_hash)
        self._set_cached(cache_key, result)

        if result.pulse_count > 0:
            self.stats["pulse_matches"] += 1

        return result

    def _query_indicator(self, indicator_type: str, indicator: str) -> OTXResult:
        """Query OTX API for an indicator"""
        result = OTXResult(
            indicator=indicator,
            indicator_type=indicator_type,
        )

        if not self.api_key:
            result.error = "API key required"
            return result

        if not self._check_rate_limit():
            result.error = "Rate limit exceeded"
            return result

        try:
            import urllib.request
            import urllib.error

            self._record_request()
            self.stats["api_calls"] += 1

            # Build API URL
            url = f"{self.BASE_URL}/indicators/{indicator_type}/{quote(indicator)}/general"

            headers = {
                "X-OTX-API-KEY": self.api_key,
                "Accept": "application/json",
                "User-Agent": "CobaltGraph/1.0",
            }

            request = urllib.request.Request(url, headers=headers)
            request.method = "GET"

            with urllib.request.urlopen(request, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))

            return self._parse_response(indicator, indicator_type, data)

        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Indicator not found - not an error
                return result
            elif e.code == 403:
                result.error = "Invalid API key"
            elif e.code == 429:
                result.error = "Rate limit exceeded"
            else:
                result.error = f"HTTP {e.code}"
            logger.debug(f"OTX API error: {e}")
            self.stats["errors"] += 1
            return result

        except Exception as e:
            logger.debug(f"OTX lookup failed: {e}")
            result.error = str(e)
            self.stats["errors"] += 1
            return result

    def _parse_response(self, indicator: str, indicator_type: str, data: Dict) -> OTXResult:
        """Parse API response into OTXResult"""
        result = OTXResult(
            indicator=indicator,
            indicator_type=indicator_type,
        )

        # Pulse information
        pulse_info = data.get("pulse_info", {})
        result.pulse_count = pulse_info.get("count", 0)

        # Parse pulses
        pulses = pulse_info.get("pulses", [])
        all_tags = set()

        for pulse_data in pulses[:10]:  # Limit to first 10 pulses
            pulse = OTXPulse(
                pulse_id=pulse_data.get("id", ""),
                name=pulse_data.get("name", ""),
                description=pulse_data.get("description", ""),
                author=pulse_data.get("author_name", ""),
                tags=pulse_data.get("tags", []),
                targeted_countries=pulse_data.get("targeted_countries", []),
                malware_families=pulse_data.get("malware_families", []),
                attack_ids=pulse_data.get("attack_ids", []),
                created=pulse_data.get("created", ""),
                modified=pulse_data.get("modified", ""),
            )
            result.pulses.append({
                "id": pulse.pulse_id,
                "name": pulse.name,
                "author": pulse.author,
                "tags": pulse.tags,
                "malware_families": pulse.malware_families,
            })

            # Aggregate tags
            all_tags.update(pulse.tags)
            all_tags.update(pulse.malware_families)

        result.tags = list(all_tags)

        # General information (available for IPs)
        if "asn" in data:
            result.asn = data.get("asn", "")
        if "country_code" in data:
            result.country = data.get("country_code", "")

        # Reputation (if available)
        if "reputation" in data:
            result.reputation = data.get("reputation", 0)

        # Related indicators
        if "related" in pulse_info:
            related = pulse_info.get("related", {})
            result.related_count = sum(related.get(k, 0) for k in related)

        return result

    def get_pulse_details(self, pulse_id: str) -> Optional[OTXPulse]:
        """
        Get detailed information about a specific pulse

        Args:
            pulse_id: OTX pulse ID

        Returns:
            OTXPulse with full details, or None on error
        """
        if not self.api_key:
            return None

        if not self._check_rate_limit():
            return None

        try:
            import urllib.request

            self._record_request()
            self.stats["api_calls"] += 1

            url = f"{self.BASE_URL}/pulses/{pulse_id}"

            headers = {
                "X-OTX-API-KEY": self.api_key,
                "Accept": "application/json",
                "User-Agent": "CobaltGraph/1.0",
            }

            request = urllib.request.Request(url, headers=headers)
            request.method = "GET"

            with urllib.request.urlopen(request, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))

            return OTXPulse(
                pulse_id=data.get("id", pulse_id),
                name=data.get("name", ""),
                description=data.get("description", ""),
                author=data.get("author_name", ""),
                tags=data.get("tags", []),
                targeted_countries=data.get("targeted_countries", []),
                malware_families=data.get("malware_families", []),
                attack_ids=data.get("attack_ids", []),
                created=data.get("created", ""),
                modified=data.get("modified", ""),
            )

        except Exception as e:
            logger.debug(f"Failed to get pulse details: {e}")
            return None

    def get_stats(self) -> Dict:
        """Get service statistics"""
        return dict(self.stats)

    def shutdown(self):
        """Graceful shutdown"""
        logger.info("AlienVaultOTXService shutdown complete")
