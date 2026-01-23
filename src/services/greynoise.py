"""
GreyNoise Integration Service for CobaltGraph

GreyNoise identifies IPs that are mass-scanning the internet (noise)
and common business services (RIOT). This helps REDUCE false positives
by identifying known benign scanners and legitimate services.

Usage:
    gn = GreyNoiseService(api_key="your_key")
    result = gn.check_ip("1.2.3.4")
    if result.riot:
        print(f"Known business service: {result.name}")
    elif result.noise and result.classification == "benign":
        print(f"Known benign scanner: {result.name}")
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
class GreyNoiseResult:
    """Result from GreyNoise IP check"""
    ip: str
    seen: bool = False  # Has GreyNoise seen this IP?
    classification: str = "unknown"  # benign, malicious, unknown
    name: str = ""  # Name of scanner/service (if known)
    link: str = ""  # Link to GreyNoise visualizer

    # RIOT (Rule It OuT) - Known business services
    riot: bool = False
    riot_category: str = ""  # cdn, cloud_provider, isp, etc.
    riot_trust_level: str = ""  # 1 (high trust) to 2 (low trust)

    # NOISE - Known internet scanners
    noise: bool = False
    noise_first_seen: str = ""
    noise_last_seen: str = ""

    # Actor information
    actor: str = ""  # Named actor (Shodan, Censys, etc.)
    tags: List[str] = field(default_factory=list)

    # Metadata
    cached: bool = False
    error: str = ""


class GreyNoiseService:
    """
    GreyNoise API integration for false positive reduction

    Features:
    - RIOT database: Identifies known business services (CDNs, cloud providers)
    - NOISE database: Identifies known internet scanners (Shodan, Censys, etc.)
    - Community API: Free tier with basic lookups
    - Caching: Reduces API calls for repeated lookups
    """

    # API endpoints
    COMMUNITY_API = "https://api.greynoise.io/v3/community/"
    RIOT_API = "https://api.greynoise.io/v2/riot/"
    NOISE_API = "https://api.greynoise.io/v2/noise/quick/"

    # Rate limiting
    RATE_LIMIT_COMMUNITY = 50  # requests per day (free tier)
    RATE_LIMIT_PAID = 500  # requests per minute (paid tier)

    # Cache settings
    CACHE_TTL = 3600  # 1 hour
    CACHE_SIZE = 10000

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_ttl: int = 3600,
        use_community_api: bool = True,
    ):
        """
        Initialize GreyNoise service

        Args:
            api_key: GreyNoise API key (optional for community API)
            cache_ttl: Cache TTL in seconds
            use_community_api: Use free community API (limited but no key needed)
        """
        self.api_key = api_key
        self.cache_ttl = cache_ttl
        self.use_community_api = use_community_api

        # Cache
        self._cache: Dict[str, tuple] = {}  # ip -> (result, timestamp)
        self._cache_lock = Lock()

        # Rate limiting
        self._request_count = 0
        self._request_reset = time.time() + 86400  # Daily reset for community
        self._rate_lock = Lock()

        # Statistics
        self.stats = {
            "lookups": 0,
            "cache_hits": 0,
            "api_calls": 0,
            "riot_matches": 0,
            "noise_matches": 0,
            "errors": 0,
        }

        # Known RIOT services (fallback when API unavailable)
        self._known_riot = self._load_known_riot()

        # Known benign scanners (fallback)
        self._known_scanners = self._load_known_scanners()

        logger.info(
            f"GreyNoiseService initialized "
            f"(api_key={'present' if api_key else 'none'}, "
            f"community={use_community_api})"
        )

    def _load_known_riot(self) -> Dict[str, Dict]:
        """
        Load known RIOT entries for offline/fallback use

        These are well-known services that are almost certainly benign.
        """
        return {
            # Cloudflare DNS
            "1.1.1.1": {"name": "Cloudflare DNS", "category": "dns", "trust": "1"},
            "1.0.0.1": {"name": "Cloudflare DNS", "category": "dns", "trust": "1"},
            # Google DNS
            "8.8.8.8": {"name": "Google DNS", "category": "dns", "trust": "1"},
            "8.8.4.4": {"name": "Google DNS", "category": "dns", "trust": "1"},
            # Quad9 DNS
            "9.9.9.9": {"name": "Quad9 DNS", "category": "dns", "trust": "1"},
            # OpenDNS
            "208.67.222.222": {"name": "OpenDNS", "category": "dns", "trust": "1"},
            "208.67.220.220": {"name": "OpenDNS", "category": "dns", "trust": "1"},
        }

    def _load_known_scanners(self) -> Dict[str, Dict]:
        """
        Load known benign scanner information for offline/fallback use

        These are legitimate security research scanners.
        """
        return {
            # Shodan (some known IPs - they rotate frequently)
            # Censys (some known IPs)
            # Note: These rotate frequently, so API is preferred
        }

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits"""
        with self._rate_lock:
            now = time.time()

            # Reset counter if day has passed
            if now > self._request_reset:
                self._request_count = 0
                self._request_reset = now + 86400

            limit = self.RATE_LIMIT_PAID if self.api_key else self.RATE_LIMIT_COMMUNITY
            if self._request_count >= limit:
                return False

            return True

    def _increment_request_count(self):
        """Increment the request counter"""
        with self._rate_lock:
            self._request_count += 1

    def _get_cached(self, ip: str) -> Optional[GreyNoiseResult]:
        """Get result from cache if valid"""
        with self._cache_lock:
            if ip in self._cache:
                result, timestamp = self._cache[ip]
                if time.time() - timestamp < self.cache_ttl:
                    self.stats["cache_hits"] += 1
                    result.cached = True
                    return result
                else:
                    del self._cache[ip]
        return None

    def _set_cached(self, ip: str, result: GreyNoiseResult):
        """Store result in cache"""
        with self._cache_lock:
            # Evict old entries if needed
            if len(self._cache) >= self.CACHE_SIZE:
                # Remove oldest 20%
                sorted_items = sorted(
                    self._cache.items(),
                    key=lambda x: x[1][1]
                )
                for old_ip, _ in sorted_items[:len(self._cache) // 5]:
                    del self._cache[old_ip]

            self._cache[ip] = (result, time.time())

    def check_ip(self, ip: str) -> GreyNoiseResult:
        """
        Check IP against GreyNoise databases

        Args:
            ip: IP address to check

        Returns:
            GreyNoiseResult with RIOT/NOISE classification
        """
        self.stats["lookups"] += 1

        # Check cache first
        cached = self._get_cached(ip)
        if cached:
            return cached

        # Check known RIOT entries (offline fallback)
        if ip in self._known_riot:
            riot_info = self._known_riot[ip]
            result = GreyNoiseResult(
                ip=ip,
                seen=True,
                classification="benign",
                name=riot_info["name"],
                riot=True,
                riot_category=riot_info["category"],
                riot_trust_level=riot_info["trust"],
            )
            self._set_cached(ip, result)
            self.stats["riot_matches"] += 1
            return result

        # Try API lookup if available
        if self._check_rate_limit():
            api_result = self._query_api(ip)
            if api_result and not api_result.error:
                self._set_cached(ip, api_result)
                if api_result.riot:
                    self.stats["riot_matches"] += 1
                if api_result.noise:
                    self.stats["noise_matches"] += 1
                return api_result

        # Return empty result if no data
        result = GreyNoiseResult(ip=ip)
        self._set_cached(ip, result)
        return result

    def _query_api(self, ip: str) -> Optional[GreyNoiseResult]:
        """Query GreyNoise API"""
        try:
            import urllib.request
            import urllib.error

            self._increment_request_count()
            self.stats["api_calls"] += 1

            # Use community API (free, no key needed)
            if self.use_community_api:
                url = f"{self.COMMUNITY_API}{quote(ip)}"
                headers = {}
                if self.api_key:
                    headers["key"] = self.api_key
            else:
                # RIOT API (requires key)
                url = f"{self.RIOT_API}{quote(ip)}"
                if not self.api_key:
                    return None
                headers = {"key": self.api_key}

            headers["Accept"] = "application/json"
            headers["User-Agent"] = "CobaltGraph/1.0"

            request = urllib.request.Request(url, headers=headers)
            request.method = "GET"

            with urllib.request.urlopen(request, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))

            return self._parse_response(ip, data)

        except urllib.error.HTTPError as e:
            if e.code == 404:
                # IP not found - not an error
                return GreyNoiseResult(ip=ip, seen=False)
            elif e.code == 429:
                logger.warning("GreyNoise rate limit exceeded")
            else:
                logger.debug(f"GreyNoise API error: {e}")
            self.stats["errors"] += 1
            return GreyNoiseResult(ip=ip, error=f"HTTP {e.code}")

        except Exception as e:
            logger.debug(f"GreyNoise lookup failed: {e}")
            self.stats["errors"] += 1
            return GreyNoiseResult(ip=ip, error=str(e))

    def _parse_response(self, ip: str, data: Dict) -> GreyNoiseResult:
        """Parse API response into GreyNoiseResult"""
        result = GreyNoiseResult(ip=ip)

        # Community API response format
        if "noise" in data:
            result.noise = data.get("noise", False)

        if "riot" in data:
            result.riot = data.get("riot", False)

        result.classification = data.get("classification", "unknown")
        result.name = data.get("name", "")
        result.link = data.get("link", "")

        # Full API response has more details
        if "seen" in data:
            result.seen = data.get("seen", False)

        if "actor" in data:
            result.actor = data.get("actor", "")

        if "tags" in data:
            result.tags = data.get("tags", [])

        if "first_seen" in data:
            result.noise_first_seen = data.get("first_seen", "")

        if "last_seen" in data:
            result.noise_last_seen = data.get("last_seen", "")

        # RIOT-specific fields
        if "category" in data:
            result.riot_category = data.get("category", "")

        if "trust_level" in data:
            result.riot_trust_level = str(data.get("trust_level", ""))

        # Mark as seen if any classification exists
        if result.riot or result.noise or result.classification != "unknown":
            result.seen = True

        return result

    def is_benign(self, ip: str) -> bool:
        """
        Quick check if IP is known to be benign

        Returns True if:
        - IP is in RIOT database (known business service)
        - IP is a benign scanner in NOISE database
        """
        result = self.check_ip(ip)
        return result.riot or (result.noise and result.classification == "benign")

    def get_stats(self) -> Dict:
        """Get service statistics"""
        return dict(self.stats)

    def shutdown(self):
        """Graceful shutdown"""
        logger.info("GreyNoiseService shutdown complete")
