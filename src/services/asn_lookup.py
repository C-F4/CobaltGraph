#!/usr/bin/env python3
"""
ASN & Organization Lookup Service
Multi-source ASN resolution with organization classification and TTL-based hop detection

Features:
- Team Cymru DNS-based ASN lookup (free, no API key)
- ip-api.com ASN/org data (backup)
- Organization classification (cloud providers, CDNs, ISPs)
- TTL-based passive hop detection
- LRU caching with configurable TTL
- Bulk lookup support with rate limiting
"""

import logging
import socket
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
import re

import requests
from requests.exceptions import RequestException, Timeout

logger = logging.getLogger(__name__)


class OrgType(Enum):
    """Organization classification types"""
    CLOUD_PROVIDER = "cloud"          # AWS, Azure, GCP, DigitalOcean, etc.
    CDN = "cdn"                        # Cloudflare, Akamai, Fastly, etc.
    HOSTING = "hosting"                # OVH, Hetzner, Linode, etc.
    ISP_RESIDENTIAL = "isp_residential"  # Comcast, AT&T, Verizon, etc.
    ISP_BUSINESS = "isp_business"      # Business internet
    ENTERPRISE = "enterprise"          # Large corporations
    EDUCATION = "education"            # Universities, research
    GOVERNMENT = "government"          # Government networks
    TOR_PROXY = "tor_proxy"            # Tor exit nodes, VPNs
    UNKNOWN = "unknown"


@dataclass
class ASNInfo:
    """ASN lookup result with organization data"""
    asn: int = 0                           # Autonomous System Number
    asn_name: str = ""                     # AS name (e.g., "GOOGLE")
    organization: str = ""                 # Organization name
    org_type: OrgType = OrgType.UNKNOWN    # Classification
    country: str = ""                      # Country code
    cidr: str = ""                         # IP CIDR block
    rir: str = ""                          # Regional Internet Registry
    description: str = ""                  # Additional description

    # TTL-based hop estimation
    estimated_hops: int = 0                # Estimated network hops
    ttl_observed: int = 0                  # Observed TTL value
    initial_ttl: int = 0                   # Estimated initial TTL

    # Trust scoring
    trust_score: float = 0.5               # 0.0 = untrusted, 1.0 = highly trusted

    # Metadata
    lookup_source: str = ""                # Source of this data
    lookup_timestamp: float = 0.0          # When lookup was performed
    cached: bool = False                   # Whether from cache

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "asn": self.asn,
            "asn_name": self.asn_name,
            "organization": self.organization,
            "org_type": self.org_type.value,
            "country": self.country,
            "cidr": self.cidr,
            "rir": self.rir,
            "description": self.description,
            "estimated_hops": self.estimated_hops,
            "ttl_observed": self.ttl_observed,
            "initial_ttl": self.initial_ttl,
            "trust_score": self.trust_score,
            "lookup_source": self.lookup_source,
            "lookup_timestamp": self.lookup_timestamp,
        }


class LRUCache:
    """
    Thread-safe LRU cache with TTL - OPTIMIZED

    Performance features:
    - RLock for thread-safe concurrent access
    - Batch eviction (20% at once) to reduce lock contention
    - Statistics tracking for cache efficiency monitoring
    """

    def __init__(self, max_size: int = 10000, ttl_seconds: int = 3600):
        from threading import RLock

        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: OrderedDict = OrderedDict()
        self.timestamps: Dict[str, float] = {}
        self._lock = RLock()

        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get(self, key: str) -> Optional[ASNInfo]:
        """Get from cache if exists and not expired (thread-safe)"""
        with self._lock:
            if key not in self.cache:
                self.misses += 1
                return None

            # Check TTL
            if time.time() - self.timestamps.get(key, 0) > self.ttl_seconds:
                del self.cache[key]
                del self.timestamps[key]
                self.misses += 1
                return None

            # Move to end (most recently used)
            self.cache.move_to_end(key)
            result = self.cache[key]
            result.cached = True
            self.hits += 1
            return result

    def put(self, key: str, value: ASNInfo):
        """Add to cache with LRU eviction (thread-safe)"""
        with self._lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            else:
                # Batch eviction - remove 20% when full
                if len(self.cache) >= self.max_size:
                    evict_count = self.max_size // 5
                    for _ in range(evict_count):
                        if self.cache:
                            oldest = next(iter(self.cache))
                            del self.cache[oldest]
                            if oldest in self.timestamps:
                                del self.timestamps[oldest]
                            self.evictions += 1

            self.cache[key] = value
            self.timestamps[key] = time.time()

    def get_stats(self) -> Dict:
        """Get cache performance statistics"""
        with self._lock:
            total = self.hits + self.misses
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "hit_rate": self.hits / max(total, 1),
            }


class ASNLookup:
    """
    Multi-source ASN lookup service with organization classification

    Primary source: Team Cymru DNS (free, reliable)
    Backup source: ip-api.com (provides ISP/org data)
    """

    # Organization classification patterns
    # Cloud providers
    CLOUD_PATTERNS = {
        r'amazon|aws|ec2': ('Amazon Web Services', OrgType.CLOUD_PROVIDER, 0.8),
        r'microsoft|azure': ('Microsoft Azure', OrgType.CLOUD_PROVIDER, 0.8),
        r'google|gcp|google cloud': ('Google Cloud', OrgType.CLOUD_PROVIDER, 0.8),
        r'digitalocean': ('DigitalOcean', OrgType.CLOUD_PROVIDER, 0.7),
        r'linode|akamai connected': ('Linode/Akamai', OrgType.CLOUD_PROVIDER, 0.7),
        r'vultr': ('Vultr', OrgType.CLOUD_PROVIDER, 0.6),
        r'oracle.*cloud': ('Oracle Cloud', OrgType.CLOUD_PROVIDER, 0.7),
        r'alibaba|aliyun': ('Alibaba Cloud', OrgType.CLOUD_PROVIDER, 0.6),
        r'tencent': ('Tencent Cloud', OrgType.CLOUD_PROVIDER, 0.6),
    }

    # CDN providers
    CDN_PATTERNS = {
        r'cloudflare': ('Cloudflare', OrgType.CDN, 0.85),
        r'akamai': ('Akamai', OrgType.CDN, 0.8),
        r'fastly': ('Fastly', OrgType.CDN, 0.8),
        r'cloudfront': ('Amazon CloudFront', OrgType.CDN, 0.8),
        r'incapsula|imperva': ('Imperva', OrgType.CDN, 0.75),
        r'stackpath|highwinds': ('StackPath', OrgType.CDN, 0.7),
        r'limelight': ('Limelight', OrgType.CDN, 0.7),
        r'edgecast|verizon digital': ('Verizon EdgeCast', OrgType.CDN, 0.75),
    }

    # Hosting providers
    HOSTING_PATTERNS = {
        r'ovh': ('OVH', OrgType.HOSTING, 0.5),
        r'hetzner': ('Hetzner', OrgType.HOSTING, 0.5),
        r'hostinger': ('Hostinger', OrgType.HOSTING, 0.4),
        r'godaddy': ('GoDaddy', OrgType.HOSTING, 0.5),
        r'bluehost': ('Bluehost', OrgType.HOSTING, 0.5),
        r'dreamhost': ('DreamHost', OrgType.HOSTING, 0.5),
        r'hostgator': ('HostGator', OrgType.HOSTING, 0.4),
        r'ionos|1&1': ('IONOS', OrgType.HOSTING, 0.5),
        r'contabo': ('Contabo', OrgType.HOSTING, 0.4),
        r'scaleway': ('Scaleway', OrgType.HOSTING, 0.5),
    }

    # Major ISPs (residential)
    ISP_RESIDENTIAL_PATTERNS = {
        r'comcast|xfinity': ('Comcast', OrgType.ISP_RESIDENTIAL, 0.6),
        r'at&t|att-internet': ('AT&T', OrgType.ISP_RESIDENTIAL, 0.6),
        r'verizon(?!.*digital)': ('Verizon', OrgType.ISP_RESIDENTIAL, 0.6),
        r'spectrum|charter': ('Spectrum', OrgType.ISP_RESIDENTIAL, 0.6),
        r'cox comm': ('Cox', OrgType.ISP_RESIDENTIAL, 0.6),
        r'centurylink|lumen': ('Lumen/CenturyLink', OrgType.ISP_RESIDENTIAL, 0.6),
        r'frontier comm': ('Frontier', OrgType.ISP_RESIDENTIAL, 0.5),
        r't-mobile|sprint': ('T-Mobile', OrgType.ISP_RESIDENTIAL, 0.6),
        r'vodafone': ('Vodafone', OrgType.ISP_RESIDENTIAL, 0.6),
        r'british telecom|bt ': ('BT', OrgType.ISP_RESIDENTIAL, 0.6),
        r'deutsche telekom': ('Deutsche Telekom', OrgType.ISP_RESIDENTIAL, 0.6),
        r'orange s\.a': ('Orange', OrgType.ISP_RESIDENTIAL, 0.6),
    }

    # Tor/VPN/Proxy indicators
    TOR_PROXY_PATTERNS = {
        r'tor exit|tor-exit': ('Tor Exit Node', OrgType.TOR_PROXY, 0.1),
        r'private internet access|pia': ('PIA VPN', OrgType.TOR_PROXY, 0.3),
        r'nordvpn': ('NordVPN', OrgType.TOR_PROXY, 0.3),
        r'expressvpn': ('ExpressVPN', OrgType.TOR_PROXY, 0.3),
        r'mullvad': ('Mullvad VPN', OrgType.TOR_PROXY, 0.3),
        r'protonvpn|proton ag': ('ProtonVPN', OrgType.TOR_PROXY, 0.3),
    }

    # Education
    EDUCATION_PATTERNS = {
        r'university|\.edu|college|academic': ('Educational Institution', OrgType.EDUCATION, 0.7),
        r'research|\.ac\.|institute': ('Research Institution', OrgType.EDUCATION, 0.7),
    }

    # Government
    GOV_PATTERNS = {
        r'\.gov|government|federal|ministry': ('Government', OrgType.GOVERNMENT, 0.7),
        r'department of|military|\.mil': ('Government/Military', OrgType.GOVERNMENT, 0.7),
    }

    # Enterprise (major tech companies)
    ENTERPRISE_PATTERNS = {
        r'apple inc': ('Apple', OrgType.ENTERPRISE, 0.85),
        r'facebook|meta platforms': ('Meta', OrgType.ENTERPRISE, 0.75),
        r'netflix': ('Netflix', OrgType.ENTERPRISE, 0.8),
        r'twitter|x corp': ('X/Twitter', OrgType.ENTERPRISE, 0.7),
        r'github': ('GitHub', OrgType.ENTERPRISE, 0.8),
        r'linkedin': ('LinkedIn', OrgType.ENTERPRISE, 0.75),
        r'paypal': ('PayPal', OrgType.ENTERPRISE, 0.8),
        r'ebay': ('eBay', OrgType.ENTERPRISE, 0.75),
        r'salesforce': ('Salesforce', OrgType.ENTERPRISE, 0.8),
        r'adobe': ('Adobe', OrgType.ENTERPRISE, 0.8),
        r'cisco': ('Cisco', OrgType.ENTERPRISE, 0.8),
        r'ibm': ('IBM', OrgType.ENTERPRISE, 0.8),
        r'oracle(?!.*cloud)': ('Oracle', OrgType.ENTERPRISE, 0.8),
    }

    # Common initial TTL values by OS
    COMMON_INITIAL_TTLS = [64, 128, 255, 32]  # Linux, Windows, Solaris/old, rare

    def __init__(self, config=None, cache_size: int = 10000, cache_ttl: int = 3600):
        """
        Initialize ASN lookup service

        Args:
            config: Optional configuration object
            cache_size: Maximum cache entries
            cache_ttl: Cache TTL in seconds
        """
        self.config = config
        self.cache = LRUCache(max_size=cache_size, ttl_seconds=cache_ttl)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CobaltGraph/1.0"})

        # Rate limiting
        self.last_request_time = 0.0
        self.min_request_interval = 0.1  # 100ms between requests

        # Stats
        self.lookups_total = 0
        self.lookups_cached = 0
        self.lookups_cymru = 0
        self.lookups_ipapi = 0

        # Compile all patterns
        self._compiled_patterns = self._compile_patterns()

    def _compile_patterns(self) -> List[Tuple[re.Pattern, str, OrgType, float]]:
        """Compile all classification patterns"""
        patterns = []
        all_pattern_dicts = [
            self.CLOUD_PATTERNS,
            self.CDN_PATTERNS,
            self.HOSTING_PATTERNS,
            self.ISP_RESIDENTIAL_PATTERNS,
            self.TOR_PROXY_PATTERNS,
            self.EDUCATION_PATTERNS,
            self.GOV_PATTERNS,
            self.ENTERPRISE_PATTERNS,
        ]

        for pattern_dict in all_pattern_dicts:
            for pattern, (name, org_type, trust) in pattern_dict.items():
                compiled = re.compile(pattern, re.IGNORECASE)
                patterns.append((compiled, name, org_type, trust))

        return patterns

    def lookup(self, ip_address: str, ttl: int = 0) -> ASNInfo:
        """
        Lookup ASN and organization for IP address

        Args:
            ip_address: IPv4 address to lookup
            ttl: Observed TTL value (for hop estimation)

        Returns:
            ASNInfo with ASN, organization, and hop data
        """
        self.lookups_total += 1

        # Check cache first
        cached = self.cache.get(ip_address)
        if cached:
            self.lookups_cached += 1
            # Update TTL-based hop estimation if new TTL provided
            if ttl > 0:
                cached.ttl_observed = ttl
                cached.initial_ttl, cached.estimated_hops = self._estimate_hops(ttl)
            return cached

        # Try Team Cymru DNS first (most reliable for ASN)
        result = self._lookup_cymru(ip_address)

        # If Cymru fails or has limited data, try ip-api
        if result.asn == 0 or not result.organization:
            ipapi_result = self._lookup_ipapi(ip_address)
            # Merge results
            if ipapi_result.asn > 0 and result.asn == 0:
                result.asn = ipapi_result.asn
                result.asn_name = ipapi_result.asn_name
            if ipapi_result.organization and not result.organization:
                result.organization = ipapi_result.organization
            if ipapi_result.country and not result.country:
                result.country = ipapi_result.country

        # Classify organization
        result = self._classify_organization(result)

        # Calculate hop estimation from TTL
        if ttl > 0:
            result.ttl_observed = ttl
            result.initial_ttl, result.estimated_hops = self._estimate_hops(ttl)

        # Timestamp
        result.lookup_timestamp = time.time()

        # Cache result
        self.cache.put(ip_address, result)

        return result

    def _lookup_cymru(self, ip_address: str) -> ASNInfo:
        """
        Lookup ASN via Team Cymru DNS

        Query format: Reverse IP octets + .origin.asn.cymru.com
        Response: ASN | IP/Prefix | Country | RIR | Allocated Date
        """
        result = ASNInfo(lookup_source="cymru")

        try:
            # Build reversed IP query
            octets = ip_address.split('.')
            if len(octets) != 4:
                return result

            reversed_ip = '.'.join(reversed(octets))
            query = f"{reversed_ip}.origin.asn.cymru.com"

            # DNS TXT lookup
            try:
                answers = socket.gethostbyname_ex(query)
                # gethostbyname_ex doesn't give TXT records, use different approach
            except socket.gaierror:
                pass

            # Use DNS resolver for TXT records
            import subprocess
            proc = subprocess.run(
                ['dig', '+short', 'TXT', query],
                capture_output=True,
                text=True,
                timeout=5
            )

            if proc.returncode == 0 and proc.stdout.strip():
                # Parse response: "ASN | IP/Prefix | Country | RIR | Date"
                txt = proc.stdout.strip().strip('"')
                parts = [p.strip() for p in txt.split('|')]

                if len(parts) >= 3:
                    result.asn = int(parts[0]) if parts[0].isdigit() else 0
                    result.cidr = parts[1] if len(parts) > 1 else ""
                    result.country = parts[2] if len(parts) > 2 else ""
                    result.rir = parts[3] if len(parts) > 3 else ""

                    # Get AS name with second query
                    if result.asn > 0:
                        as_query = f"AS{result.asn}.asn.cymru.com"
                        proc2 = subprocess.run(
                            ['dig', '+short', 'TXT', as_query],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if proc2.returncode == 0 and proc2.stdout.strip():
                            # "ASN | Country | RIR | Date | AS Name"
                            txt2 = proc2.stdout.strip().strip('"')
                            parts2 = [p.strip() for p in txt2.split('|')]
                            if len(parts2) >= 5:
                                result.asn_name = parts2[4]
                                result.organization = parts2[4]

                    self.lookups_cymru += 1
                    logger.debug(f"Cymru lookup: {ip_address} -> AS{result.asn} ({result.asn_name})")

        except Exception as e:
            logger.debug(f"Cymru lookup failed for {ip_address}: {e}")

        return result

    def _lookup_ipapi(self, ip_address: str) -> ASNInfo:
        """
        Lookup ASN via ip-api.com
        Returns ISP, org, and ASN data
        """
        result = ASNInfo(lookup_source="ipapi")

        try:
            # Rate limiting
            elapsed = time.time() - self.last_request_time
            if elapsed < self.min_request_interval:
                time.sleep(self.min_request_interval - elapsed)
            self.last_request_time = time.time()

            # Query ip-api with ASN field
            url = f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,isp,org,as,asname"
            response = self.session.get(url, timeout=3)

            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    result.country = data.get("countryCode", "")
                    result.organization = data.get("org", "") or data.get("isp", "")

                    # Parse AS field (format: "AS12345 Organization Name")
                    as_field = data.get("as", "")
                    if as_field:
                        match = re.match(r'AS(\d+)\s*(.*)', as_field)
                        if match:
                            result.asn = int(match.group(1))
                            result.asn_name = match.group(2).strip() or data.get("asname", "")

                    self.lookups_ipapi += 1
                    logger.debug(f"ip-api lookup: {ip_address} -> AS{result.asn} ({result.organization})")

        except (RequestException, Timeout) as e:
            logger.debug(f"ip-api lookup failed for {ip_address}: {e}")
        except Exception as e:
            logger.debug(f"ip-api lookup error for {ip_address}: {e}")

        return result

    def _classify_organization(self, info: ASNInfo) -> ASNInfo:
        """
        Classify organization type and calculate trust score

        Args:
            info: ASNInfo to classify

        Returns:
            Updated ASNInfo with org_type and trust_score
        """
        # Combine all text fields for pattern matching
        search_text = f"{info.organization} {info.asn_name} {info.description}".lower()

        # Check against all patterns
        for compiled_pattern, name, org_type, trust in self._compiled_patterns:
            if compiled_pattern.search(search_text):
                info.org_type = org_type
                info.trust_score = trust
                # Use pattern name if more specific than current org name
                if len(name) > 3 and (not info.organization or len(info.organization) > 50):
                    info.description = info.organization
                    info.organization = name
                logger.debug(f"Classified {info.organization} as {org_type.value} (trust: {trust})")
                return info

        # Default classification based on generic patterns
        if 'hosting' in search_text or 'host' in search_text:
            info.org_type = OrgType.HOSTING
            info.trust_score = 0.4
        elif 'telecom' in search_text or 'communications' in search_text:
            info.org_type = OrgType.ISP_RESIDENTIAL
            info.trust_score = 0.5
        else:
            info.org_type = OrgType.UNKNOWN
            info.trust_score = 0.5

        return info

    def _estimate_hops(self, observed_ttl: int) -> Tuple[int, int]:
        """
        Estimate network hops from observed TTL

        TTL decrements by 1 at each router hop.
        Common initial TTL values:
        - Linux/Unix: 64
        - Windows: 128
        - Solaris/AIX: 255
        - Some embedded: 32

        Args:
            observed_ttl: TTL value from received packet

        Returns:
            Tuple of (estimated_initial_ttl, estimated_hops)
        """
        if observed_ttl <= 0:
            return (0, 0)

        # Find most likely initial TTL
        best_initial = 64
        min_hops = 999

        for initial in self.COMMON_INITIAL_TTLS:
            if initial >= observed_ttl:
                hops = initial - observed_ttl
                if hops < min_hops:
                    min_hops = hops
                    best_initial = initial

        # Sanity check - more than 30 hops is unusual
        if min_hops > 30:
            # Might be a non-standard initial TTL
            # Assume the closest power of 2 or common value
            for check in [32, 60, 64, 128, 255]:
                if check >= observed_ttl:
                    hops = check - observed_ttl
                    if hops <= 30:
                        return (check, hops)

        return (best_initial, max(0, min_hops))

    def lookup_bulk(self, ip_addresses: List[str], ttls: Optional[List[int]] = None) -> List[ASNInfo]:
        """
        Bulk lookup for multiple IPs

        Args:
            ip_addresses: List of IPs to lookup
            ttls: Optional list of TTL values (parallel to ip_addresses)

        Returns:
            List of ASNInfo results
        """
        results = []
        ttls = ttls or [0] * len(ip_addresses)

        for ip, ttl in zip(ip_addresses, ttls):
            result = self.lookup(ip, ttl)
            results.append(result)

        return results

    def get_stats(self) -> Dict:
        """Get lookup statistics"""
        return {
            "total_lookups": self.lookups_total,
            "cache_hits": self.lookups_cached,
            "cymru_lookups": self.lookups_cymru,
            "ipapi_lookups": self.lookups_ipapi,
            "cache_hit_rate": (self.lookups_cached / max(1, self.lookups_total)) * 100,
            "cache_size": len(self.cache.cache),
        }


class TTLAnalyzer:
    """
    Passive hop detection through TTL analysis

    Analyzes TTL patterns to:
    - Estimate network distance (hops)
    - Detect OS fingerprinting
    - Identify anomalies (TTL manipulation)
    """

    # Common initial TTLs by OS
    OS_TTL_SIGNATURES = {
        64: ["Linux", "macOS", "iOS", "Android", "FreeBSD"],
        128: ["Windows"],
        255: ["Solaris", "AIX", "Cisco IOS", "Network Equipment"],
        32: ["Embedded", "Legacy Windows"],
    }

    def __init__(self):
        self.ttl_history: Dict[str, List[Tuple[float, int]]] = {}  # IP -> [(timestamp, ttl), ...]
        self.hop_estimates: Dict[str, int] = {}  # IP -> estimated hops
        self.os_guesses: Dict[str, str] = {}  # IP -> OS guess

    def analyze(self, ip: str, ttl: int, timestamp: Optional[float] = None) -> Dict:
        """
        Analyze TTL for hop estimation and OS fingerprinting

        Args:
            ip: Source IP address
            ttl: Observed TTL value
            timestamp: Optional timestamp

        Returns:
            Analysis result dict
        """
        timestamp = timestamp or time.time()

        # Store history
        if ip not in self.ttl_history:
            self.ttl_history[ip] = []
        self.ttl_history[ip].append((timestamp, ttl))

        # Keep last 100 observations per IP
        if len(self.ttl_history[ip]) > 100:
            self.ttl_history[ip] = self.ttl_history[ip][-100:]

        # Estimate initial TTL and hops
        initial_ttl, hops = self._estimate_initial_ttl(ttl)
        self.hop_estimates[ip] = hops

        # OS fingerprinting
        os_guess = self._guess_os(initial_ttl)
        self.os_guesses[ip] = os_guess

        # Detect anomalies
        anomaly = self._detect_anomaly(ip, ttl)

        return {
            "ip": ip,
            "observed_ttl": ttl,
            "initial_ttl": initial_ttl,
            "estimated_hops": hops,
            "os_guess": os_guess,
            "anomaly": anomaly,
            "timestamp": timestamp,
        }

    def _estimate_initial_ttl(self, observed: int) -> Tuple[int, int]:
        """Estimate initial TTL and hop count"""
        candidates = [32, 64, 128, 255]

        for initial in candidates:
            if initial >= observed:
                hops = initial - observed
                if hops <= 30:  # Reasonable hop count
                    return (initial, hops)

        # Fallback
        return (64, max(0, 64 - observed))

    def _guess_os(self, initial_ttl: int) -> str:
        """Guess OS from initial TTL"""
        for ttl, os_list in self.OS_TTL_SIGNATURES.items():
            if abs(initial_ttl - ttl) <= 4:  # Allow small variance
                return os_list[0]  # Return first match
        return "Unknown"

    def _detect_anomaly(self, ip: str, current_ttl: int) -> Optional[str]:
        """Detect TTL anomalies"""
        history = self.ttl_history.get(ip, [])

        if len(history) < 5:
            return None

        # Get recent TTLs
        recent_ttls = [t[1] for t in history[-10:]]
        avg_ttl = sum(recent_ttls) / len(recent_ttls)

        # Sudden TTL change (possible route change or manipulation)
        if abs(current_ttl - avg_ttl) > 10:
            return f"TTL_JUMP: {avg_ttl:.0f} -> {current_ttl}"

        # TTL variance too high (unstable routing)
        variance = sum((t - avg_ttl) ** 2 for t in recent_ttls) / len(recent_ttls)
        if variance > 25:  # Std dev > 5
            return f"TTL_UNSTABLE: variance={variance:.1f}"

        return None

    def get_hop_summary(self) -> Dict[str, int]:
        """Get hop estimates for all tracked IPs"""
        return dict(self.hop_estimates)

    def get_os_summary(self) -> Dict[str, str]:
        """Get OS guesses for all tracked IPs"""
        return dict(self.os_guesses)


# Convenience function for quick lookups
def lookup_asn(ip: str, ttl: int = 0) -> ASNInfo:
    """Quick ASN lookup (creates new instance each time)"""
    service = ASNLookup()
    return service.lookup(ip, ttl)


if __name__ == "__main__":
    # Test the service
    logging.basicConfig(level=logging.DEBUG)

    service = ASNLookup()
    ttl_analyzer = TTLAnalyzer()

    test_ips = [
        ("8.8.8.8", 117),      # Google DNS
        ("1.1.1.1", 55),       # Cloudflare
        ("13.107.4.52", 119),  # Microsoft
        ("151.101.1.140", 56), # Fastly/Reddit
        ("104.16.132.229", 57),# Cloudflare
    ]

    print("=" * 80)
    print("ASN & Organization Lookup with TTL-Based Hop Detection")
    print("=" * 80)

    for ip, ttl in test_ips:
        info = service.lookup(ip, ttl)
        ttl_result = ttl_analyzer.analyze(ip, ttl)

        print(f"\nIP: {ip}")
        print(f"  ASN: AS{info.asn} ({info.asn_name})")
        print(f"  Organization: {info.organization}")
        print(f"  Type: {info.org_type.value}")
        print(f"  Country: {info.country}")
        print(f"  CIDR: {info.cidr}")
        print(f"  Trust Score: {info.trust_score:.2f}")
        print(f"  TTL: {info.ttl_observed} (initial: {info.initial_ttl})")
        print(f"  Estimated Hops: {info.estimated_hops}")
        print(f"  OS Guess: {ttl_result['os_guess']}")

    print("\n" + "=" * 80)
    print("Statistics:", service.get_stats())
