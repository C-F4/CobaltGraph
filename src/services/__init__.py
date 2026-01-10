"""
CobaltGraph Services
Modular service layer for CobaltGraph platform

Services:
- GeoLookup: IP geolocation via ip-api.com
- IPReputation: Threat intelligence (VirusTotal, AbuseIPDB)
- ASNLookup: ASN/organization lookup with TTL-based hop detection
"""

from .geo_lookup import GeoLookup
from .ip_reputation import IPReputation

# ASN lookup with graceful fallback
try:
    from .asn_lookup import ASNLookup, ASNInfo, OrgType, TTLAnalyzer
    ASN_AVAILABLE = True
except ImportError:
    ASNLookup = None
    ASNInfo = None
    OrgType = None
    TTLAnalyzer = None
    ASN_AVAILABLE = False

__all__ = [
    "GeoLookup",
    "IPReputation",
    "ASNLookup",
    "ASNInfo",
    "OrgType",
    "TTLAnalyzer",
    "ASN_AVAILABLE",
]
