"""
CobaltGraph Data Models
Database table schemas and data structures

Defines:
- Connection model
- Device model
- Threat zone model
- Data validation
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Connection:
    """
    Network connection record

    Represents a single network connection with geolocation,
    threat intelligence, ASN/organization, and hop data.
    """

    id: Optional[int] = None
    timestamp: float = 0.0
    src_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    dst_country: Optional[str] = None
    dst_lat: Optional[float] = None
    dst_lon: Optional[float] = None
    dst_org: Optional[str] = None
    dst_hostname: Optional[str] = None
    threat_score: float = 0.0
    device_vendor: Optional[str] = None
    protocol: str = "TCP"

    # ASN and Organization fields
    dst_asn: Optional[int] = None           # Autonomous System Number
    dst_asn_name: Optional[str] = None      # AS name (e.g., "GOOGLE")
    dst_org_type: Optional[str] = None      # Organization type (cloud, cdn, isp, etc.)
    dst_cidr: Optional[str] = None          # IP CIDR block

    # TTL and Hop detection fields
    ttl_observed: Optional[int] = None      # Observed TTL value
    ttl_initial: Optional[int] = None       # Estimated initial TTL
    hop_count: Optional[int] = None         # Estimated network hops
    os_fingerprint: Optional[str] = None    # OS guess from TTL

    # Trust scoring
    org_trust_score: Optional[float] = None # Organization trust (0.0-1.0)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "src_mac": self.src_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "dst_country": self.dst_country,
            "dst_lat": self.dst_lat,
            "dst_lon": self.dst_lon,
            "dst_org": self.dst_org,
            "dst_hostname": self.dst_hostname,
            "threat_score": self.threat_score,
            "device_vendor": self.device_vendor,
            "protocol": self.protocol,
            # ASN/Org fields
            "dst_asn": self.dst_asn,
            "dst_asn_name": self.dst_asn_name,
            "dst_org_type": self.dst_org_type,
            "dst_cidr": self.dst_cidr,
            # Hop detection fields
            "ttl_observed": self.ttl_observed,
            "ttl_initial": self.ttl_initial,
            "hop_count": self.hop_count,
            "os_fingerprint": self.os_fingerprint,
            # Trust
            "org_trust_score": self.org_trust_score,
        }


@dataclass
class Device:
    """
    Network device record

    Represents a discovered device on the network with
    MAC address, vendor, and activity tracking.
    """

    mac: str
    ip_addresses: list
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0
    connection_count: int = 0
    threat_score: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "mac": self.mac,
            "ip_addresses": self.ip_addresses,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packet_count": self.packet_count,
            "connection_count": self.connection_count,
            "threat_score": self.threat_score,
        }
