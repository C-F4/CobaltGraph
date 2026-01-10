"""
Pipeline Events

Data classes for events flowing through the pipeline stages.
Replaces the nested dict structures with typed, validated objects.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
import time


class ThreatLevel(Enum):
    """Threat severity classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class EventType(Enum):
    """Types of events in the pipeline"""
    CONNECTION = "connection"
    DEVICE = "device"
    ALERT = "alert"
    STATS = "stats"


@dataclass
class GeoData:
    """Geographic location data"""
    country: str = ""
    country_code: str = ""
    city: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: str = ""
    timezone: str = ""


@dataclass
class ASNData:
    """Autonomous System Number data"""
    asn: int = 0
    asn_name: str = ""
    organization: str = ""
    org_type: str = "unknown"
    trust_score: float = 0.5
    cidr: str = ""
    country: str = ""


@dataclass
class ThreatIntelData:
    """Threat intelligence enrichment data"""
    is_malicious: bool = False
    is_tor_exit: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    abuse_score: float = 0.0
    virustotal_score: float = 0.0
    sources: List[str] = field(default_factory=list)


@dataclass
class TracerouteData:
    """Traceroute hop data for network distance verification"""
    hop_count: int = 0                           # Verified or estimated hop count
    verified: bool = False                       # True if from actual traceroute
    ttl_observed: Optional[int] = None           # Observed TTL from packet
    ttl_initial: Optional[int] = None            # Estimated initial TTL
    latency_ms: Optional[float] = None           # Round-trip latency
    hops: List[Dict] = field(default_factory=list)  # Individual hop details
    error: Optional[str] = None                  # Error if traceroute failed


@dataclass
class ConsensusResult:
    """Result from consensus scoring"""
    final_score: float = 0.0
    confidence: float = 0.5
    high_uncertainty: bool = False

    # Individual scorer results
    score_statistical: float = 0.0
    score_rule_based: float = 0.0
    score_ml: float = 0.0
    score_organization: float = 0.0

    # Scorer details
    scorer_agreement: float = 0.0
    outlier_detected: bool = False
    outlier_scorer: Optional[str] = None


@dataclass
class AnomalyData:
    """Result from anomaly detection"""
    score: float = 0.0
    anomaly_type: str = "normal"
    z_score: float = 0.0
    percentile: float = 50.0
    factors: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ConnectionEvent:
    """
    Represents a network connection flowing through the pipeline.

    This replaces the raw dict that was passed through _process_connection().
    """
    # Core identifiers
    timestamp: float = field(default_factory=time.time)
    src_ip: str = ""
    src_mac: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = "TCP"

    # Device info (for network mode)
    device_vendor: str = ""
    device_hostname: Optional[str] = None

    # Enrichment data
    geo: GeoData = field(default_factory=GeoData)
    asn: ASNData = field(default_factory=ASNData)
    threat_intel: ThreatIntelData = field(default_factory=ThreatIntelData)
    traceroute: TracerouteData = field(default_factory=TracerouteData)

    # Scoring
    consensus: ConsensusResult = field(default_factory=ConsensusResult)
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN

    # Analytics
    anomaly: Optional[AnomalyData] = None

    # Metadata
    is_duplicate: bool = False
    processing_time_ms: float = 0.0
    enrichment_sources: List[str] = field(default_factory=list)

    @property
    def threat_score(self) -> float:
        """Convenience accessor for final threat score"""
        return self.consensus.final_score

    @property
    def is_high_threat(self) -> bool:
        """Check if connection is high threat (>= 0.7)"""
        return self.consensus.final_score >= 0.7

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage and IPC"""
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "src_mac": self.src_mac,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "device_vendor": self.device_vendor,
            "device_hostname": self.device_hostname,

            # Geo
            "dst_country": self.geo.country,
            "dst_country_code": self.geo.country_code,
            "dst_city": self.geo.city,
            "dst_lat": self.geo.latitude,
            "dst_lon": self.geo.longitude,
            "dst_isp": self.geo.isp,

            # ASN
            "dst_asn": self.asn.asn,
            "dst_asn_name": self.asn.asn_name,
            "dst_org": self.asn.organization,
            "dst_org_type": self.asn.org_type,
            "org_trust_score": self.asn.trust_score,

            # Threat intel
            "is_malicious": self.threat_intel.is_malicious,
            "is_tor_exit": self.threat_intel.is_tor_exit,
            "abuse_score": self.threat_intel.abuse_score,

            # Traceroute / Hop data
            "hop_count": self.traceroute.hop_count,
            "hop_verified": self.traceroute.verified,
            "ttl_observed": self.traceroute.ttl_observed,
            "ttl_initial": self.traceroute.ttl_initial,

            # Scoring
            "threat_score": self.consensus.final_score,
            "confidence": self.consensus.confidence,
            "high_uncertainty": self.consensus.high_uncertainty,
            "score_statistical": self.consensus.score_statistical,
            "score_rule_based": self.consensus.score_rule_based,
            "score_ml": self.consensus.score_ml,
            "score_organization": self.consensus.score_organization,

            # Analytics
            "anomaly_score": self.anomaly.score if self.anomaly else None,
            "anomaly_type": self.anomaly.anomaly_type if self.anomaly else None,

            # Metadata
            "processing_time_ms": self.processing_time_ms,
        }

    @classmethod
    def from_raw(cls, raw: Dict[str, Any]) -> "ConnectionEvent":
        """Create from raw capture dict (NetworkMonitor/DeviceMonitor output)"""
        return cls(
            timestamp=raw.get("timestamp", time.time()),
            src_ip=raw.get("src_ip", ""),
            src_mac=raw.get("src_mac", ""),
            dst_ip=raw.get("dst_ip", ""),
            dst_port=raw.get("dst_port", 0),
            protocol=raw.get("protocol", "TCP"),
            device_vendor=raw.get("device_vendor", ""),
        )


@dataclass
class DeviceEvent:
    """
    Represents a discovered device on the network.
    """
    mac: str = ""
    ip: str = ""
    vendor: str = ""
    hostname: Optional[str] = None
    packet_type: str = "unknown"  # arp, broadcast, connection
    timestamp: float = field(default_factory=time.time)

    # Aggregated threat data
    threat_score_sum: float = 0.0
    connection_count: int = 0
    high_threat_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "mac": self.mac,
            "ip": self.ip,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "packet_type": self.packet_type,
            "timestamp": self.timestamp,
            "threat_score_sum": self.threat_score_sum,
            "connection_count": self.connection_count,
            "high_threat_count": self.high_threat_count,
        }

    @classmethod
    def from_raw(cls, raw: Dict[str, Any]) -> "DeviceEvent":
        """Create from raw capture dict"""
        return cls(
            mac=raw.get("mac", ""),
            ip=raw.get("ip", ""),
            vendor=raw.get("vendor", ""),
            hostname=raw.get("hostname"),
            packet_type=raw.get("packet_type", "unknown"),
            timestamp=raw.get("timestamp", time.time()),
        )


@dataclass
class StageResult:
    """
    Result from processing a single stage.

    Each pipeline stage returns this to indicate success/failure
    and provide metrics for monitoring.
    """
    success: bool = True
    data: Any = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # Performance metrics
    processing_time_ms: float = 0.0
    items_processed: int = 0
    items_skipped: int = 0

    # Stage-specific metrics (e.g., cache hits, API calls)
    metrics: Dict[str, float] = field(default_factory=dict)

    def __bool__(self) -> bool:
        """Allow using result in boolean context"""
        return self.success

    def add_error(self, msg: str):
        """Add an error message"""
        self.errors.append(msg)
        self.success = False

    def add_warning(self, msg: str):
        """Add a warning message"""
        self.warnings.append(msg)

    def add_metric(self, name: str, value: float):
        """Add a performance metric"""
        self.metrics[name] = value


@dataclass
class PipelineStats:
    """Aggregated statistics for the entire pipeline"""
    total_connections: int = 0
    total_devices: int = 0
    high_threat_connections: int = 0

    # Per-stage metrics
    validation_time_ms: float = 0.0
    enrichment_time_ms: float = 0.0
    scoring_time_ms: float = 0.0
    storage_time_ms: float = 0.0

    # Error counts
    validation_errors: int = 0
    enrichment_errors: int = 0
    scoring_errors: int = 0
    storage_errors: int = 0

    # Cache stats
    dedup_hits: int = 0
    geo_cache_hits: int = 0
    asn_cache_hits: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for IPC"""
        return {
            "total_connections": self.total_connections,
            "total_devices": self.total_devices,
            "high_threat_connections": self.high_threat_connections,
            "validation_time_ms": self.validation_time_ms,
            "enrichment_time_ms": self.enrichment_time_ms,
            "scoring_time_ms": self.scoring_time_ms,
            "storage_time_ms": self.storage_time_ms,
            "dedup_hits": self.dedup_hits,
        }
