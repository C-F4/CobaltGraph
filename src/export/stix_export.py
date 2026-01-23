#!/usr/bin/env python3
"""
CobaltGraph STIX 2.1 Export

Export connections, IOCs, and threat intelligence in STIX 2.1 format
for sharing with other security tools and platforms.

STIX (Structured Threat Information eXpression) is a standardized
language for describing cyber threat information.

Supports export of:
- Indicators (IP, domain, hash IOCs)
- Observed Data (network connections)
- Relationships (connections between objects)
- Bundles (collections of objects)

Usage:
    exporter = STIXExporter()
    stix_indicator = exporter.export_ip_indicator("1.2.3.4", 0.85)
    bundle = exporter.export_bundle([connection1, connection2])
    json_output = exporter.to_json(bundle)
"""

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


# STIX 2.1 Constants
STIX_VERSION = "2.1"
STIX_NAMESPACE = "cobaltgraph"


def generate_stix_id(object_type: str, deterministic_value: Optional[str] = None) -> str:
    """
    Generate a STIX 2.1 compliant ID.

    Args:
        object_type: STIX object type (indicator, observed-data, etc.)
        deterministic_value: Optional value for deterministic ID generation

    Returns:
        STIX ID in format: type--uuid
    """
    if deterministic_value:
        # Generate deterministic UUID from value
        namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL namespace
        generated_uuid = uuid.uuid5(namespace, f"{STIX_NAMESPACE}:{deterministic_value}")
    else:
        generated_uuid = uuid.uuid4()

    return f"{object_type}--{generated_uuid}"


def get_timestamp() -> str:
    """Get current timestamp in STIX format"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class STIXIndicator:
    """STIX 2.1 Indicator object"""
    type: str = "indicator"
    spec_version: str = STIX_VERSION
    id: str = ""
    created: str = ""
    modified: str = ""
    name: str = ""
    description: str = ""
    indicator_types: List[str] = None
    pattern: str = ""
    pattern_type: str = "stix"
    pattern_version: str = "2.1"
    valid_from: str = ""
    valid_until: str = ""
    kill_chain_phases: List[Dict] = None
    confidence: int = 0
    labels: List[str] = None
    external_references: List[Dict] = None

    def __post_init__(self):
        if not self.id:
            self.id = generate_stix_id("indicator")
        if not self.created:
            self.created = get_timestamp()
        if not self.modified:
            self.modified = self.created
        if not self.valid_from:
            self.valid_from = self.created
        if self.indicator_types is None:
            self.indicator_types = []
        if self.labels is None:
            self.labels = []
        if self.kill_chain_phases is None:
            self.kill_chain_phases = []
        if self.external_references is None:
            self.external_references = []

    def to_dict(self) -> Dict:
        """Convert to STIX-compliant dictionary"""
        result = {
            "type": self.type,
            "spec_version": self.spec_version,
            "id": self.id,
            "created": self.created,
            "modified": self.modified,
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
            "valid_from": self.valid_from,
        }

        # Add optional fields if present
        if self.name:
            result["name"] = self.name
        if self.description:
            result["description"] = self.description
        if self.indicator_types:
            result["indicator_types"] = self.indicator_types
        if self.valid_until:
            result["valid_until"] = self.valid_until
        if self.confidence > 0:
            result["confidence"] = self.confidence
        if self.labels:
            result["labels"] = self.labels
        if self.kill_chain_phases:
            result["kill_chain_phases"] = self.kill_chain_phases
        if self.external_references:
            result["external_references"] = self.external_references

        return result


@dataclass
class STIXObservedData:
    """STIX 2.1 Observed Data object"""
    type: str = "observed-data"
    spec_version: str = STIX_VERSION
    id: str = ""
    created: str = ""
    modified: str = ""
    first_observed: str = ""
    last_observed: str = ""
    number_observed: int = 1
    objects: Dict[str, Dict] = None  # SCO objects

    def __post_init__(self):
        if not self.id:
            self.id = generate_stix_id("observed-data")
        if not self.created:
            self.created = get_timestamp()
        if not self.modified:
            self.modified = self.created
        if not self.first_observed:
            self.first_observed = self.created
        if not self.last_observed:
            self.last_observed = self.created
        if self.objects is None:
            self.objects = {}

    def to_dict(self) -> Dict:
        """Convert to STIX-compliant dictionary"""
        return {
            "type": self.type,
            "spec_version": self.spec_version,
            "id": self.id,
            "created": self.created,
            "modified": self.modified,
            "first_observed": self.first_observed,
            "last_observed": self.last_observed,
            "number_observed": self.number_observed,
            "object_refs": list(self.objects.keys()) if self.objects else [],
        }


@dataclass
class STIXRelationship:
    """STIX 2.1 Relationship object"""
    type: str = "relationship"
    spec_version: str = STIX_VERSION
    id: str = ""
    created: str = ""
    modified: str = ""
    relationship_type: str = ""
    source_ref: str = ""
    target_ref: str = ""
    description: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = generate_stix_id("relationship")
        if not self.created:
            self.created = get_timestamp()
        if not self.modified:
            self.modified = self.created

    def to_dict(self) -> Dict:
        """Convert to STIX-compliant dictionary"""
        result = {
            "type": self.type,
            "spec_version": self.spec_version,
            "id": self.id,
            "created": self.created,
            "modified": self.modified,
            "relationship_type": self.relationship_type,
            "source_ref": self.source_ref,
            "target_ref": self.target_ref,
        }
        if self.description:
            result["description"] = self.description
        return result


@dataclass
class STIXBundle:
    """STIX 2.1 Bundle object"""
    type: str = "bundle"
    id: str = ""
    objects: List[Dict] = None

    def __post_init__(self):
        if not self.id:
            self.id = generate_stix_id("bundle")
        if self.objects is None:
            self.objects = []

    def to_dict(self) -> Dict:
        """Convert to STIX-compliant dictionary"""
        return {
            "type": self.type,
            "id": self.id,
            "objects": self.objects,
        }


class STIXExporter:
    """
    Export CobaltGraph data to STIX 2.1 format.

    Supports exporting:
    - Individual indicators (IPs, domains, hashes)
    - Connection events as observed data
    - Bundles of multiple objects
    """

    # Indicator type mappings
    INDICATOR_TYPES = {
        "malicious-activity": "malicious-activity",
        "anomalous-activity": "anomalous-activity",
        "benign": "benign",
        "unknown": "unknown",
    }

    # Kill chain phases (simplified)
    KILL_CHAIN_PHASES = {
        "c2": {
            "kill_chain_name": "lockheed-martin-cyber-kill-chain",
            "phase_name": "command-and-control"
        },
        "exfiltration": {
            "kill_chain_name": "lockheed-martin-cyber-kill-chain",
            "phase_name": "actions-on-objectives"
        },
        "reconnaissance": {
            "kill_chain_name": "lockheed-martin-cyber-kill-chain",
            "phase_name": "reconnaissance"
        },
    }

    def __init__(self, producer_name: str = "CobaltGraph"):
        """
        Initialize STIX exporter.

        Args:
            producer_name: Name of the producing organization
        """
        self.producer_name = producer_name

        # Identity for produced objects
        self.identity_id = generate_stix_id("identity", producer_name)

        # Statistics
        self.stats = {
            "indicators_exported": 0,
            "observed_data_exported": 0,
            "bundles_exported": 0,
        }

        logger.info(f"STIXExporter initialized (producer: {producer_name})")

    def export_ip_indicator(
        self,
        ip: str,
        threat_score: float,
        confidence: float = 0.8,
        description: str = "",
        labels: Optional[List[str]] = None,
        kill_chain_phase: str = "",
    ) -> STIXIndicator:
        """
        Export an IP address as a STIX Indicator.

        Args:
            ip: IPv4 or IPv6 address
            threat_score: Threat score (0.0 - 1.0)
            confidence: Confidence level (0.0 - 1.0)
            description: Optional description
            labels: Optional labels
            kill_chain_phase: Optional kill chain phase (c2, exfiltration, etc.)

        Returns:
            STIXIndicator object
        """
        # Determine indicator type based on threat score
        if threat_score >= 0.7:
            indicator_type = "malicious-activity"
        elif threat_score >= 0.4:
            indicator_type = "anomalous-activity"
        else:
            indicator_type = "unknown"

        # Build STIX pattern
        if ":" in ip:
            # IPv6
            pattern = f"[ipv6-addr:value = '{ip}']"
        else:
            # IPv4
            pattern = f"[ipv4-addr:value = '{ip}']"

        # Build labels
        all_labels = labels or []
        all_labels.append(f"threat-score-{int(threat_score * 100)}")

        # Kill chain phases
        kill_chain_phases = []
        if kill_chain_phase and kill_chain_phase in self.KILL_CHAIN_PHASES:
            kill_chain_phases.append(self.KILL_CHAIN_PHASES[kill_chain_phase])

        indicator = STIXIndicator(
            id=generate_stix_id("indicator", f"ip:{ip}"),
            name=f"Malicious IP: {ip}",
            description=description or f"IP address {ip} flagged with threat score {threat_score:.2f}",
            indicator_types=[indicator_type],
            pattern=pattern,
            confidence=int(confidence * 100),
            labels=all_labels,
            kill_chain_phases=kill_chain_phases,
            external_references=[{
                "source_name": self.producer_name,
                "description": f"Threat score: {threat_score:.2f}",
            }],
        )

        self.stats["indicators_exported"] += 1
        return indicator

    def export_domain_indicator(
        self,
        domain: str,
        threat_score: float,
        confidence: float = 0.8,
        is_dga: bool = False,
        description: str = "",
        labels: Optional[List[str]] = None,
    ) -> STIXIndicator:
        """
        Export a domain name as a STIX Indicator.

        Args:
            domain: Domain name
            threat_score: Threat score (0.0 - 1.0)
            confidence: Confidence level (0.0 - 1.0)
            is_dga: Whether domain is algorithmically generated
            description: Optional description
            labels: Optional labels

        Returns:
            STIXIndicator object
        """
        # Determine indicator type
        if is_dga:
            indicator_type = "malicious-activity"
        elif threat_score >= 0.7:
            indicator_type = "malicious-activity"
        elif threat_score >= 0.4:
            indicator_type = "anomalous-activity"
        else:
            indicator_type = "unknown"

        # Build STIX pattern
        pattern = f"[domain-name:value = '{domain}']"

        # Build labels
        all_labels = labels or []
        all_labels.append(f"threat-score-{int(threat_score * 100)}")
        if is_dga:
            all_labels.append("dga")

        indicator = STIXIndicator(
            id=generate_stix_id("indicator", f"domain:{domain}"),
            name=f"Malicious Domain: {domain}",
            description=description or f"Domain {domain} flagged with threat score {threat_score:.2f}",
            indicator_types=[indicator_type],
            pattern=pattern,
            confidence=int(confidence * 100),
            labels=all_labels,
        )

        self.stats["indicators_exported"] += 1
        return indicator

    def export_connection(self, connection_data: Dict) -> STIXObservedData:
        """
        Export a connection event as STIX Observed Data.

        Args:
            connection_data: Connection dictionary from ConnectionEvent

        Returns:
            STIXObservedData object
        """
        timestamp = connection_data.get("timestamp", time.time())
        if isinstance(timestamp, (int, float)):
            observed_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            observed_str = observed_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        else:
            observed_str = get_timestamp()

        # Build SCO (STIX Cyber-observable Objects)
        src_ip = connection_data.get("src_ip", "")
        dst_ip = connection_data.get("dst_ip", "")
        dst_port = connection_data.get("dst_port", 0)
        protocol = connection_data.get("protocol", "TCP").lower()

        objects = {}

        # Source IP
        if src_ip and src_ip != "local":
            src_id = generate_stix_id("ipv4-addr", f"src:{src_ip}")
            objects[src_id] = {
                "type": "ipv4-addr",
                "value": src_ip,
            }

        # Destination IP
        if dst_ip:
            dst_id = generate_stix_id("ipv4-addr", f"dst:{dst_ip}")
            objects[dst_id] = {
                "type": "ipv4-addr",
                "value": dst_ip,
            }

        # Network traffic
        traffic_id = generate_stix_id("network-traffic",
                                       f"{src_ip}:{dst_ip}:{dst_port}:{timestamp}")
        objects[traffic_id] = {
            "type": "network-traffic",
            "src_ref": src_id if src_ip and src_ip != "local" else None,
            "dst_ref": dst_id if dst_ip else None,
            "dst_port": dst_port,
            "protocols": [protocol],
        }

        # Add domain if present
        domain = connection_data.get("dns_query") or connection_data.get("tls_sni")
        if domain:
            domain_id = generate_stix_id("domain-name", domain)
            objects[domain_id] = {
                "type": "domain-name",
                "value": domain,
            }

        observed_data = STIXObservedData(
            id=generate_stix_id("observed-data",
                               f"{dst_ip}:{dst_port}:{timestamp}"),
            first_observed=observed_str,
            last_observed=observed_str,
            number_observed=1,
            objects=objects,
        )

        self.stats["observed_data_exported"] += 1
        return observed_data

    def export_bundle(
        self,
        connections: List[Dict],
        include_indicators: bool = True,
        min_threat_score: float = 0.5,
    ) -> STIXBundle:
        """
        Export multiple connections as a STIX Bundle.

        Args:
            connections: List of connection dictionaries
            include_indicators: Also create indicators for high-threat IPs
            min_threat_score: Minimum threat score for indicator creation

        Returns:
            STIXBundle object
        """
        objects = []
        seen_ips = set()

        for conn in connections:
            # Add observed data
            observed = self.export_connection(conn)
            objects.append(observed.to_dict())

            # Optionally add indicators for high-threat destinations
            if include_indicators:
                dst_ip = conn.get("dst_ip", "")
                threat_score = conn.get("threat_score", 0)

                if dst_ip and dst_ip not in seen_ips and threat_score >= min_threat_score:
                    indicator = self.export_ip_indicator(
                        ip=dst_ip,
                        threat_score=threat_score,
                        confidence=conn.get("confidence", 0.8),
                        labels=[conn.get("dst_org_type", "unknown")],
                    )
                    objects.append(indicator.to_dict())

                    # Add relationship between observed data and indicator
                    relationship = STIXRelationship(
                        relationship_type="based-on",
                        source_ref=indicator.id,
                        target_ref=observed.id,
                        description="Indicator based on observed network traffic",
                    )
                    objects.append(relationship.to_dict())

                    seen_ips.add(dst_ip)

        bundle = STIXBundle(objects=objects)
        self.stats["bundles_exported"] += 1

        return bundle

    def to_json(self, obj: Union[STIXIndicator, STIXObservedData, STIXBundle, Dict],
                indent: int = 2) -> str:
        """
        Convert STIX object to JSON string.

        Args:
            obj: STIX object or dictionary
            indent: JSON indentation

        Returns:
            JSON string
        """
        if hasattr(obj, "to_dict"):
            data = obj.to_dict()
        else:
            data = obj

        return json.dumps(data, indent=indent, default=str)

    def save_bundle(self, bundle: STIXBundle, filepath: str):
        """
        Save a STIX bundle to a JSON file.

        Args:
            bundle: STIXBundle to save
            filepath: Output file path
        """
        with open(filepath, "w") as f:
            f.write(self.to_json(bundle))

        logger.info(f"STIX bundle saved to {filepath} ({len(bundle.objects)} objects)")

    def get_stats(self) -> Dict:
        """Get exporter statistics"""
        return dict(self.stats)


# Convenience factory
def create_stix_exporter(producer_name: str = "CobaltGraph") -> STIXExporter:
    """Create a STIXExporter instance"""
    return STIXExporter(producer_name=producer_name)
