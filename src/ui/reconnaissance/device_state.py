#!/usr/bin/env python3
"""
CobaltGraph Device State Machine & Reconnaissance Engine

Implements unified device tracking for both device and network modes:
- Device state lifecycle (DISCOVERED → ACTIVE → IDLE → OFFLINE)
- Per-device threat aggregation and trending
- Behavior pattern analysis
- Passive fingerprinting (MAC, TTL, OS, hops)

This layer sits between the database and UI, providing:
1. Real-time device state management
2. Threat score aggregation per device
3. Activity pattern detection
4. Device-level behavioral anomalies
5. Passive reconnaissance data enrichment
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
import statistics
import time

logger = logging.getLogger(__name__)


class DeviceState(Enum):
    """Device lifecycle state machine"""
    DISCOVERED = "discovered"      # First appearance (< 1 min)
    ACTIVE = "active"              # Recently active (< 5 min)
    IDLE = "idle"                  # Inactive (5-30 min)
    OFFLINE = "offline"            # Offline (> 30 min)


class DeviceRole(Enum):
    """Inferred device role from behavior"""
    WORKSTATION = "workstation"    # User device (high entropy, varied ports)
    SERVER = "server"              # Always-on service (low entropy, few ports)
    IOT = "iot"                    # IoT device (periodic, low traffic)
    GATEWAY = "gateway"            # Router/firewall (highest traffic)
    DNS_CLIENT = "dns_client"      # Primary DNS resolver
    UNKNOWN = "unknown"


@dataclass
class ConnectionMetrics:
    """Per-device connection statistics"""
    total_connections: int = 0
    unique_destinations: int = 0
    unique_ports: Set[int] = field(default_factory=set)
    unique_protocols: Set[str] = field(default_factory=set)
    threat_scores: List[float] = field(default_factory=list)
    high_threat_count: int = 0
    anomaly_count: int = 0

    # Temporal metrics
    connections_per_hour: List[int] = field(default_factory=list)
    last_activity: float = 0.0
    activity_variance: float = 0.0

    # Passive fingerprinting
    ttl_samples: List[int] = field(default_factory=list)
    observed_os_fingerprints: Set[str] = field(default_factory=set)
    average_hop_count: float = 0.0

    def calculate_threat_average(self) -> float:
        """Calculate average threat score"""
        if not self.threat_scores:
            return 0.0
        return statistics.mean(self.threat_scores)

    def calculate_threat_95th_percentile(self) -> float:
        """Calculate 95th percentile threat score"""
        if len(self.threat_scores) < 2:
            return self.calculate_threat_average()
        return sorted(self.threat_scores)[int(len(self.threat_scores) * 0.95)]

    def calculate_activity_variance(self) -> float:
        """Calculate variance in connection rate"""
        if len(self.connections_per_hour) < 2:
            return 0.0
        try:
            return statistics.stdev(self.connections_per_hour)
        except (ValueError, statistics.StatisticsError):
            return 0.0

    def infer_role(self) -> DeviceRole:
        """Infer device role from connection patterns"""
        avg_connections = sum(self.connections_per_hour) / len(self.connections_per_hour) if self.connections_per_hour else 0
        port_entropy = len(self.unique_ports) / max(len(self.unique_protocols), 1)

        # Always-on with low entropy
        if avg_connections > 0 and port_entropy < 3:
            return DeviceRole.SERVER

        # Periodic activity (characteristic of IoT)
        if self.activity_variance > 2.0 and avg_connections < 5:
            return DeviceRole.IOT

        # High traffic volume (gateway/router)
        if self.total_connections > 1000:
            return DeviceRole.GATEWAY

        # Primarily DNS
        if 53 in self.unique_ports and len(self.unique_ports) < 3:
            return DeviceRole.DNS_CLIENT

        # Default: varied patterns (workstation)
        return DeviceRole.WORKSTATION


@dataclass
class PassiveFingerprint:
    """Passive fingerprinting data collected from connections"""
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None
    ip_addresses: Set[str] = field(default_factory=set)
    hostname: Optional[str] = None

    # OS fingerprinting via TTL analysis
    estimated_os: Optional[str] = None
    ttl_initial_estimate: Optional[int] = None
    os_confidence: float = 0.0

    # Network position
    average_hop_count: float = 0.0
    hop_variance: float = 0.0
    is_local: bool = False

    # Protocol analysis
    preferred_protocols: Dict[str, int] = field(default_factory=dict)
    preferred_ports: Dict[int, int] = field(default_factory=dict)
    broadcast_count: int = 0
    arp_count: int = 0


@dataclass
class DeviceReconRecord:
    """Complete device reconnaissance record"""
    # Identity
    mac_address: Optional[str]
    primary_ip: str
    vendor: Optional[str] = None
    hostname: Optional[str] = None

    # State tracking
    state: DeviceState = DeviceState.DISCOVERED
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    first_seen_human: str = ""
    last_seen_human: str = ""

    # Threat metrics
    threat_score: float = 0.0
    threat_trend: List[float] = field(default_factory=list)
    threat_percentile_95: float = 0.0
    risk_flags: List[str] = field(default_factory=list)
    analyst_notes: str = ""

    # Connection metrics
    metrics: ConnectionMetrics = field(default_factory=ConnectionMetrics)

    # Passive fingerprinting
    fingerprint: PassiveFingerprint = field(default_factory=PassiveFingerprint)

    # Role inference
    inferred_role: DeviceRole = DeviceRole.UNKNOWN

    # Behavioral analysis
    is_anomalous: bool = False
    anomaly_type: Optional[str] = None
    anomaly_score: float = 0.0

    # Peer analysis
    associated_devices: Set[str] = field(default_factory=set)
    shared_destinations: Dict[str, int] = field(default_factory=dict)

    def update_state(self) -> None:
        """Update state based on activity"""
        now = time.time()
        time_since_activity = now - self.last_seen

        if time_since_activity < 60:
            self.state = DeviceState.ACTIVE
        elif time_since_activity < 300:  # 5 minutes
            self.state = DeviceState.IDLE
        elif time_since_activity < 1800:  # 30 minutes
            self.state = DeviceState.IDLE
        else:
            self.state = DeviceState.OFFLINE

    def update_timestamps(self) -> None:
        """Update human-readable timestamps"""
        self.first_seen_human = datetime.fromtimestamp(self.first_seen).strftime("%Y-%m-%d %H:%M:%S")
        self.last_seen_human = datetime.fromtimestamp(self.last_seen).strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> Dict:
        """Convert to dictionary for display/export"""
        self.update_state()
        self.update_timestamps()

        return {
            "mac": self.mac_address,
            "primary_ip": self.primary_ip,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "state": self.state.value,
            "first_seen": self.first_seen_human,
            "last_seen": self.last_seen_human,
            "threat_score": round(self.threat_score, 3),
            "threat_percentile_95": round(self.threat_percentile_95, 3),
            "high_threat_count": self.metrics.high_threat_count,
            "total_connections": self.metrics.total_connections,
            "unique_destinations": self.metrics.unique_destinations,
            "unique_ports": len(self.metrics.unique_ports),
            "inferred_role": self.inferred_role.value,
            "is_anomalous": self.is_anomalous,
            "anomaly_type": self.anomaly_type,
            "risk_flags": self.risk_flags,
            "notes": self.analyst_notes,
        }


class DeviceReconnaissanceEngine:
    """
    Central device reconnaissance and state management engine

    Responsibilities:
    1. Aggregate per-device metrics from connection stream
    2. Track device lifecycle state (discovered → active → idle → offline)
    3. Perform passive fingerprinting (MAC, TTL, OS, hops)
    4. Detect behavioral anomalies
    5. Infer device role from patterns
    6. Track device-to-device relationships
    """

    def __init__(self, max_devices: int = 10000, activity_ttl: int = 3600):
        """
        Initialize reconnaissance engine

        Args:
            max_devices: Maximum devices to track
            activity_ttl: Time-to-live for activity window (seconds)
        """
        self.devices: Dict[str, DeviceReconRecord] = {}
        self.max_devices = max_devices
        self.activity_ttl = activity_ttl

        # Lookup tables for fast queries
        self.mac_to_devices: Dict[str, str] = {}  # MAC → primary_ip
        self.ip_to_devices: Dict[str, str] = {}   # IP → primary_ip

        # Temporal tracking
        self.activity_window: Dict[str, deque] = {}  # primary_ip → deque(hourly_counts)
        self.last_eviction = time.time()

    def process_connection(self, connection: Dict) -> Optional[str]:
        """
        Process a connection and update device records

        Args:
            connection: Connection event from pipeline

        Returns:
            Device key (MAC or primary IP) for the source device
        """
        from collections import deque

        timestamp = connection.get('timestamp', time.time())

        # Determine device identity
        src_mac = connection.get('src_mac')
        src_ip = connection.get('src_ip')

        # In network mode: identify by MAC
        # In device mode: identify by IP
        device_key = src_mac if src_mac else src_ip

        if not device_key:
            return None

        # Create device record if not exists
        if device_key not in self.devices:
            if len(self.devices) >= self.max_devices:
                self._evict_old_devices()

            record = DeviceReconRecord(
                mac_address=src_mac,
                primary_ip=src_ip,
                vendor=connection.get('device_vendor'),
                hostname=connection.get('hostname'),
                first_seen=timestamp
            )
            self.devices[device_key] = record

            # Update lookup tables
            if src_mac:
                self.mac_to_devices[src_mac] = device_key
            if src_ip:
                self.ip_to_devices[src_ip] = device_key

        device = self.devices[device_key]
        device.last_seen = timestamp

        # Update metrics
        dst_ip = connection.get('dst_ip')
        dst_port = connection.get('dst_port')
        protocol = connection.get('protocol', 'unknown')
        threat_score = float(connection.get('threat_score', 0) or 0)

        device.metrics.total_connections += 1
        device.metrics.threat_scores.append(threat_score)
        device.metrics.unique_protocols.add(protocol)

        if dst_port:
            device.metrics.unique_ports.add(int(dst_port))

        if threat_score >= 0.7:
            device.metrics.high_threat_count += 1

        # Update unique destinations
        if dst_ip:
            device.metrics.unique_destinations = len(set(d for d in [connection.get('dst_ip')]))

        # Update threat score (rolling average)
        device.threat_score = device.metrics.calculate_threat_average()
        device.threat_percentile_95 = device.metrics.calculate_threat_95th_percentile()

        # Update passive fingerprinting
        if src_mac:
            device.fingerprint.mac_address = src_mac
        device.fingerprint.ip_addresses.add(src_ip)

        ttl = connection.get('ttl_observed')
        if ttl:
            device.metrics.ttl_samples.append(ttl)
            device.fingerprint.ttl_initial_estimate = connection.get('ttl_initial')

        os_fp = connection.get('os_fingerprint')
        if os_fp:
            device.metrics.observed_os_fingerprints.add(os_fp)
            device.fingerprint.estimated_os = os_fp

        hop_count = connection.get('hop_count')
        if hop_count:
            device.metrics.average_hop_count = (
                (device.metrics.average_hop_count * (device.metrics.total_connections - 1) + hop_count) /
                device.metrics.total_connections
            )

        # Update inferred role
        device.inferred_role = device.metrics.infer_role()

        # Track hourly activity
        if device_key not in self.activity_window:
            self.activity_window[device_key] = deque(maxlen=24)  # Last 24 hours

        # This is simplified; real implementation would bucket by hour
        self.activity_window[device_key].append(1)
        device.metrics.connections_per_hour = list(self.activity_window[device_key])
        device.metrics.activity_variance = device.metrics.calculate_activity_variance()

        return device_key

    def get_device(self, device_key: str) -> Optional[DeviceReconRecord]:
        """Get device record by key"""
        return self.devices.get(device_key)

    def get_devices(self, filter_state: Optional[DeviceState] = None,
                   sort_by: str = "threat", limit: Optional[int] = None) -> List[DeviceReconRecord]:
        """
        Get device list with optional filtering and sorting

        Args:
            filter_state: Filter by device state
            sort_by: Sort by "threat", "activity", "name", or "role"
            limit: Limit results

        Returns:
            List of device records
        """
        devices = list(self.devices.values())

        # Update states
        for device in devices:
            device.update_state()

        # Filter
        if filter_state:
            devices = [d for d in devices if d.state == filter_state]

        # Sort
        if sort_by == "threat":
            devices.sort(key=lambda d: d.threat_score, reverse=True)
        elif sort_by == "activity":
            devices.sort(key=lambda d: d.last_seen, reverse=True)
        elif sort_by == "name":
            devices.sort(key=lambda d: d.vendor or d.mac_address or d.primary_ip)
        elif sort_by == "role":
            devices.sort(key=lambda d: d.inferred_role.value)

        if limit:
            devices = devices[:limit]

        return devices

    def get_device_summary(self) -> Dict:
        """Get summary statistics for all devices"""
        devices = list(self.devices.values())

        if not devices:
            return {
                "total_devices": 0,
                "active_devices": 0,
                "idle_devices": 0,
                "offline_devices": 0,
                "high_threat_devices": 0,
                "average_threat": 0.0,
                "max_threat": 0.0,
            }

        # Update all states
        for device in devices:
            device.update_state()

        active = sum(1 for d in devices if d.state == DeviceState.ACTIVE)
        idle = sum(1 for d in devices if d.state == DeviceState.IDLE)
        offline = sum(1 for d in devices if d.state == DeviceState.OFFLINE)
        high_threat = sum(1 for d in devices if d.threat_score >= 0.7)

        threat_scores = [d.threat_score for d in devices]
        avg_threat = statistics.mean(threat_scores) if threat_scores else 0.0
        max_threat = max(threat_scores) if threat_scores else 0.0

        return {
            "total_devices": len(devices),
            "active_devices": active,
            "idle_devices": idle,
            "offline_devices": offline,
            "high_threat_devices": high_threat,
            "average_threat": round(avg_threat, 3),
            "max_threat": round(max_threat, 3),
        }

    def _evict_old_devices(self) -> None:
        """Evict offline devices to maintain memory limits"""
        now = time.time()
        to_remove = []

        for key, device in self.devices.items():
            if (now - device.last_seen) > self.activity_ttl:
                to_remove.append(key)

        for key in to_remove:
            device = self.devices.pop(key)
            if device.mac_address:
                self.mac_to_devices.pop(device.mac_address, None)
            self.ip_to_devices.pop(device.primary_ip, None)
            self.activity_window.pop(key, None)

        if to_remove:
            logger.info(f"Evicted {len(to_remove)} offline devices")
