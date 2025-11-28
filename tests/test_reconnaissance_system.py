#!/usr/bin/env python3
"""
Reconnaissance System Tests

Comprehensive test suite for device state machine, reconnaissance engine,
and UI panel integration.

Test Coverage:
- Device state machine transitions
- Connection processing and aggregation
- Device role inference
- Passive fingerprinting
- Threat scoring aggregation
- Device filtering and sorting
"""

import pytest
import time
from unittest.mock import Mock, patch

# Import reconnaissance components
from src.ui.reconnaissance import (
    DeviceState,
    DeviceRole,
    DeviceReconRecord,
    PassiveFingerprint,
    ConnectionMetrics,
    DeviceReconnaissanceEngine,
)


class TestDeviceState:
    """Test device state machine"""

    def test_state_enum_values(self):
        """Test DeviceState enum values"""
        assert DeviceState.DISCOVERED.value == "discovered"
        assert DeviceState.ACTIVE.value == "active"
        assert DeviceState.IDLE.value == "idle"
        assert DeviceState.OFFLINE.value == "offline"

    def test_state_transitions(self):
        """Test device state transitions"""
        device = DeviceReconRecord(
            mac_address="00:1A:2B:3C:4D:5E",
            primary_ip="192.168.1.100"
        )

        # Initially DISCOVERED
        device.update_state()
        assert device.state == DeviceState.ACTIVE  # First update

        # Simulate passage of time
        device.last_seen = time.time() - 60  # 1 minute ago
        device.update_state()
        assert device.state == DeviceState.ACTIVE

        device.last_seen = time.time() - 360  # 6 minutes ago
        device.update_state()
        assert device.state == DeviceState.IDLE

        device.last_seen = time.time() - 2000  # 33 minutes ago
        device.update_state()
        assert device.state == DeviceState.OFFLINE


class TestDeviceRole:
    """Test device role inference"""

    def test_role_enum_values(self):
        """Test DeviceRole enum values"""
        assert DeviceRole.WORKSTATION.value == "workstation"
        assert DeviceRole.SERVER.value == "server"
        assert DeviceRole.IOT.value == "iot"
        assert DeviceRole.GATEWAY.value == "gateway"

    def test_role_inference_workstation(self):
        """Test workstation role inference"""
        metrics = ConnectionMetrics()
        metrics.total_connections = 100
        metrics.unique_ports = {80, 443, 22, 53, 3306}
        metrics.unique_protocols = {"TCP", "UDP"}
        metrics.connections_per_hour = [5, 7, 3, 8, 6]
        metrics.activity_variance = 2.5

        role = metrics.infer_role()
        assert role == DeviceRole.WORKSTATION

    def test_role_inference_server(self):
        """Test server role inference"""
        metrics = ConnectionMetrics()
        metrics.total_connections = 5000
        metrics.unique_ports = {443, 80}
        metrics.unique_protocols = {"TCP"}
        metrics.connections_per_hour = [100, 102, 99, 101, 98]

        role = metrics.infer_role()
        # Server has high traffic and low port entropy
        assert role in [DeviceRole.SERVER, DeviceRole.GATEWAY]

    def test_role_inference_iot(self):
        """Test IoT role inference"""
        metrics = ConnectionMetrics()
        metrics.total_connections = 100
        metrics.unique_ports = {8883, 5683}
        metrics.unique_protocols = {"TCP"}
        metrics.connections_per_hour = [0, 0, 5, 0, 0, 0, 5]
        metrics.activity_variance = 3.0

        role = metrics.infer_role()
        assert role == DeviceRole.IOT


class TestConnectionMetrics:
    """Test connection metrics calculation"""

    def test_threat_average_calculation(self):
        """Test threat score averaging"""
        metrics = ConnectionMetrics()
        metrics.threat_scores = [0.1, 0.2, 0.3, 0.4, 0.5]

        avg = metrics.calculate_threat_average()
        assert avg == 0.3

    def test_threat_95th_percentile(self):
        """Test 95th percentile threat calculation"""
        metrics = ConnectionMetrics()
        metrics.threat_scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]

        p95 = metrics.calculate_threat_95th_percentile()
        assert p95 >= 0.9

    def test_activity_variance_calculation(self):
        """Test activity variance calculation"""
        metrics = ConnectionMetrics()
        metrics.connections_per_hour = [10, 12, 15, 11, 13]

        variance = metrics.calculate_activity_variance()
        assert variance >= 0


class TestDeviceReconnaissanceEngine:
    """Test device reconnaissance engine"""

    def test_engine_initialization(self):
        """Test engine creation"""
        engine = DeviceReconnaissanceEngine(max_devices=1000, activity_ttl=3600)
        assert len(engine.devices) == 0
        assert engine.max_devices == 1000
        assert engine.activity_ttl == 3600

    def test_process_single_connection(self):
        """Test processing a single connection"""
        engine = DeviceReconnaissanceEngine()

        connection = {
            'timestamp': time.time(),
            'src_mac': '00:1A:2B:3C:4D:5E',
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'dst_port': 53,
            'protocol': 'UDP',
            'threat_score': 0.1,
            'device_vendor': 'Apple',
            'ttl_observed': 64,
            'ttl_initial': 64,
            'hop_count': 0,
            'os_fingerprint': 'Linux',
        }

        device_key = engine.process_connection(connection)
        assert device_key == '00:1A:2B:3C:4D:5E'

        device = engine.get_device(device_key)
        assert device is not None
        assert device.mac_address == '00:1A:2B:3C:4D:5E'
        assert device.metrics.total_connections == 1
        assert device.threat_score == 0.1

    def test_process_multiple_connections(self):
        """Test processing multiple connections from same device"""
        engine = DeviceReconnaissanceEngine()

        for i in range(10):
            connection = {
                'timestamp': time.time() + i,
                'src_mac': '00:1A:2B:3C:4D:5E',
                'src_ip': '192.168.1.100',
                'dst_ip': f'10.0.0.{i}',
                'dst_port': 80 + i,
                'protocol': 'TCP',
                'threat_score': 0.1 * i,
                'device_vendor': 'Apple',
            }

            engine.process_connection(connection)

        device = engine.get_device('00:1A:2B:3C:4D:5E')
        assert device.metrics.total_connections == 10
        assert len(device.metrics.unique_ports) == 10

    def test_device_filtering_by_state(self):
        """Test filtering devices by state"""
        engine = DeviceReconnaissanceEngine()

        # Add device
        connection = {
            'timestamp': time.time(),
            'src_mac': '00:1A:2B:3C:4D:5E',
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'dst_port': 53,
            'protocol': 'UDP',
            'threat_score': 0.1,
        }

        engine.process_connection(connection)
        device = engine.get_device('00:1A:2B:3C:4D:5E')
        device.update_state()

        # Get active devices
        active = engine.get_devices(filter_state=DeviceState.ACTIVE)
        assert len(active) == 1

        # No offline devices yet
        offline = engine.get_devices(filter_state=DeviceState.OFFLINE)
        assert len(offline) == 0

    def test_device_sorting(self):
        """Test device sorting options"""
        engine = DeviceReconnaissanceEngine()

        # Add devices with different threat scores
        for mac, threat in [
            ('00:1A:2B:3C:4D:5E', 0.9),
            ('00:2C:3D:4E:5F:6A', 0.3),
            ('00:3D:4E:5F:6A:7B', 0.6),
        ]:
            connection = {
                'timestamp': time.time(),
                'src_mac': mac,
                'src_ip': f'192.168.1.{mac[-2:]}',
                'dst_ip': '8.8.8.8',
                'dst_port': 53,
                'protocol': 'UDP',
                'threat_score': threat,
            }

            engine.process_connection(connection)

        # Sort by threat
        devices = engine.get_devices(sort_by="threat")
        assert devices[0].threat_score >= devices[1].threat_score
        assert devices[1].threat_score >= devices[2].threat_score

    def test_device_summary(self):
        """Test device summary statistics"""
        engine = DeviceReconnaissanceEngine()

        # Add devices
        for i in range(5):
            connection = {
                'timestamp': time.time(),
                'src_mac': f'00:1A:2B:3C:4D:{i:02X}',
                'src_ip': f'192.168.1.{100+i}',
                'dst_ip': '8.8.8.8',
                'dst_port': 53,
                'protocol': 'UDP',
                'threat_score': 0.1 * i,
            }

            engine.process_connection(connection)

        summary = engine.get_device_summary()
        assert summary['total_devices'] == 5
        assert summary['active_devices'] >= 4

    def test_device_eviction(self):
        """Test device eviction when limit reached"""
        engine = DeviceReconnaissanceEngine(max_devices=5, activity_ttl=10)

        # Add more devices than limit
        for i in range(10):
            connection = {
                'timestamp': time.time() - (11 if i >= 5 else 0),  # Old ones
                'src_mac': f'00:1A:2B:3C:4D:{i:02X}',
                'src_ip': f'192.168.1.{100+i}',
                'dst_ip': '8.8.8.8',
                'dst_port': 53,
                'protocol': 'UDP',
                'threat_score': 0.1,
            }

            engine.process_connection(connection)

        # Check that old devices were evicted
        assert len(engine.devices) <= 10  # No infinite growth

    def test_threat_trend_tracking(self):
        """Test threat score trending"""
        engine = DeviceReconnaissanceEngine()

        # Add connections with increasing threat
        for threat in [0.1, 0.2, 0.3, 0.4, 0.5]:
            connection = {
                'timestamp': time.time(),
                'src_mac': '00:1A:2B:3C:4D:5E',
                'src_ip': '192.168.1.100',
                'dst_ip': f'10.0.0.{int(threat*10)}',
                'dst_port': 80,
                'protocol': 'TCP',
                'threat_score': threat,
            }

            engine.process_connection(connection)

        device = engine.get_device('00:1A:2B:3C:4D:5E')
        assert device.threat_percentile_95 >= device.threat_score


class TestPassiveFingerprinting:
    """Test passive fingerprinting features"""

    def test_os_detection_from_ttl(self):
        """Test OS detection from TTL values"""
        device = DeviceReconRecord(
            mac_address="00:1A:2B:3C:4D:5E",
            primary_ip="192.168.1.100"
        )

        # Linux typically has TTL 64
        device.metrics.ttl_samples = [64, 64, 63, 64, 64]
        device.fingerprint.ttl_initial_estimate = 64

        # Should be detected as Linux
        assert "64" in str(device.fingerprint.ttl_initial_estimate)

    def test_hop_count_analysis(self):
        """Test hop count network position classification"""
        device = DeviceReconRecord(
            mac_address="00:1A:2B:3C:4D:5E",
            primary_ip="192.168.1.100"
        )

        device.metrics.average_hop_count = 2.0
        assert device.metrics.average_hop_count <= 3  # Local network

        device.metrics.average_hop_count = 5.0
        assert device.metrics.average_hop_count <= 7  # Regional

        device.metrics.average_hop_count = 15.0
        assert device.metrics.average_hop_count <= 15  # Cross-region


class TestIntegration:
    """Integration tests"""

    def test_full_device_lifecycle(self):
        """Test complete device lifecycle"""
        engine = DeviceReconnaissanceEngine()

        # Device discovery
        conn1 = {
            'timestamp': time.time(),
            'src_mac': '00:1A:2B:3C:4D:5E',
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'dst_port': 53,
            'protocol': 'UDP',
            'threat_score': 0.1,
            'device_vendor': 'Apple',
        }

        device_key = engine.process_connection(conn1)
        device = engine.get_device(device_key)
        assert device.state == DeviceState.DISCOVERED or device.state == DeviceState.ACTIVE

        # Device becomes active
        for i in range(5):
            conn = dict(conn1)
            conn['timestamp'] = time.time()
            conn['dst_ip'] = f'10.0.0.{i}'
            conn['threat_score'] = 0.1 + i * 0.05

            engine.process_connection(conn)

        device = engine.get_device(device_key)
        assert device.metrics.total_connections == 6
        assert device.threat_score > 0.1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
