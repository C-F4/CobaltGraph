#!/usr/bin/env python3
"""
Manual validation script for FlatWorldMap globe visualization
Tests: coordinate conversion, heatmap aggregation, rendering performance
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.ui.globe_flat import FlatWorldMap, ThreatPin


def test_initialization():
    """Test basic initialization"""
    globe = FlatWorldMap(width=140, height=30)
    assert globe.width == 140
    assert globe.height == 30
    assert len(globe.threats) == 0
    assert len(globe.heatmap) == 0
    print("✓ Initialization test passed")


def test_latlon_to_screen():
    """Test coordinate conversion"""
    globe = FlatWorldMap(width=140, height=30)

    # Center (0, 0) should be roughly in the middle
    x, y = globe.latlon_to_screen(0, 0)
    assert 0 <= x < globe.width
    assert 0 <= y < globe.height
    print(f"✓ Center (0,0) → ({x}, {y})")

    # North pole
    x_np, y_np = globe.latlon_to_screen(85, 0)
    assert 0 <= x_np < globe.width
    assert 0 <= y_np < globe.height

    # South pole
    x_sp, y_sp = globe.latlon_to_screen(-85, 0)
    assert y_sp > y_np  # South should be lower (higher y)
    print(f"✓ Poles: North={y_np}, South={y_sp}")

    # Extremes
    x_w, _ = globe.latlon_to_screen(0, -180)
    x_e, _ = globe.latlon_to_screen(0, 180)
    assert 0 <= x_w < globe.width
    assert 0 <= x_e < globe.width
    print(f"✓ Extremes: West={x_w}, East={x_e}")


def test_threat_selection():
    """Test threat character and color selection"""
    globe = FlatWorldMap()

    assert globe.get_threat_char(0.85) == "●"
    assert globe.get_threat_char(0.70) == "◉"
    assert globe.get_threat_char(0.50) == "◯"
    assert globe.get_threat_color(0.85) == "bold red"
    print("✓ Threat character and color selection passed")


def test_add_threats():
    """Test adding threats"""
    globe = FlatWorldMap()

    # Single threat
    globe.add_threat(40.7128, -74.0060, "1.2.3.4", 0.85, "unknown")
    assert len(globe.threats) == 1
    print("✓ Single threat added")

    # Multiple threats
    globe.add_threat(51.5074, -0.1278, "5.6.7.8", 0.75, "cloud")
    globe.add_threat(48.8566, 2.3522, "9.10.11.12", 0.65, "hosting")
    assert len(globe.threats) == 3
    print("✓ Multiple threats added")

    # Max capacity test (deque maxlen=50)
    globe2 = FlatWorldMap()
    for i in range(60):
        globe2.add_threat(0, i, f"1.2.3.{i%256}", 0.5, "unknown")
    assert len(globe2.threats) == 50
    print("✓ Threat deque maxlen=50 working correctly")


def test_heatmap():
    """Test heatmap aggregation"""
    globe = FlatWorldMap()

    # Add threat at 0, 0
    globe.add_threat(0, 0, "1.2.3.4", 0.9, "unknown")
    assert len(globe.heatmap) > 0
    # heatmap_max starts at 1.0, so it stays at 1.0 since 0.9 < 1.0
    assert globe.heatmap_max == 1.0

    # Add another at same location
    globe.add_threat(0, 0, "5.6.7.8", 0.8, "cloud")
    assert (18, 9) in globe.heatmap
    assert abs(globe.heatmap[(18, 9)] - 1.7) < 0.0001  # 0.9 + 0.8
    assert abs(globe.heatmap_max - 1.7) < 0.0001  # Now 1.7 > 1.0
    print("✓ Heatmap aggregation working correctly")

    # Test with higher threat to increase heatmap_max
    globe2 = FlatWorldMap()
    globe2.add_threat(0, 0, "1.2.3.4", 1.5, "unknown")  # Score > 1.0
    assert abs(globe2.heatmap[(18, 9)] - 1.5) < 0.0001
    assert abs(globe2.heatmap_max - 1.5) < 0.0001
    print("✓ Heatmap max updating correctly")

    # Grid bounds test
    globe2 = FlatWorldMap()
    for i in range(20):
        globe2.add_threat(85, 180, f"1.2.3.{i}", 0.5, "unknown")
    for gx, gy in globe2.heatmap.keys():
        assert 0 <= gx <= 35
        assert 0 <= gy <= 17
    print("✓ Heatmap grid bounds clamping working")


def test_update():
    """Test update mechanism"""
    globe = FlatWorldMap()
    globe.add_threat(0, 0, "1.2.3.4", 0.75, "unknown")

    initial_age = globe.threats[0].age
    globe.update(dt=0.5)
    assert globe.threats[0].age == initial_age + 0.5
    assert globe.time_elapsed == 0.5
    assert globe.frame_count == 1

    globe.update(dt=0.1)
    assert globe.threats[0].age == initial_age + 0.6
    assert globe.time_elapsed == 0.6
    assert globe.frame_count == 2
    print("✓ Update mechanism and aging working")


def test_render():
    """Test rendering"""
    globe = FlatWorldMap()

    # Empty render
    panel = globe.render()
    assert panel is not None
    assert "World Threat Map" in str(panel.title)
    print("✓ Empty render successful")

    # With threats
    globe.add_threat(40.7128, -74.0060, "1.2.3.4", 0.85, "unknown")
    globe.add_threat(51.5074, -0.1278, "5.6.7.8", 0.75, "cloud")
    assert len(globe.threats) == 2
    panel = globe.render()
    assert panel is not None
    assert hasattr(panel, 'title')
    print("✓ Render with threats successful")


def test_render_performance():
    """Test rendering performance"""
    globe = FlatWorldMap()

    # Add maximum capacity threats
    for i in range(50):
        lat = (i % 18) * 10 - 85
        lon = (i % 36) * 10 - 180
        globe.add_threat(lat, lon, f"1.2.3.{i%256}", 0.5 + (i % 50) / 100, "unknown")

    # Measure render time
    start = time.time()
    panel = globe.render()
    elapsed = time.time() - start

    assert elapsed < 0.05  # Should render in <50ms
    print(f"✓ Render with 50 threats: {elapsed*1000:.2f}ms")

    # Caching test
    start = time.time()
    panel2 = globe.render()
    elapsed2 = time.time() - start
    print(f"✓ Cached render: {elapsed2*1000:.2f}ms")


def test_clear():
    """Test clearing threats"""
    globe = FlatWorldMap()
    globe.add_threat(0, 0, "1.2.3.4", 0.75, "unknown")
    globe.add_threat(10, 10, "5.6.7.8", 0.85, "cloud")

    assert len(globe.threats) == 2
    globe.clear_threats()
    assert len(globe.threats) == 0
    assert len(globe.heatmap) == 0
    assert globe.heatmap_max == 1.0
    print("✓ Clear threats working")


def test_realistic_scenario():
    """Test with realistic threat distribution"""
    globe = FlatWorldMap()

    threats_data = [
        (40.7128, -74.0060, "1.2.3.4", 0.95, "tor"),           # NY, Tor
        (51.5074, -0.1278, "5.6.7.8", 0.85, "vpn"),            # London, VPN
        (48.8566, 2.3522, "9.10.11.12", 0.75, "hosting"),      # Paris, Hosting
        (35.6762, 139.6503, "13.14.15.16", 0.65, "cloud"),     # Tokyo, Cloud
        (37.7749, -122.4194, "17.18.19.20", 0.55, "enterprise"),# SF, Enterprise
        (52.5200, 13.4050, "21.22.23.24", 0.45, "isp"),        # Berlin, ISP
        (55.7558, 37.6173, "25.26.27.28", 0.35, "unknown"),    # Moscow, Unknown
        (-33.8688, 151.2093, "29.30.31.32", 0.25, "education"),# Sydney, Education
        (-23.5505, -46.6333, "33.34.35.36", 0.15, "cdn"),      # São Paulo, CDN
        (1.3521, 103.8198, "37.38.39.40", 0.05, "government"),# Singapore, Government
    ]

    for lat, lon, ip, score, org_type in threats_data:
        globe.add_threat(lat, lon, ip, score, org_type)

    assert len(globe.threats) == 10

    # Simulate updates
    for i in range(5):
        globe.update(dt=0.2)

    assert globe.time_elapsed == 1.0
    assert globe.frame_count == 5

    panel = globe.render()
    assert panel is not None

    high_threat = sum(1 for t in globe.threats if t.threat_score >= 0.7)
    assert high_threat >= 2
    print(f"✓ Realistic scenario: {len(globe.threats)} threats, {high_threat} critical")


def test_threat_pin():
    """Test ThreatPin dataclass"""
    pin = ThreatPin(
        lat=40.7128,
        lon=-74.0060,
        threat_score=0.85,
        org_type="cloud",
        ip="1.2.3.4",
        age=1.5
    )

    assert pin.lat == 40.7128
    assert pin.lon == -74.0060
    assert pin.threat_score == 0.85
    assert pin.org_type == "cloud"
    assert pin.ip == "1.2.3.4"
    assert pin.age == 1.5
    print("✓ ThreatPin dataclass working")


def main():
    """Run all tests"""
    tests = [
        ("Initialization", test_initialization),
        ("Coordinate Conversion", test_latlon_to_screen),
        ("Threat Selection", test_threat_selection),
        ("Add Threats", test_add_threats),
        ("Heatmap", test_heatmap),
        ("Update", test_update),
        ("Render", test_render),
        ("Render Performance", test_render_performance),
        ("Clear", test_clear),
        ("Realistic Scenario", test_realistic_scenario),
        ("ThreatPin", test_threat_pin),
    ]

    print("=" * 70)
    print("FlatWorldMap Unit Tests")
    print("=" * 70)

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            print(f"\n{test_name}:")
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test_name} failed: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test_name} error: {e}")
            failed += 1

    print("\n" + "=" * 70)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 70)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
