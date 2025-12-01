#!/usr/bin/env python3
"""
Integration tests for the globe grid dashboard.
Tests interaction between dashboard and globe components.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.ui.globe_flat import FlatWorldMap


def test_dashboard_globe_size():
    """Test that the globe size matches dashboard panel constraints"""
    # Dashboard panels are typically 40-60 chars wide and 15-20 chars tall
    # The EnhancedThreatGlobePanel is now using 60x18
    globe = FlatWorldMap(width=60, height=18)

    assert globe.width == 60, f"Expected width 60, got {globe.width}"
    assert globe.height == 18, f"Expected height 18, got {globe.height}"

    print(f"✓ Globe size optimal for panel: {globe.width}x{globe.height}")


def test_globe_performance():
    """Test globe rendering performance"""
    import time

    globe = FlatWorldMap(width=60, height=18)

    # Add threats
    for i in range(30):
        lat = (i % 18) * 10 - 85
        lon = (i % 36) * 10 - 175
        globe.add_threat(lat, lon, f"192.168.{i//256}.{i%256}", 0.3 + i*0.02, "cloud")

    # Time rendering
    start = time.time()
    for _ in range(10):
        panel = globe.render()
        globe.update(0.05)
    elapsed = time.time() - start

    avg_time = elapsed / 10
    print(f"✓ Average render time: {avg_time*1000:.2f}ms per frame (target: <50ms)")
    assert avg_time < 0.05, f"Render time too slow: {avg_time*1000:.2f}ms"


def test_globe_with_real_threat_data():
    """Test globe with realistic threat data"""
    globe = FlatWorldMap(width=60, height=18)

    # Simulated real threat data
    threat_data = [
        # (lat, lon, threat_score, org_type, ip)
        (37.7749, -122.4194, 0.85, "cloud", "1.2.3.4"),        # AWS US-WEST-2
        (51.5074, -0.1278, 0.62, "isp", "4.5.6.7"),             # UK ISP
        (35.6762, 139.6503, 0.91, "tor", "7.8.9.10"),           # Tokyo Tor Exit
        (48.8566, 2.3522, 0.54, "cdn", "10.11.12.13"),          # Paris CDN
        (52.5200, 13.4050, 0.45, "enterprise", "13.14.15.16"),  # Berlin Corp
        (-33.8688, 151.2093, 0.38, "hosting", "16.17.18.19"),   # Sydney Host
        (39.9042, 116.4074, 0.88, "vpn", "19.20.21.22"),        # Beijing VPN
        (55.7558, 37.6173, 0.79, "isp", "22.23.24.25"),         # Moscow ISP
        (1.3521, 103.8198, 0.66, "cloud", "25.26.27.28"),       # Singapore AWS
        (34.0522, -118.2437, 0.92, "tor", "28.29.30.31"),       # LA Tor Node
    ]

    for lat, lon, score, org_type, ip in threat_data:
        globe.add_threat(lat, lon, ip, score, org_type)

    assert len(globe.threats) == len(threat_data)
    assert globe.heatmap_max > 0

    # Verify render succeeds
    panel = globe.render()
    assert panel is not None

    print(f"✓ Processed {len(globe.threats)} realistic threats")
    print(f"✓ Heatmap coverage: {len(globe.heatmap)} cells")
    print(f"✓ Max threat score: {globe.heatmap_max:.2f}")


def test_globe_regional_distribution():
    """Test that threats are distributed across regions"""
    globe = FlatWorldMap(width=60, height=18)

    # Add threats across different regions
    regions = {
        "North America": (37.7749, -122.4194),
        "Europe": (51.5074, -0.1278),
        "Asia": (35.6762, 139.6503),
        "South America": (-23.5505, -46.6333),
        "Africa": (-33.9249, 18.4241),
    }

    for region, (lat, lon) in regions.items():
        for i in range(3):
            globe.add_threat(lat + i*0.5, lon + i*0.5, f"1.2.3.{i}", 0.5, "cloud")

    assert len(globe.threats) == 15
    print(f"✓ Distributed {len(globe.threats)} threats across {len(regions)} regions")


def test_globe_animation():
    """Test globe animation frame counter"""
    globe = FlatWorldMap(width=60, height=18)

    globe.add_threat(0, 0, "1.2.3.4", 0.8, "cloud")

    initial_frame = globe.frame_count
    for i in range(20):
        globe.update(0.016)  # 60 FPS

    assert globe.frame_count > initial_frame
    assert globe.frame_count == initial_frame + 20

    print(f"✓ Animation frame counting works: {globe.frame_count} frames")


def test_globe_panel_rendering():
    """Test that globe renders as a Rich Panel suitable for dashboard"""
    from rich.panel import Panel

    globe = FlatWorldMap(width=60, height=18)

    # Add some threats
    for i in range(5):
        lat = i * 20 - 40
        lon = i * 30 - 75
        globe.add_threat(lat, lon, f"1.2.3.{i}", 0.5, "cloud")

    panel = globe.render()

    # Verify it's a Rich Panel
    assert isinstance(panel, Panel)
    assert panel.title is not None
    assert "🌍" in str(panel.title)  # Should have globe emoji

    print(f"✓ Globe renders as proper Rich Panel")
    print(f"✓ Panel title: {panel.title}")


def run_all_tests():
    """Run all integration tests"""
    print("\n" + "=" * 60)
    print("Globe Integration Test Suite")
    print("=" * 60 + "\n")

    tests = [
        test_dashboard_globe_size,
        test_globe_performance,
        test_globe_with_real_threat_data,
        test_globe_regional_distribution,
        test_globe_animation,
        test_globe_panel_rendering,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"✗ {test.__name__} failed: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60 + "\n")

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
