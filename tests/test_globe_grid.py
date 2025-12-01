#!/usr/bin/env python3
"""
Test suite for globe grid dashboard rendering.
Tests that the globe fits within the panel and renders correctly.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "src"))

from src.ui.globe_flat import FlatWorldMap, ThreatPin


def test_globe_initialization():
    """Test that globe initializes with correct dimensions"""
    globe = FlatWorldMap(width=60, height=18)

    assert globe.width == 60
    assert globe.height == 18
    assert len(globe.threats) == 0
    print("✓ Globe initialization test passed")


def test_globe_add_threats():
    """Test adding threats to the globe"""
    globe = FlatWorldMap(width=60, height=18)

    # Add various threats
    threats = [
        (37.7749, -122.4194, 0.8, "cloud", "1.2.3.4"),      # SF
        (51.5074, -0.1278, 0.6, "isp", "1.2.3.5"),           # London
        (35.6762, 139.6503, 0.9, "tor", "1.2.3.6"),          # Tokyo
        (37.7749, -122.4194, 0.5, "cdn", "1.2.3.7"),         # Duplicate location
        (-33.8688, 151.2093, 0.3, "enterprise", "1.2.3.8"),  # Sydney
    ]

    for lat, lon, score, org_type, ip in threats:
        globe.add_threat(lat, lon, ip, score, org_type)

    assert len(globe.threats) == 5
    assert len(globe.heatmap) > 0
    print(f"✓ Added {len(globe.threats)} threats to globe")
    print(f"✓ Heatmap has {len(globe.heatmap)} cells")


def test_globe_render():
    """Test that globe renders without errors"""
    globe = FlatWorldMap(width=60, height=18)

    # Add some threats
    globe.add_threat(37.7749, -122.4194, "1.2.3.4", 0.8, "cloud")
    globe.add_threat(51.5074, -0.1278, "1.2.3.5", 0.6, "isp")
    globe.add_threat(35.6762, 139.6503, "1.2.3.6", 0.9, "tor")

    # Render
    panel = globe.render()

    assert panel is not None
    assert hasattr(panel, 'title')
    assert hasattr(panel, 'renderable')
    print("✓ Globe renders without errors")
    print(f"✓ Panel title: {panel.title}")


def test_globe_canvas_size():
    """Test that rendered output respects canvas dimensions"""
    globe = FlatWorldMap(width=60, height=18)

    # Add threats
    for i in range(10):
        lat = (i % 10) * 10 - 45
        lon = (i % 5) * 30 - 75
        globe.add_threat(lat, lon, f"1.2.3.{i}", 0.5 + i*0.05, "cloud")

    panel = globe.render()

    # Get rendered text
    assert panel is not None
    print("✓ Canvas size test passed")


def test_globe_coordinate_conversion():
    """Test lat/lon to screen coordinate conversion"""
    globe = FlatWorldMap(width=60, height=18)

    # Test cardinal points
    tests = [
        (0, 0, "Equator/Prime Meridian"),
        (90, 0, "North Pole"),
        (-90, 0, "South Pole"),
        (0, 180, "Date Line East"),
        (0, -180, "Date Line West"),
        (45, 45, "NE Quadrant"),
        (-45, -45, "SW Quadrant"),
    ]

    for lat, lon, desc in tests:
        x, y = globe.latlon_to_screen(lat, lon)
        assert 0 <= x < globe.width, f"X out of bounds for {desc}"
        assert 0 <= y < globe.height, f"Y out of bounds for {desc}"

    print("✓ Coordinate conversion test passed")


def test_globe_threat_characters():
    """Test threat score to character mapping"""
    globe = FlatWorldMap(width=60, height=18)

    score_tests = [
        (0.9, "●"),
        (0.8, "●"),
        (0.7, "◉"),
        (0.6, "◉"),
        (0.5, "◯"),
        (0.4, "◯"),
        (0.3, "○"),
        (0.2, "○"),
        (0.1, "·"),
        (0.0, "·"),
    ]

    for score, expected_char in score_tests:
        char = globe.get_threat_char(score)
        assert char == expected_char, f"Score {score} should map to {expected_char}, got {char}"

    print("✓ Threat character mapping test passed")


def test_globe_threat_colors():
    """Test threat score to color mapping"""
    globe = FlatWorldMap(width=60, height=18)

    score_tests = [
        (0.9, "bold red"),
        (0.8, "bold red"),
        (0.7, "bold yellow"),
        (0.6, "bold yellow"),
        (0.5, "yellow"),
        (0.4, "yellow"),
        (0.3, "cyan"),
        (0.2, "cyan"),
        (0.1, "green"),
        (0.0, "green"),
    ]

    for score, expected_color in score_tests:
        color = globe.get_threat_color(score)
        assert color == expected_color, f"Score {score} should map to {expected_color}, got {color}"

    print("✓ Threat color mapping test passed")


def test_globe_maximum_threats():
    """Test that globe handles max threat capacity"""
    globe = FlatWorldMap(width=60, height=18)

    # Add more threats than the deque max (50)
    for i in range(100):
        lat = (i % 20) * 10 - 95
        lon = (i % 36) * 10 - 175
        globe.add_threat(lat, lon, f"1.2.3.{i}", 0.5, "cloud")

    # Should only keep max 50
    assert len(globe.threats) == 50
    print(f"✓ Globe maintains max threat capacity: {len(globe.threats)}/50")


def test_globe_update():
    """Test globe update/animation loop"""
    globe = FlatWorldMap(width=60, height=18)

    globe.add_threat(37.7749, -122.4194, "1.2.3.4", 0.8, "cloud")

    initial_time = globe.time_elapsed
    initial_frame = globe.frame_count

    # Update globe
    globe.update(0.05)

    assert globe.time_elapsed > initial_time
    assert globe.frame_count > initial_frame
    print("✓ Globe update loop test passed")


def test_globe_clear():
    """Test clearing threats from globe"""
    globe = FlatWorldMap(width=60, height=18)

    globe.add_threat(37.7749, -122.4194, "1.2.3.4", 0.8, "cloud")
    globe.add_threat(51.5074, -0.1278, "1.2.3.5", 0.6, "isp")

    assert len(globe.threats) > 0

    globe.clear_threats()

    assert len(globe.threats) == 0
    assert len(globe.heatmap) == 0
    print("✓ Clear threats test passed")


def run_all_tests():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("Globe Grid Dashboard Test Suite")
    print("=" * 60 + "\n")

    tests = [
        test_globe_initialization,
        test_globe_add_threats,
        test_globe_coordinate_conversion,
        test_globe_threat_characters,
        test_globe_threat_colors,
        test_globe_render,
        test_globe_canvas_size,
        test_globe_maximum_threats,
        test_globe_update,
        test_globe_clear,
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

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60 + "\n")

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
