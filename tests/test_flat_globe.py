#!/usr/bin/env python3
"""
Unit tests for FlatWorldMap globe visualization
Tests: coordinate conversion, heatmap aggregation, rendering performance
"""

import pytest
import time
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ui.globe_flat import FlatWorldMap, ThreatPin


class TestFlatWorldMap:
    """Test suite for FlatWorldMap class"""

    @pytest.fixture
    def globe(self):
        """Create a FlatWorldMap instance for testing"""
        return FlatWorldMap(width=140, height=30)

    def test_initialization(self, globe):
        """Test basic initialization"""
        assert globe.width == 140
        assert globe.height == 30
        assert len(globe.threats) == 0
        assert len(globe.heatmap) == 0
        assert globe.time_elapsed == 0.0
        assert globe.frame_count == 0

    def test_latlon_to_screen_center(self, globe):
        """Test coordinate conversion at center (0, 0)"""
        x, y = globe.latlon_to_screen(0, 0)
        # Center should be roughly in the middle
        assert 50 < x < 90  # Width is 140, so center ~70
        assert 10 < y < 20  # Height is 30, so center ~15

    def test_latlon_to_screen_extreme(self, globe):
        """Test coordinate conversion at extremes"""
        # North pole
        x_np, y_np = globe.latlon_to_screen(85, 0)
        assert 0 <= x_np < globe.width
        assert 0 <= y_np < globe.height

        # South pole
        x_sp, y_sp = globe.latlon_to_screen(-85, 0)
        assert 0 <= x_sp < globe.width
        assert 0 <= y_sp < globe.height
        # South should be lower (higher y value)
        assert y_sp > y_np

        # West
        x_w, y_w = globe.latlon_to_screen(0, -180)
        assert 0 <= x_w < globe.width

        # East
        x_e, y_e = globe.latlon_to_screen(0, 180)
        assert 0 <= x_e < globe.width

    def test_latlon_to_screen_clamping(self, globe):
        """Test that coordinates are clamped to valid ranges"""
        # Invalid latitude (too high)
        x, y = globe.latlon_to_screen(95, 0)
        assert 0 <= x < globe.width
        assert 0 <= y < globe.height

        # Invalid latitude (too low)
        x, y = globe.latlon_to_screen(-95, 0)
        assert 0 <= x < globe.width
        assert 0 <= y < globe.height

    def test_threat_char_selection(self, globe):
        """Test threat character selection by score"""
        assert globe.get_threat_char(0.85) == "●"  # Critical
        assert globe.get_threat_char(0.70) == "◉"  # High
        assert globe.get_threat_char(0.50) == "◯"  # Medium
        assert globe.get_threat_char(0.30) == "○"  # Low
        assert globe.get_threat_char(0.10) == "·"  # Info

    def test_threat_color_selection(self, globe):
        """Test threat color selection by score"""
        assert globe.get_threat_color(0.85) == "bold red"
        assert globe.get_threat_color(0.70) == "bold yellow"
        assert globe.get_threat_color(0.50) == "yellow"
        assert globe.get_threat_color(0.30) == "cyan"
        assert globe.get_threat_color(0.10) == "green"

    def test_add_threat_single(self, globe):
        """Test adding a single threat"""
        globe.add_threat(40.7128, -74.0060, "1.2.3.4", 0.85, "unknown")
        assert len(globe.threats) == 1
        threat = globe.threats[0]
        assert threat.ip == "1.2.3.4"
        assert threat.threat_score == 0.85
        assert threat.lat == 40.7128
        assert threat.lon == -74.0060

    def test_add_threat_multiple(self, globe):
        """Test adding multiple threats"""
        ips = ["1.2.3.4", "5.6.7.8", "9.10.11.12"]
        lats = [40.7128, 51.5074, 35.6762]
        lons = [-74.0060, -0.1278, 139.6503]

        for ip, lat, lon in zip(ips, lats, lons):
            globe.add_threat(lat, lon, ip, 0.75, "unknown")

        assert len(globe.threats) == 3
        assert globe.threats[0].ip == "1.2.3.4"
        assert globe.threats[1].ip == "5.6.7.8"
        assert globe.threats[2].ip == "9.10.11.12"

    def test_add_threat_max_capacity(self, globe):
        """Test that threat deque respects maxlen=50"""
        for i in range(60):
            globe.add_threat(0, i, f"1.2.3.{i%256}", 0.5, "unknown")

        assert len(globe.threats) == 50  # maxlen=50
        # Oldest threats should be gone
        assert globe.threats[-1].ip == f"1.2.3.{59%256}"

    def test_heatmap_aggregation(self, globe):
        """Test heatmap grid aggregation"""
        # Add threat at 0, 0 (should map to grid cell 18, 9)
        globe.add_threat(0, 0, "1.2.3.4", 0.8, "unknown")

        # Check heatmap has data
        assert len(globe.heatmap) > 0
        assert globe.heatmap_max > 0

    def test_heatmap_grid_calculation(self, globe):
        """Test heatmap grid cell calculation"""
        # Threat at 0°, 0° should be in center grid cell
        globe.add_threat(0, 0, "1.2.3.4", 0.9, "unknown")

        # Grid: gx = (lon + 180) / 10, gy = (90 - lat) / 10
        # For (0, 0): gx = (0 + 180) / 10 = 18, gy = (90 - 0) / 10 = 9
        expected_grid = (18, 9)
        assert expected_grid in globe.heatmap
        assert globe.heatmap[expected_grid] == 0.9

    def test_update_aging(self, globe):
        """Test threat aging in update()"""
        globe.add_threat(0, 0, "1.2.3.4", 0.75, "unknown")
        initial_age = globe.threats[0].age

        globe.update(dt=0.5)
        assert globe.threats[0].age == initial_age + 0.5

        globe.update(dt=0.1)
        assert globe.threats[0].age == initial_age + 0.6

    def test_update_time_tracking(self, globe):
        """Test time tracking in update()"""
        globe.update(dt=1.0)
        assert globe.time_elapsed == 1.0
        assert globe.frame_count == 1

        globe.update(dt=0.5)
        assert globe.time_elapsed == 1.5
        assert globe.frame_count == 2

    def test_render_basic(self, globe):
        """Test that render returns a Panel"""
        panel = globe.render()
        assert panel is not None
        assert hasattr(panel, 'title')
        assert 'World Threat Map' in panel.title

    def test_render_with_threats(self, globe):
        """Test rendering with threats"""
        globe.add_threat(40.7128, -74.0060, "1.2.3.4", 0.85, "unknown")
        globe.add_threat(51.5074, -0.1278, "5.6.7.8", 0.75, "cloud")

        panel = globe.render()
        assert panel is not None
        # Should have threat count in stats
        assert "Threats: 2" in str(panel)

    def test_render_performance(self, globe):
        """Test rendering performance with 50 threats"""
        # Add maximum capacity threats
        for i in range(50):
            lat = (i % 18) * 10 - 85
            lon = (i % 36) * 10 - 180
            globe.add_threat(lat, lon, f"1.2.3.{i%256}", 0.5 + (i % 50) / 100, "unknown")

        # Measure render time
        start = time.time()
        panel = globe.render()
        elapsed = time.time() - start

        # Should render in less than 20ms even with 50 threats
        assert elapsed < 0.02, f"Render took {elapsed*1000:.1f}ms, expected <20ms"
        assert panel is not None

    def test_render_caching(self, globe):
        """Test base map caching"""
        # First render
        start1 = time.time()
        panel1 = globe.render()
        elapsed1 = time.time() - start1

        # Cache should be populated
        assert globe._base_map_cache is not None

        # Second render should be faster (uses cache)
        start2 = time.time()
        panel2 = globe.render()
        elapsed2 = time.time() - start2

        # Second render should be comparable or faster
        # (We don't assert strict faster due to timing variability)
        assert panel1 is not None
        assert panel2 is not None

    def test_clear_threats(self, globe):
        """Test clearing all threats"""
        globe.add_threat(0, 0, "1.2.3.4", 0.75, "unknown")
        globe.add_threat(10, 10, "5.6.7.8", 0.85, "cloud")
        globe.add_threat(20, 20, "9.10.11.12", 0.65, "hosting")

        assert len(globe.threats) == 3
        assert len(globe.heatmap) > 0

        globe.clear_threats()

        assert len(globe.threats) == 0
        assert len(globe.heatmap) == 0
        assert globe.heatmap_max == 1.0

    def test_org_colors(self, globe):
        """Test organization color mapping"""
        assert globe.org_colors['cloud'] == 'cyan'
        assert globe.org_colors['tor'] == 'bold red'
        assert globe.org_colors['vpn'] == 'bold magenta'
        assert globe.org_colors['unknown'] == 'dim white'

    def test_threat_pin_dataclass(self):
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

    def test_heatmap_grid_bounds(self, globe):
        """Test heatmap grid cell clamping"""
        # Extreme coordinates should clamp to valid grid cells
        globe.add_threat(85, 180, "1.2.3.4", 0.9, "unknown")

        # All grid cells should be within bounds
        for grid_cell in globe.heatmap.keys():
            gx, gy = grid_cell
            assert 0 <= gx <= 35
            assert 0 <= gy <= 17

    def test_multiple_threats_same_location(self, globe):
        """Test multiple threats at same location"""
        # Add two threats to same location
        globe.add_threat(0, 0, "1.2.3.4", 0.8, "unknown")
        globe.add_threat(0, 0, "5.6.7.8", 0.7, "cloud")

        assert len(globe.threats) == 2
        # Heatmap should aggregate scores
        assert (18, 9) in globe.heatmap
        assert globe.heatmap[(18, 9)] == 0.8 + 0.7


class TestFlatWorldMapIntegration:
    """Integration tests for FlatWorldMap with realistic data"""

    def test_realistic_threat_scenario(self):
        """Test with realistic threat distribution"""
        globe = FlatWorldMap(width=140, height=30)

        # Simulate real threat data
        threats_data = [
            # (lat, lon, ip, score, org_type)
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

        # Render should succeed
        panel = globe.render()
        assert panel is not None

        # Stats should be correct
        high_threat = sum(1 for t in globe.threats if t.threat_score >= 0.7)
        assert high_threat >= 2  # At least 2 high threats in our data

    def test_stress_test_max_threats(self):
        """Stress test with maximum threat capacity"""
        globe = FlatWorldMap(width=140, height=30)

        # Add 100 threats (50 will remain due to maxlen)
        import random
        for i in range(100):
            lat = random.uniform(-85, 85)
            lon = random.uniform(-180, 180)
            score = random.random()
            globe.add_threat(lat, lon, f"threat_{i}", score, "unknown")

        assert len(globe.threats) == 50

        # Multiple renders should work
        for _ in range(3):
            panel = globe.render()
            assert panel is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
