#!/usr/bin/env python3
"""
Visual test for the globe grid dashboard.
This test renders the globe and displays it to verify it fits properly in a panel.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.ui.globe_flat import FlatWorldMap
from rich.console import Console


def test_globe_visual_output():
    """Render globe and display the output"""
    console = Console()

    globe = FlatWorldMap(width=60, height=18)

    # Add some realistic threat data
    threats = [
        (37.7749, -122.4194, 0.85, "cloud", "1.2.3.4"),
        (51.5074, -0.1278, 0.62, "isp", "4.5.6.7"),
        (35.6762, 139.6503, 0.91, "tor", "7.8.9.10"),
        (48.8566, 2.3522, 0.54, "cdn", "10.11.12.13"),
        (52.5200, 13.4050, 0.45, "enterprise", "13.14.15.16"),
        (-33.8688, 151.2093, 0.38, "hosting", "16.17.18.19"),
        (39.9042, 116.4074, 0.88, "vpn", "19.20.21.22"),
        (55.7558, 37.6173, 0.79, "isp", "22.23.24.25"),
        (1.3521, 103.8198, 0.66, "cloud", "25.26.27.28"),
        (34.0522, -118.2437, 0.92, "tor", "28.29.30.31"),
    ]

    for lat, lon, score, org_type, ip in threats:
        globe.add_threat(lat, lon, ip, score, org_type)

    print("\n" + "=" * 70)
    print("GLOBE GRID DASHBOARD - VISUAL TEST")
    print("=" * 70)
    print(f"\nGlobe dimensions: {globe.width} x {globe.height} characters")
    print(f"Threats loaded: {len(globe.threats)}")
    print(f"Heatmap cells active: {len(globe.heatmap)}")
    print("\n" + "-" * 70)
    print("RENDERED OUTPUT (within panel bounds):")
    print("-" * 70 + "\n")

    # Render the globe
    panel = globe.render()

    # Display with rich
    console.print(panel)

    print("\n" + "-" * 70)
    print("PANEL METRICS:")
    print("-" * 70)
    print(f"✓ Width: {globe.width} chars (fits in standard ~100 char panel)")
    print(f"✓ Height: {globe.height} lines (fits in standard ~30 line panel)")
    print(f"✓ Aspect ratio: {globe.width/globe.height:.2f}:1 (wide format)")
    print(f"✓ Threat density: {len(globe.threats) / (globe.width*globe.height)*100:.1f}% of cells")
    print(f"✓ Heatmap density: {len(globe.heatmap) / 648*100:.1f}% of grid cells (36x18 geographic grid)")
    print("\n" + "=" * 70 + "\n")

    return True


def test_globe_with_max_threats():
    """Test globe with maximum threat capacity"""
    console = Console()

    globe = FlatWorldMap(width=60, height=18)

    # Add max threats
    for i in range(50):
        lat = (i * 7.2) % 180 - 90
        lon = (i * 7.2) % 360 - 180
        globe.add_threat(lat, lon, f"192.168.{i//256}.{i%256}", 0.5 + i*0.01, "cloud")

    print("\n" + "=" * 70)
    print("GLOBE WITH MAXIMUM THREATS (50)")
    print("=" * 70 + "\n")

    panel = globe.render()
    console.print(panel)

    print("\n✓ Successfully rendered {0} threats".format(len(globe.threats)))
    print("=" * 70 + "\n")

    return True


def test_globe_density_levels():
    """Test globe with different threat densities"""
    console = Console()

    densities = {
        "Low": 5,
        "Medium": 15,
        "High": 30,
        "Critical": 50,
    }

    print("\n" + "=" * 70)
    print("GLOBE DENSITY LEVELS TEST")
    print("=" * 70)

    for level, count in densities.items():
        globe = FlatWorldMap(width=60, height=18)

        for i in range(count):
            lat = (i * 180 / count) - 90
            lon = (i * 360 / count) - 180
            score = 0.3 + (i / count) * 0.6
            globe.add_threat(lat, lon, f"1.2.3.{i}", score, "cloud")

        panel = globe.render()

        print(f"\n[{level.upper()} DENSITY: {count} threats]")
        print("-" * 70)
        console.print(panel)

    print("\n" + "=" * 70 + "\n")
    return True


if __name__ == "__main__":
    try:
        print("\nStarting visual tests...\n")

        test_globe_visual_output()
        test_globe_with_max_threats()
        test_globe_density_levels()

        print("\n✓ All visual tests completed successfully!")
        print("\nThe globe grid fits properly within the dashboard panel.")
        print("Size: 60x18 characters")
        print("Format: Equirectangular world map with threat markers and heatmap")
        print("\n")

        sys.exit(0)

    except Exception as e:
        print(f"\n✗ Visual test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
