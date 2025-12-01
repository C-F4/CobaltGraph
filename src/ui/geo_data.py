#!/usr/bin/env python3
"""
Geographic data module for globe rendering
Provides country boundaries, coastlines, and coordinate systems
"""

from dataclasses import dataclass
from typing import List, Tuple, Dict, Optional


@dataclass
class Point:
    """A single geographic point"""
    lat: float
    lon: float


@dataclass
class Polygon:
    """A polygon representing a country or region"""
    name: str
    points: List[Point]

    def is_closed(self) -> bool:
        """Check if polygon is properly closed"""
        if len(self.points) < 3:
            return False
        return (self.points[0].lat == self.points[-1].lat and
                self.points[0].lon == self.points[-1].lon)


class GeoData:
    """
    Simplified world map with country boundaries
    Uses simplified coastlines for terminal rendering
    """

    def __init__(self):
        """Initialize geographic data"""
        self.countries = self._load_countries()
        self.coastlines = self._load_coastlines()

    def _load_countries(self) -> Dict[str, Polygon]:
        """Load simplified country boundaries (major countries only)"""
        countries = {}

        # North America
        countries['USA'] = Polygon('USA', [
            Point(49, -125), Point(49, -65), Point(25, -65),
            Point(25, -125), Point(49, -125)
        ])

        countries['Canada'] = Polygon('Canada', [
            Point(83, -141), Point(83, -52), Point(60, -52),
            Point(60, -141), Point(83, -141)
        ])

        countries['Mexico'] = Polygon('Mexico', [
            Point(33, -117), Point(33, -86), Point(14, -86),
            Point(14, -117), Point(33, -117)
        ])

        # South America
        countries['Brazil'] = Polygon('Brazil', [
            Point(5, -35), Point(5, -73), Point(-35, -73),
            Point(-35, -35), Point(5, -35)
        ])

        countries['Argentina'] = Polygon('Argentina', [
            Point(-22, -55), Point(-22, -73), Point(-56, -73),
            Point(-56, -55), Point(-22, -55)
        ])

        # Europe
        countries['Russia'] = Polygon('Russia', [
            Point(81, 18), Point(81, 169), Point(41, 169),
            Point(41, 18), Point(81, 18)
        ])

        countries['UK'] = Polygon('UK', [
            Point(59, -2), Point(59, -8), Point(50, -8),
            Point(50, -2), Point(59, -2)
        ])

        countries['France'] = Polygon('France', [
            Point(51, -5), Point(51, 8), Point(42, 8),
            Point(42, -5), Point(51, -5)
        ])

        countries['Germany'] = Polygon('Germany', [
            Point(56, 5), Point(56, 16), Point(47, 16),
            Point(47, 5), Point(56, 5)
        ])

        countries['Spain'] = Polygon('Spain', [
            Point(44, -9), Point(44, 4), Point(35, 4),
            Point(35, -9), Point(44, -9)
        ])

        countries['Italy'] = Polygon('Italy', [
            Point(47, 6), Point(47, 19), Point(37, 19),
            Point(37, 6), Point(47, 6)
        ])

        countries['Greece'] = Polygon('Greece', [
            Point(42, 19), Point(42, 29), Point(34, 29),
            Point(34, 19), Point(42, 19)
        ])

        # Africa
        countries['Egypt'] = Polygon('Egypt', [
            Point(32, 25), Point(32, 37), Point(22, 37),
            Point(22, 25), Point(32, 25)
        ])

        countries['Nigeria'] = Polygon('Nigeria', [
            Point(14, 2), Point(14, 15), Point(4, 15),
            Point(4, 2), Point(14, 2)
        ])

        countries['South Africa'] = Polygon('South Africa', [
            Point(-22, 16), Point(-22, 33), Point(-35, 33),
            Point(-35, 16), Point(-22, 16)
        ])

        # Middle East
        countries['Saudi Arabia'] = Polygon('Saudi Arabia', [
            Point(33, 34), Point(33, 56), Point(16, 56),
            Point(16, 34), Point(33, 34)
        ])

        countries['Iran'] = Polygon('Iran', [
            Point(38, 44), Point(38, 61), Point(25, 61),
            Point(25, 44), Point(38, 44)
        ])

        countries['Iraq'] = Polygon('Iraq', [
            Point(38, 38), Point(38, 49), Point(29, 49),
            Point(29, 38), Point(38, 38)
        ])

        # Asia
        countries['China'] = Polygon('China', [
            Point(54, 73), Point(54, 135), Point(18, 135),
            Point(18, 73), Point(54, 73)
        ])

        countries['India'] = Polygon('India', [
            Point(35, 68), Point(35, 97), Point(8, 97),
            Point(8, 68), Point(35, 68)
        ])

        countries['Japan'] = Polygon('Japan', [
            Point(45, 130), Point(45, 146), Point(30, 146),
            Point(30, 130), Point(45, 130)
        ])

        countries['Southeast Asia'] = Polygon('Southeast Asia', [
            Point(21, 92), Point(21, 142), Point(1, 142),
            Point(1, 92), Point(21, 92)
        ])

        countries['Australia'] = Polygon('Australia', [
            Point(-10, 113), Point(-10, 154), Point(-44, 154),
            Point(-44, 113), Point(-10, 113)
        ])

        return countries

    def _load_coastlines(self) -> List[Polygon]:
        """Load simplified continent outlines for better visual representation"""
        coastlines = []

        # North America - simplified outline
        coastlines.append(Polygon('North America', [
            Point(50, -140), Point(50, -100), Point(48, -95),
            Point(45, -93), Point(42, -85), Point(40, -75),
            Point(35, -80), Point(30, -85), Point(25, -97),
            Point(20, -105), Point(25, -110), Point(30, -115),
            Point(35, -120), Point(45, -125), Point(50, -140)
        ]))

        # South America - simplified outline
        coastlines.append(Polygon('South America', [
            Point(12, -60), Point(10, -65), Point(5, -70),
            Point(0, -72), Point(-5, -72), Point(-10, -72),
            Point(-15, -70), Point(-20, -68), Point(-25, -65),
            Point(-30, -60), Point(-35, -55), Point(-40, -56),
            Point(-40, -60), Point(-35, -62), Point(-30, -65),
            Point(-20, -70), Point(-10, -72), Point(0, -70),
            Point(5, -65), Point(12, -60)
        ]))

        # Europe + Africa - simplified
        coastlines.append(Polygon('Africa & Europe', [
            Point(70, -10), Point(65, 0), Point(60, 10),
            Point(55, 20), Point(50, 25), Point(45, 20),
            Point(40, 10), Point(35, 0), Point(30, -10),
            Point(25, -20), Point(20, -30), Point(15, -35),
            Point(10, -35), Point(5, -30), Point(0, -20),
            Point(-5, -10), Point(-10, -5), Point(-15, 0),
            Point(-20, 10), Point(-15, 20), Point(-5, 25),
            Point(5, 20), Point(15, 15), Point(25, 10),
            Point(35, 5), Point(45, 15), Point(55, 20),
            Point(65, 10), Point(70, -10)
        ]))

        # Asia - simplified
        coastlines.append(Polygon('Asia', [
            Point(70, 30), Point(70, 100), Point(60, 120),
            Point(50, 130), Point(40, 135), Point(30, 140),
            Point(20, 130), Point(15, 110), Point(10, 90),
            Point(15, 70), Point(25, 50), Point(35, 40),
            Point(45, 35), Point(55, 30), Point(65, 25),
            Point(70, 30)
        ]))

        # Australia
        coastlines.append(Polygon('Australia', [
            Point(-10, 115), Point(-10, 155), Point(-30, 155),
            Point(-40, 150), Point(-43, 140), Point(-40, 130),
            Point(-25, 128), Point(-15, 125), Point(-10, 115)
        ]))

        return coastlines

    def get_country(self, name: str) -> Optional[Polygon]:
        """Get country boundary by name"""
        return self.countries.get(name)

    def get_all_countries(self) -> List[Polygon]:
        """Get all country polygons"""
        return list(self.countries.values())

    def get_coastlines(self) -> List[Polygon]:
        """Get major coastline polygons"""
        return self.coastlines

    def latlon_to_screen(self, lat: float, lon: float,
                        width: int, height: int,
                        rotation: float = 0.0) -> Tuple[int, int]:
        """
        Convert latitude/longitude to screen coordinates

        Args:
            lat: Latitude (-90 to 90)
            lon: Longitude (-180 to 180)
            width: Screen width
            height: Screen height
            rotation: Globe rotation angle (degrees, 0-360)

        Returns:
            (x, y) screen coordinates, or None if point is behind globe
        """
        # Apply rotation
        rotated_lon = (lon + rotation) % 360
        if rotated_lon > 180:
            rotated_lon -= 360

        # Check if point is visible (front hemisphere)
        if rotated_lon < -90 or rotated_lon > 90:
            return None

        # Simple cylindrical projection
        # X: longitude -90 to 90 → 0 to width
        # Y: latitude -90 to 90 → height to 0 (inverted)
        x = int((rotated_lon + 90) / 180 * (width - 1))
        y = int((90 - lat) / 180 * (height - 1))

        # Clip to screen bounds
        if 0 <= x < width and 0 <= y < height:
            return (x, y)

        return None

    def apply_mercator_projection(self, lat: float, lon: float) -> Tuple[float, float]:
        """Apply Mercator projection for better visual representation"""
        import math

        # Mercator projection
        x = lon
        y = math.log(math.tan(math.pi / 4 + math.radians(lat) / 2))

        return x, y

    def get_world_map_detailed(self) -> Dict[str, List[Tuple[float, float]]]:
        """
        Get detailed 30-country world map for flat visualization
        Returns simplified country boundaries optimized for terminal rendering
        """
        return {
            # North America
            'USA': [
                (49, -125), (49, -120), (49, -115), (49, -110), (49, -105),
                (48, -100), (47, -95), (46, -93), (44, -88), (42, -85),
                (40, -80), (38, -75), (36, -75), (34, -81), (32, -87),
                (30, -93), (28, -96), (27, -97), (26, -99), (25, -103),
                (26, -110), (30, -114), (35, -120), (40, -124), (43, -125),
                (49, -125)
            ],
            'Canada': [
                (83, -141), (83, -130), (83, -110), (83, -90), (83, -70),
                (75, -70), (65, -70), (60, -95), (60, -110), (60, -130),
                (68, -141), (75, -141), (83, -141)
            ],
            'Mexico': [
                (33, -117), (32, -110), (30, -103), (28, -98), (26, -97),
                (20, -87), (18, -92), (17, -96), (19, -104), (25, -110),
                (28, -113), (33, -117)
            ],
            # South America
            'Brazil': [
                (5, -35), (5, -50), (3, -60), (-5, -65), (-10, -68),
                (-15, -70), (-20, -68), (-25, -60), (-30, -55), (-33, -55),
                (-20, -40), (-10, -38), (0, -35), (5, -35)
            ],
            'Argentina': [
                (-22, -58), (-25, -62), (-30, -65), (-35, -68), (-40, -70),
                (-45, -72), (-50, -72), (-52, -70), (-52, -65), (-50, -60),
                (-45, -58), (-40, -60), (-35, -58), (-30, -60), (-25, -55),
                (-22, -58)
            ],
            'Colombia': [
                (13, -77), (11, -75), (8, -72), (2, -68), (1, -72),
                (3, -76), (6, -77), (10, -76), (13, -77)
            ],
            # Europe
            'Russia': [
                (69, 20), (69, 60), (69, 100), (69, 140), (69, 170),
                (60, 170), (50, 160), (45, 140), (45, 100), (45, 60),
                (45, 30), (50, 20), (60, 20), (69, 20)
            ],
            'UK': [
                (59, -2), (59, -8), (57, -6), (54, -5), (51, -1),
                (50, -3), (50, -5), (52, -3), (55, -4), (59, -2)
            ],
            'France': [
                (51, -5), (50, -1), (48, 2), (45, 4), (43, 2),
                (43, -1), (44, -6), (47, -5), (51, -5)
            ],
            'Germany': [
                (56, 5), (56, 16), (50, 16), (48, 8), (48, 5), (56, 5)
            ],
            'Spain': [
                (44, -9), (44, -1), (42, 4), (40, 3), (39, -3),
                (37, -8), (36, -9), (43, -9), (44, -9)
            ],
            'Italy': [
                (47, 6), (47, 19), (44, 20), (41, 19), (38, 16),
                (37, 12), (41, 12), (44, 9), (47, 6)
            ],
            'Greece': [
                (42, 19), (42, 29), (39, 29), (36, 28), (35, 23),
                (37, 19), (39, 21), (42, 19)
            ],
            'Poland': [
                (56, 14), (56, 25), (50, 25), (49, 14), (50, 14), (56, 14)
            ],
            'Ukraine': [
                (53, 22), (53, 42), (48, 42), (45, 34), (45, 22), (53, 22)
            ],
            'Turkey': [
                (42, 26), (42, 45), (37, 45), (36, 26), (39, 26), (42, 26)
            ],
            # Africa
            'Egypt': [
                (32, 25), (32, 37), (28, 37), (22, 37), (22, 25), (32, 25)
            ],
            'Nigeria': [
                (14, 2), (14, 15), (11, 15), (4, 12), (4, 2), (14, 2)
            ],
            'South Africa': [
                (-22, 16), (-22, 33), (-28, 33), (-34, 25), (-34, 16), (-22, 16)
            ],
            'Kenya': [
                (5, 34), (5, 42), (-1, 42), (-5, 34), (-4, 34), (0, 36), (5, 34)
            ],
            'Algeria': [
                (37, -9), (37, 9), (35, 10), (27, 6), (22, 0), (22, -9), (37, -9)
            ],
            # Middle East
            'Saudi Arabia': [
                (33, 34), (33, 56), (20, 56), (16, 40), (22, 34), (33, 34)
            ],
            'Iran': [
                (38, 44), (38, 61), (35, 61), (25, 54), (25, 44), (38, 44)
            ],
            'Iraq': [
                (38, 38), (38, 49), (33, 49), (29, 38), (33, 38), (38, 38)
            ],
            # Asia
            'China': [
                (54, 73), (54, 100), (54, 130), (50, 135), (40, 135),
                (30, 130), (25, 110), (25, 85), (30, 73), (40, 75), (54, 73)
            ],
            'India': [
                (35, 68), (35, 97), (30, 97), (20, 90), (10, 92), (8, 88),
                (8, 68), (20, 68), (28, 70), (35, 68)
            ],
            'Japan': [
                (45, 130), (45, 146), (42, 145), (36, 142), (30, 130),
                (30, 135), (35, 140), (42, 143), (45, 130)
            ],
            'Indonesia': [
                (7, 95), (7, 142), (-2, 142), (-11, 130), (-11, 95),
                (-5, 95), (0, 98), (5, 100), (7, 95)
            ],
            'South Korea': [
                (39, 124), (39, 132), (34, 132), (33, 126), (34, 124), (39, 124)
            ],
            # Oceania
            'Australia': [
                (-10, 113), (-10, 154), (-25, 154), (-40, 145),
                (-43, 135), (-40, 120), (-25, 113), (-10, 113)
            ],
        }
