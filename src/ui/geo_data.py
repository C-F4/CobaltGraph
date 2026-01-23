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
        """Load continent outlines with improved detail (~40-50 points per continent)."""
        coastlines = []

        # North America - improved outline (~45 points)
        coastlines.append(Polygon('North America', [
            Point(71, -156), Point(70, -141), Point(60, -141),  # Alaska
            Point(55, -130), Point(50, -127), Point(48, -124),  # Pacific NW
            Point(45, -124), Point(42, -124), Point(38, -123),  # California
            Point(34, -120), Point(32, -117), Point(28, -114),  # Baja
            Point(24, -110), Point(22, -106), Point(20, -105),  # Mexico Pacific
            Point(18, -103), Point(16, -95), Point(18, -92),    # Central America
            Point(20, -87), Point(22, -86), Point(25, -81),     # Yucatan
            Point(26, -80), Point(30, -81), Point(32, -80),     # Florida
            Point(35, -75), Point(37, -76), Point(39, -74),     # Mid-Atlantic
            Point(41, -71), Point(43, -70), Point(45, -67),     # New England
            Point(47, -64), Point(50, -58), Point(52, -56),     # Maritime Canada
            Point(55, -60), Point(60, -64), Point(63, -68),     # Labrador
            Point(66, -62), Point(70, -70), Point(72, -80),     # Baffin
            Point(75, -95), Point(72, -115), Point(71, -156),   # Arctic
        ]))

        # South America - improved outline (~40 points)
        coastlines.append(Polygon('South America', [
            Point(12, -72), Point(10, -75), Point(5, -77),      # Venezuela/Colombia coast
            Point(1, -79), Point(-2, -80), Point(-5, -81),      # Ecuador
            Point(-10, -78), Point(-15, -75), Point(-18, -70),  # Peru
            Point(-22, -70), Point(-27, -70), Point(-33, -72),  # Chile north
            Point(-40, -73), Point(-46, -75), Point(-52, -72),  # Chile south
            Point(-55, -68), Point(-54, -65), Point(-52, -59),  # Tierra del Fuego
            Point(-46, -67), Point(-42, -64), Point(-38, -57),  # Argentina coast
            Point(-35, -57), Point(-30, -50), Point(-25, -47),  # Uruguay/Brazil south
            Point(-20, -42), Point(-15, -39), Point(-10, -37),  # Brazil east
            Point(-5, -35), Point(0, -48), Point(5, -52),       # Brazil north
            Point(8, -58), Point(10, -62), Point(12, -72),      # Guianas
        ]))

        # Europe - separate for clarity (~35 points)
        coastlines.append(Polygon('Europe', [
            Point(71, 25), Point(70, 30), Point(68, 25),        # Norway north
            Point(64, 10), Point(58, 5), Point(56, 8),          # Scandinavia west
            Point(55, 12), Point(54, 10), Point(52, 4),         # Denmark/Netherlands
            Point(51, 2), Point(49, -5), Point(48, -5),         # France
            Point(44, -9), Point(37, -9), Point(36, -6),        # Iberia west
            Point(36, -2), Point(38, 0), Point(41, 2),          # Spain south/east
            Point(43, 3), Point(43, 6), Point(44, 8),           # France south
            Point(44, 12), Point(41, 18), Point(39, 20),        # Italy
            Point(40, 24), Point(41, 29), Point(46, 31),        # Greece/Turkey
            Point(55, 28), Point(60, 30), Point(65, 40),        # Baltic/Russia
            Point(69, 35), Point(70, 28), Point(71, 25),        # Norway
        ]))

        # Africa - improved outline (~40 points)
        coastlines.append(Polygon('Africa', [
            Point(35, -6), Point(34, 10), Point(32, 25),        # Mediterranean
            Point(31, 33), Point(29, 33), Point(25, 35),        # Egypt
            Point(20, 38), Point(15, 43), Point(12, 44),        # Horn approach
            Point(10, 50), Point(5, 48), Point(0, 42),          # Horn of Africa
            Point(-5, 40), Point(-10, 40), Point(-15, 38),      # East Africa
            Point(-20, 35), Point(-25, 35), Point(-30, 31),     # Mozambique
            Point(-34, 26), Point(-34, 18), Point(-30, 17),     # South Africa
            Point(-25, 15), Point(-20, 13), Point(-15, 12),     # Namibia/Angola
            Point(-10, 13), Point(-5, 10), Point(0, 6),         # Congo
            Point(5, 5), Point(10, 5), Point(15, 0),            # Gulf of Guinea
            Point(20, -5), Point(25, -10), Point(28, -14),      # West Africa
            Point(32, -13), Point(35, -6),                       # Morocco
        ]))

        # Asia - improved outline (~50 points)
        coastlines.append(Polygon('Asia', [
            Point(70, 70), Point(72, 80), Point(75, 100),       # Siberia north
            Point(72, 130), Point(70, 170), Point(65, 170),     # Siberia east
            Point(60, 165), Point(55, 160), Point(50, 145),     # Far east Russia
            Point(45, 142), Point(40, 132), Point(35, 129),     # Korea/Japan area
            Point(30, 122), Point(25, 120), Point(22, 114),     # China coast
            Point(20, 110), Point(15, 108), Point(10, 105),     # Vietnam
            Point(5, 103), Point(1, 104), Point(-5, 106),       # Indonesia start
            Point(-8, 114), Point(-8, 122), Point(-2, 130),     # Indonesia
            Point(5, 127), Point(12, 125), Point(18, 120),      # Philippines
            Point(20, 100), Point(15, 95), Point(10, 93),       # Thailand
            Point(8, 80), Point(10, 75), Point(15, 73),         # India south
            Point(20, 72), Point(25, 68), Point(25, 62),        # India west
            Point(28, 57), Point(27, 51), Point(30, 48),        # Arabian Peninsula
            Point(35, 35), Point(40, 30), Point(45, 35),        # Turkey
            Point(55, 55), Point(60, 60), Point(70, 70),        # Central Asia
        ]))

        # Australia - improved outline (~25 points)
        coastlines.append(Polygon('Australia', [
            Point(-10, 142), Point(-12, 140), Point(-15, 130),  # North coast
            Point(-18, 122), Point(-20, 115), Point(-25, 113),  # West coast
            Point(-30, 115), Point(-34, 116), Point(-35, 118),  # SW corner
            Point(-35, 137), Point(-37, 140), Point(-39, 145),  # South coast
            Point(-38, 147), Point(-33, 152), Point(-28, 154),  # SE coast
            Point(-24, 152), Point(-20, 149), Point(-16, 145),  # East coast
            Point(-12, 143), Point(-10, 142),                    # Back to north
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
