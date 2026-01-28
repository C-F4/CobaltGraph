#!/usr/bin/env python3
"""
Geographic data module for globe rendering
Provides country boundaries, coastlines, and coordinate systems
with improved accuracy for geo-spatial visualization
"""

from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Optional
import math


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
    is_water: bool = False  # True for lakes, seas, etc.

    def is_closed(self) -> bool:
        """Check if polygon is properly closed"""
        if len(self.points) < 3:
            return False
        return (self.points[0].lat == self.points[-1].lat and
                self.points[0].lon == self.points[-1].lon)

    def contains_point(self, lat: float, lon: float) -> bool:
        """
        Check if a point is inside this polygon using ray casting.
        """
        if len(self.points) < 3:
            return False

        inside = False
        n = len(self.points)
        j = n - 1

        for i in range(n):
            pi = self.points[i]
            pj = self.points[j]

            if ((pi.lon > lon) != (pj.lon > lon) and
                lat < (pj.lat - pi.lat) * (lon - pi.lon) / (pj.lon - pi.lon + 0.0001) + pi.lat):
                inside = not inside
            j = i

        return inside


class GeoData:
    """
    World map with accurate coastlines and boundaries
    Optimized for terminal rendering with land/ocean detection

    Uses a precomputed land mask grid for fast and accurate land detection.
    """

    def __init__(self):
        """Initialize geographic data"""
        self.countries = self._load_countries()
        self.coastlines = self._load_coastlines()
        self.water_bodies = self._load_water_bodies()
        self._land_cache: Dict[Tuple[int, int], bool] = {}

        # Precomputed land mask for accurate detection (1 degree resolution)
        self._land_mask = self._build_land_mask()

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
        """Load continent outlines with high accuracy for geo-spatial analysis."""
        coastlines = []

        # North America - detailed outline with major features
        coastlines.append(Polygon('North America', [
            # Alaska
            Point(71, -156), Point(70, -162), Point(66, -164), Point(64, -166),
            Point(61, -166), Point(58, -162), Point(56, -160), Point(55, -163),
            Point(52, -172), Point(52, -178), Point(55, 180), Point(60, 175),
            Point(65, 170), Point(70, -168), Point(71, -156),
        ]))

        coastlines.append(Polygon('North America Main', [
            # Alaska panhandle to BC
            Point(60, -141), Point(59, -138), Point(58, -134), Point(56, -132),
            Point(55, -130), Point(54, -131), Point(52, -128), Point(50, -127),
            # Pacific Northwest
            Point(49, -124), Point(48, -124), Point(47, -124), Point(46, -124),
            Point(45, -124), Point(44, -124), Point(43, -124), Point(42, -124),
            Point(41, -124), Point(40, -124), Point(39, -123), Point(38, -123),
            Point(37, -122), Point(36, -122), Point(35, -121), Point(34, -120),
            # Southern California / Baja
            Point(33, -118), Point(32, -117), Point(31, -116), Point(29, -114),
            Point(28, -113), Point(26, -112), Point(24, -110), Point(23, -110),
            # Mexico Pacific
            Point(22, -106), Point(20, -105), Point(19, -105), Point(18, -103),
            Point(17, -101), Point(16, -98), Point(16, -95), Point(17, -92),
            # Central America
            Point(18, -88), Point(17, -88), Point(16, -88), Point(15, -87),
            Point(14, -87), Point(13, -87), Point(12, -87), Point(11, -84),
            Point(10, -83), Point(9, -80), Point(8, -77),
        ]))

        coastlines.append(Polygon('North America East', [
            # Yucatan
            Point(21, -87), Point(21, -90), Point(20, -91), Point(19, -91),
            # Gulf of Mexico
            Point(19, -96), Point(26, -97), Point(28, -97), Point(29, -95),
            Point(30, -93), Point(29, -90), Point(30, -88), Point(30, -86),
            # Florida
            Point(30, -84), Point(29, -83), Point(28, -82), Point(27, -80),
            Point(26, -80), Point(25, -80), Point(24, -81), Point(25, -81),
            Point(26, -82), Point(28, -82), Point(30, -81), Point(31, -81),
            # US East Coast
            Point(32, -80), Point(33, -79), Point(34, -78), Point(35, -76),
            Point(36, -76), Point(37, -76), Point(38, -75), Point(39, -74),
            Point(40, -74), Point(41, -72), Point(42, -71), Point(43, -70),
            Point(44, -68), Point(45, -67), Point(46, -67),
            # Maritime Canada
            Point(47, -64), Point(46, -61), Point(45, -61), Point(44, -64),
            Point(44, -66), Point(45, -67), Point(47, -65), Point(48, -64),
            Point(49, -64), Point(50, -57), Point(52, -56), Point(53, -56),
            # Labrador
            Point(54, -58), Point(55, -59), Point(56, -60), Point(58, -62),
            Point(60, -64), Point(62, -66), Point(64, -68),
            # Baffin
            Point(66, -62), Point(67, -61), Point(69, -67), Point(70, -70),
            Point(72, -78), Point(73, -82), Point(74, -90), Point(74, -95),
            Point(72, -105), Point(70, -120), Point(69, -130), Point(70, -138),
            Point(69, -141), Point(60, -141),
        ]))

        # Greenland
        coastlines.append(Polygon('Greenland', [
            Point(83, -35), Point(83, -25), Point(81, -18), Point(78, -18),
            Point(76, -22), Point(74, -20), Point(72, -22), Point(70, -22),
            Point(68, -28), Point(66, -35), Point(64, -40), Point(62, -42),
            Point(60, -43), Point(60, -47), Point(62, -50), Point(66, -53),
            Point(68, -54), Point(70, -52), Point(72, -54), Point(74, -56),
            Point(77, -60), Point(79, -65), Point(81, -64), Point(83, -45),
            Point(83, -35),
        ]))

        # South America - detailed outline
        coastlines.append(Polygon('South America', [
            # Caribbean coast
            Point(12, -72), Point(12, -70), Point(11, -68), Point(11, -64),
            Point(10, -62), Point(9, -60), Point(8, -58), Point(7, -57),
            # Brazil north
            Point(5, -51), Point(3, -50), Point(1, -50), Point(0, -50),
            Point(-2, -44), Point(-3, -39), Point(-5, -35),
            # Brazil east
            Point(-7, -35), Point(-9, -35), Point(-12, -37), Point(-15, -39),
            Point(-18, -39), Point(-20, -40), Point(-22, -41), Point(-23, -43),
            Point(-24, -46), Point(-26, -48), Point(-28, -49), Point(-30, -51),
            # Uruguay/Argentina
            Point(-33, -53), Point(-35, -57), Point(-38, -58), Point(-40, -62),
            Point(-42, -64), Point(-44, -65), Point(-46, -67), Point(-48, -66),
            Point(-50, -68), Point(-52, -69), Point(-53, -68), Point(-54, -66),
            # Tierra del Fuego
            Point(-55, -68), Point(-55, -64), Point(-54, -64),
            # Chile south
            Point(-52, -72), Point(-50, -74), Point(-48, -75), Point(-46, -75),
            Point(-44, -73), Point(-42, -72), Point(-40, -73), Point(-38, -73),
            Point(-36, -73), Point(-34, -72), Point(-32, -71), Point(-30, -71),
            # Chile/Peru
            Point(-28, -71), Point(-26, -71), Point(-24, -70), Point(-22, -70),
            Point(-20, -70), Point(-18, -71), Point(-16, -73), Point(-14, -76),
            Point(-12, -77), Point(-10, -78), Point(-8, -79), Point(-6, -81),
            Point(-4, -81), Point(-2, -80), Point(0, -80),
            # Ecuador/Colombia
            Point(2, -79), Point(4, -77), Point(6, -77), Point(8, -77),
            Point(10, -75), Point(11, -73), Point(12, -72),
        ]))

        # Europe - detailed with Scandinavian fjords simplified
        coastlines.append(Polygon('Europe', [
            # Norway north
            Point(71, 28), Point(70, 25), Point(69, 26), Point(68, 23),
            Point(67, 15), Point(66, 13), Point(65, 12), Point(64, 11),
            Point(63, 8), Point(62, 6), Point(61, 5), Point(60, 5),
            # Scandinavia west
            Point(59, 5), Point(58, 6), Point(57, 8), Point(56, 9),
            Point(55, 10), Point(54, 11), Point(55, 13), Point(56, 14),
            # Denmark/Germany
            Point(55, 9), Point(54, 9), Point(54, 8), Point(53, 8),
            Point(52, 5), Point(51, 4), Point(51, 3),
            # Netherlands/Belgium/France
            Point(51, 2), Point(50, 1), Point(49, 0), Point(49, -1),
            Point(48, -4), Point(48, -5), Point(47, -3), Point(46, -1),
            # Brittany/Bay of Biscay
            Point(48, -5), Point(47, -4), Point(46, -2), Point(45, -1),
            Point(44, -2), Point(43, -2), Point(43, -8), Point(42, -9),
            # Iberian Peninsula
            Point(41, -9), Point(39, -9), Point(37, -9), Point(36, -8),
            Point(36, -6), Point(37, -7), Point(36, -5), Point(36, -2),
            Point(37, -1), Point(38, 0), Point(39, 0), Point(40, 0),
            Point(41, 1), Point(42, 3), Point(43, 3),
            # France south / Italy
            Point(43, 4), Point(43, 5), Point(43, 6), Point(43, 7),
            Point(44, 8), Point(44, 9), Point(45, 10), Point(45, 12),
            Point(44, 12), Point(43, 14), Point(42, 15), Point(41, 16),
            Point(40, 16), Point(39, 17), Point(38, 16), Point(37, 15),
            # Italy boot
            Point(38, 12), Point(39, 15), Point(40, 18), Point(41, 17),
            Point(42, 18), Point(44, 14), Point(46, 13),
            # Adriatic / Balkans
            Point(45, 14), Point(44, 15), Point(43, 17), Point(42, 18),
            Point(41, 19), Point(40, 20), Point(39, 20), Point(38, 21),
            # Greece
            Point(38, 23), Point(39, 23), Point(40, 23), Point(40, 25),
            Point(41, 26), Point(41, 29), Point(42, 28),
            # Turkey / Black Sea
            Point(42, 32), Point(42, 34), Point(43, 40), Point(46, 38),
            Point(47, 40), Point(48, 40), Point(50, 37), Point(54, 38),
            # Baltic
            Point(56, 21), Point(55, 20), Point(54, 19), Point(55, 17),
            Point(56, 16), Point(57, 17), Point(58, 17), Point(59, 18),
            Point(60, 19), Point(60, 22), Point(61, 22), Point(63, 21),
            Point(65, 24), Point(66, 24), Point(68, 28), Point(70, 28),
            Point(71, 28),
        ]))

        # British Isles
        coastlines.append(Polygon('British Isles', [
            # Great Britain
            Point(59, -3), Point(58, -5), Point(57, -6), Point(56, -6),
            Point(55, -5), Point(54, -5), Point(53, -4), Point(53, -3),
            Point(52, -4), Point(51, -5), Point(50, -5), Point(50, -4),
            Point(51, -3), Point(51, -1), Point(51, 0), Point(51, 1),
            Point(52, 2), Point(53, 0), Point(54, -1), Point(55, -2),
            Point(56, -2), Point(57, -2), Point(58, -3), Point(59, -3),
        ]))

        coastlines.append(Polygon('Ireland', [
            Point(55, -6), Point(55, -8), Point(54, -10), Point(53, -10),
            Point(52, -10), Point(51, -10), Point(52, -8), Point(52, -6),
            Point(53, -6), Point(54, -6), Point(55, -6),
        ]))

        # Africa - detailed outline
        coastlines.append(Polygon('Africa', [
            # Morocco / Western Sahara
            Point(36, -6), Point(35, -6), Point(34, -7), Point(32, -9),
            Point(30, -10), Point(28, -13), Point(26, -14), Point(24, -16),
            Point(22, -17), Point(20, -17), Point(18, -16), Point(16, -17),
            # West Africa
            Point(15, -17), Point(14, -17), Point(13, -16), Point(11, -15),
            Point(10, -14), Point(8, -13), Point(6, -10), Point(5, -7),
            Point(5, -4), Point(6, 0), Point(6, 2), Point(5, 5),
            # Gulf of Guinea
            Point(4, 6), Point(4, 7), Point(4, 8), Point(4, 10),
            Point(3, 10), Point(2, 10), Point(1, 9), Point(0, 9),
            Point(-1, 9), Point(-2, 9), Point(-4, 11), Point(-6, 12),
            # Congo / Angola
            Point(-6, 12), Point(-8, 13), Point(-10, 14), Point(-12, 14),
            Point(-14, 12), Point(-16, 12), Point(-17, 12),
            # Namibia / South Africa
            Point(-18, 12), Point(-20, 13), Point(-22, 14), Point(-25, 15),
            Point(-28, 16), Point(-31, 18), Point(-33, 18), Point(-34, 18),
            Point(-35, 20), Point(-34, 22), Point(-34, 26), Point(-33, 28),
            # South Africa east
            Point(-32, 29), Point(-30, 31), Point(-28, 32), Point(-26, 33),
            Point(-24, 35), Point(-22, 35), Point(-20, 35), Point(-18, 38),
            # Mozambique / Tanzania
            Point(-15, 40), Point(-12, 40), Point(-10, 40), Point(-8, 40),
            Point(-6, 39), Point(-5, 39), Point(-4, 40), Point(-2, 41),
            # Horn of Africa
            Point(0, 42), Point(2, 45), Point(4, 46), Point(8, 47),
            Point(10, 48), Point(11, 50), Point(12, 51), Point(11, 43),
            # Red Sea / Egypt
            Point(13, 43), Point(15, 42), Point(18, 38), Point(22, 36),
            Point(25, 35), Point(28, 34), Point(30, 33), Point(31, 32),
            Point(32, 32), Point(32, 30), Point(31, 28), Point(32, 25),
            # Mediterranean
            Point(33, 12), Point(35, 11), Point(37, 10), Point(37, 8),
            Point(37, 3), Point(36, -1), Point(35, -3), Point(36, -6),
        ]))

        # Asia - detailed with major peninsulas
        coastlines.append(Polygon('Asia', [
            # Middle East
            Point(32, 35), Point(34, 36), Point(36, 36), Point(37, 37),
            Point(40, 40), Point(42, 44), Point(42, 50), Point(40, 52),
            Point(38, 56), Point(37, 57), Point(36, 57),
            # Persian Gulf / Arabian Peninsula
            Point(30, 48), Point(28, 49), Point(26, 50), Point(24, 51),
            Point(23, 55), Point(22, 56), Point(22, 59), Point(25, 60),
            Point(26, 56), Point(28, 57), Point(29, 55), Point(29, 50),
            Point(30, 48),
        ]))

        coastlines.append(Polygon('Asia South', [
            # Arabian Peninsula south
            Point(17, 53), Point(15, 52), Point(14, 48), Point(13, 45),
            Point(12, 44), Point(12, 43),
            # India west coast
            Point(24, 68), Point(22, 69), Point(21, 70), Point(20, 72),
            Point(19, 73), Point(18, 73), Point(17, 73), Point(16, 73),
            Point(15, 74), Point(14, 74), Point(13, 75), Point(12, 75),
            Point(10, 76), Point(8, 77),
            # India south
            Point(7, 78), Point(8, 79), Point(10, 80), Point(12, 80),
            Point(13, 80), Point(14, 80), Point(15, 80), Point(16, 81),
            Point(18, 84), Point(20, 87), Point(21, 88), Point(22, 89),
            # Bangladesh
            Point(22, 91), Point(24, 92),
            # Myanmar / Thailand
            Point(21, 93), Point(19, 93), Point(17, 94), Point(15, 98),
            Point(13, 99), Point(11, 99), Point(10, 99), Point(8, 99),
            Point(7, 100), Point(6, 100), Point(5, 103),
            # Malaysia
            Point(4, 103), Point(3, 104), Point(1, 103), Point(1, 104),
        ]))

        coastlines.append(Polygon('Asia East', [
            # Vietnam
            Point(22, 107), Point(21, 106), Point(19, 106), Point(17, 107),
            Point(16, 108), Point(14, 109), Point(12, 109), Point(10, 107),
            Point(9, 105), Point(10, 104),
            # China south
            Point(22, 114), Point(23, 117), Point(25, 119), Point(27, 121),
            Point(29, 122), Point(31, 122), Point(32, 122), Point(34, 120),
            Point(36, 121), Point(38, 122), Point(40, 122),
            # Korea
            Point(40, 125), Point(38, 126), Point(37, 127), Point(36, 127),
            Point(35, 129), Point(34, 127), Point(33, 126),
            # Korea east
            Point(35, 129), Point(37, 130), Point(39, 128), Point(40, 129),
            Point(42, 130), Point(43, 131),
            # Russia Far East
            Point(45, 136), Point(47, 139), Point(49, 140), Point(50, 140),
            Point(52, 141), Point(54, 143), Point(56, 143), Point(58, 142),
            Point(60, 150), Point(61, 160), Point(63, 165), Point(65, 170),
            Point(66, 175), Point(68, 180),
        ]))

        # Japan
        coastlines.append(Polygon('Japan', [
            # Honshu
            Point(41, 140), Point(40, 140), Point(39, 140), Point(38, 140),
            Point(37, 140), Point(36, 140), Point(35, 139), Point(35, 138),
            Point(35, 137), Point(35, 136), Point(34, 135), Point(34, 134),
            Point(34, 133), Point(34, 132), Point(35, 133), Point(36, 136),
            Point(37, 137), Point(38, 138), Point(39, 140), Point(41, 140),
        ]))

        coastlines.append(Polygon('Hokkaido', [
            Point(43, 145), Point(44, 145), Point(45, 142), Point(44, 140),
            Point(42, 140), Point(42, 143), Point(43, 145),
        ]))

        # Indonesia major islands
        coastlines.append(Polygon('Sumatra', [
            Point(6, 95), Point(5, 97), Point(3, 99), Point(1, 101),
            Point(-1, 102), Point(-3, 104), Point(-5, 105), Point(-6, 105),
            Point(-6, 103), Point(-4, 102), Point(-2, 101), Point(0, 100),
            Point(2, 98), Point(4, 96), Point(6, 95),
        ]))

        coastlines.append(Polygon('Borneo', [
            Point(7, 117), Point(6, 118), Point(4, 118), Point(2, 118),
            Point(0, 117), Point(-2, 117), Point(-3, 116), Point(-4, 116),
            Point(-3, 114), Point(-2, 112), Point(0, 110), Point(2, 110),
            Point(4, 114), Point(6, 116), Point(7, 117),
        ]))

        coastlines.append(Polygon('New Guinea', [
            Point(-1, 131), Point(-2, 134), Point(-4, 137), Point(-5, 141),
            Point(-6, 144), Point(-7, 147), Point(-9, 148), Point(-10, 147),
            Point(-9, 143), Point(-8, 140), Point(-6, 138), Point(-5, 135),
            Point(-3, 132), Point(-1, 131),
        ]))

        # Australia - detailed outline
        coastlines.append(Polygon('Australia', [
            # North coast
            Point(-11, 136), Point(-12, 133), Point(-13, 130), Point(-14, 127),
            Point(-15, 124), Point(-17, 122), Point(-19, 121), Point(-21, 117),
            Point(-23, 114), Point(-25, 113), Point(-27, 114),
            # West coast
            Point(-29, 115), Point(-31, 116), Point(-33, 116), Point(-35, 117),
            # South coast
            Point(-35, 119), Point(-34, 122), Point(-34, 125), Point(-34, 128),
            Point(-35, 131), Point(-35, 134), Point(-36, 137), Point(-37, 140),
            Point(-39, 143), Point(-39, 147),
            # East coast
            Point(-38, 148), Point(-36, 150), Point(-34, 151), Point(-32, 152),
            Point(-30, 153), Point(-28, 154), Point(-25, 153), Point(-23, 151),
            Point(-20, 149), Point(-18, 146), Point(-15, 145), Point(-13, 142),
            Point(-11, 136),
        ]))

        # Tasmania
        coastlines.append(Polygon('Tasmania', [
            Point(-41, 145), Point(-42, 145), Point(-43, 146), Point(-44, 146),
            Point(-43, 148), Point(-42, 148), Point(-41, 147), Point(-41, 145),
        ]))

        # New Zealand
        coastlines.append(Polygon('New Zealand North', [
            Point(-35, 173), Point(-36, 175), Point(-38, 177), Point(-40, 176),
            Point(-41, 175), Point(-39, 174), Point(-37, 174), Point(-35, 173),
        ]))

        coastlines.append(Polygon('New Zealand South', [
            Point(-41, 174), Point(-42, 172), Point(-44, 169), Point(-46, 167),
            Point(-47, 168), Point(-46, 170), Point(-44, 172), Point(-42, 174),
            Point(-41, 174),
        ]))

        # Philippines
        coastlines.append(Polygon('Philippines', [
            Point(19, 121), Point(18, 122), Point(16, 120), Point(14, 121),
            Point(12, 124), Point(10, 126), Point(8, 126), Point(6, 126),
            Point(7, 124), Point(9, 123), Point(11, 120), Point(13, 120),
            Point(15, 120), Point(17, 120), Point(19, 121),
        ]))

        # Madagascar
        coastlines.append(Polygon('Madagascar', [
            Point(-12, 49), Point(-14, 48), Point(-16, 47), Point(-19, 44),
            Point(-22, 44), Point(-25, 45), Point(-25, 47), Point(-23, 48),
            Point(-20, 49), Point(-16, 50), Point(-13, 50), Point(-12, 49),
        ]))

        # Sri Lanka
        coastlines.append(Polygon('Sri Lanka', [
            Point(10, 80), Point(9, 80), Point(7, 80), Point(6, 80),
            Point(6, 81), Point(8, 82), Point(10, 81), Point(10, 80),
        ]))

        # Antarctica - visible portion within Miller projection bounds (capped at -85°)
        # Simplified outline of the Antarctic continent
        coastlines.append(Polygon('Antarctica', [
            # Starting from Antarctic Peninsula (pointing toward South America)
            Point(-63, -60), Point(-65, -58), Point(-68, -62), Point(-70, -60),
            Point(-72, -65), Point(-74, -70), Point(-76, -75), Point(-78, -80),
            # West Antarctica / Ross Sea region
            Point(-80, -90), Point(-82, -100), Point(-84, -110), Point(-85, -120),
            Point(-85, -130), Point(-85, -140), Point(-85, -150), Point(-84, -160),
            Point(-82, -170), Point(-80, -175), Point(-78, 180), Point(-76, 175),
            # East Antarctica
            Point(-74, 170), Point(-72, 160), Point(-70, 150), Point(-68, 140),
            Point(-66, 130), Point(-68, 120), Point(-70, 110), Point(-68, 100),
            Point(-66, 90), Point(-68, 80), Point(-70, 70), Point(-68, 60),
            Point(-66, 50), Point(-68, 40), Point(-70, 30), Point(-68, 20),
            Point(-70, 10), Point(-72, 0), Point(-70, -10), Point(-68, -20),
            Point(-70, -30), Point(-68, -40), Point(-66, -50), Point(-63, -60),
        ]))

        return coastlines

    def _load_water_bodies(self) -> List[Polygon]:
        """Load major internal water bodies."""
        water = []

        # Great Lakes
        water.append(Polygon('Great Lakes', [
            Point(49, -88), Point(48, -85), Point(46, -83), Point(45, -82),
            Point(43, -82), Point(42, -83), Point(42, -86), Point(44, -88),
            Point(46, -90), Point(48, -89), Point(49, -88),
        ], is_water=True))

        # Caspian Sea
        water.append(Polygon('Caspian Sea', [
            Point(47, 50), Point(45, 51), Point(43, 52), Point(40, 53),
            Point(38, 53), Point(37, 50), Point(38, 48), Point(40, 48),
            Point(43, 47), Point(45, 48), Point(47, 50),
        ], is_water=True))

        # Mediterranean (outline for rendering)
        water.append(Polygon('Mediterranean', [
            Point(36, -5), Point(37, 0), Point(38, 5), Point(37, 10),
            Point(38, 15), Point(37, 20), Point(35, 25), Point(34, 30),
            Point(31, 32), Point(31, 28), Point(33, 20), Point(35, 10),
            Point(36, 0), Point(36, -5),
        ], is_water=True))

        # Black Sea
        water.append(Polygon('Black Sea', [
            Point(46, 31), Point(45, 34), Point(44, 37), Point(43, 40),
            Point(42, 41), Point(41, 39), Point(42, 35), Point(43, 32),
            Point(45, 30), Point(46, 31),
        ], is_water=True))

        # Red Sea
        water.append(Polygon('Red Sea', [
            Point(28, 34), Point(26, 35), Point(22, 38), Point(18, 40),
            Point(14, 43), Point(13, 43), Point(15, 41), Point(20, 38),
            Point(24, 36), Point(27, 34), Point(28, 34),
        ], is_water=True))

        # Persian Gulf
        water.append(Polygon('Persian Gulf', [
            Point(30, 49), Point(28, 50), Point(26, 51), Point(25, 53),
            Point(26, 55), Point(27, 56), Point(29, 50), Point(30, 49),
        ], is_water=True))

        # Hudson Bay
        water.append(Polygon('Hudson Bay', [
            Point(63, -80), Point(60, -78), Point(58, -80), Point(56, -85),
            Point(55, -90), Point(57, -93), Point(60, -92), Point(63, -88),
            Point(63, -80),
        ], is_water=True))

        return water

    def _build_land_mask(self) -> set:
        """
        Build a precomputed land mask for accurate geography visualization.

        Uses a hybrid approach:
        1. Fill closed coastline polygons (Australia, Greenland, etc.)
        2. Use continental region approximations for complex multi-segment coastlines
        3. Refine with water body exclusions

        Returns a set of (lat, lon) tuples representing land at 1-degree resolution.
        """
        land = set()

        # First pass: fill closed coastline polygons
        # NOTE: Antarctica excluded - handled separately with minimal footprint
        closed_coastlines = [
            'Greenland', 'Australia', 'Tasmania', 'New Zealand North',
            'New Zealand South', 'Japan', 'Hokkaido', 'Sumatra', 'Borneo',
            'New Guinea', 'Philippines', 'Madagascar', 'Sri Lanka',
            'British Isles', 'Ireland'
        ]

        for coastline in self.coastlines:
            # Skip Antarctica polygon - handled separately with minimal footprint
            if coastline.name == 'Antarctica':
                continue
            if coastline.name in closed_coastlines or coastline.is_closed():
                if len(coastline.points) >= 3:
                    lats = [p.lat for p in coastline.points]
                    lons = [p.lon for p in coastline.points]
                    min_lat, max_lat = int(min(lats)), int(max(lats))
                    min_lon, max_lon = int(min(lons)), int(max(lons))

                    for lat in range(min_lat, max_lat + 1):
                        for lon in range(min_lon, max_lon + 1):
                            if coastline.contains_point(lat, lon):
                                land.add((lat, lon))

        # Second pass: continental approximations for accurate shapes
        # North America - contiguous US + Southern Canada with proper coastal detail
        for lat in range(25, 55):
            if lat >= 49:
                # US-Canada border region
                west, east = -125, -52
            elif lat >= 45:
                # Great Lakes region - narrower in east
                west, east = -125, -66
            elif lat >= 42:
                # Northern US
                west, east = -124, -70
            elif lat >= 38:
                # Mid-Atlantic states
                west, east = -124, -74
            elif lat >= 35:
                # Southern states
                west, east = -122, -75
            elif lat >= 30:
                # Gulf states / Florida panhandle
                west, east = -118, -80
            elif lat >= 27:
                # Florida peninsula (narrower)
                west, east = -98, -80
            else:
                # Southern Florida tip
                west, east = -82, -80
            for lon in range(west, east + 1):
                # Exclude Gulf of Mexico (larger exclusion)
                if 25 <= lat <= 30 and -97 <= lon <= -82:
                    continue
                # Exclude Great Lakes (more precise - don't exclude Chicago)
                # Lake Superior: lat 46-49, lon -92 to -84
                # Lake Michigan: lat 42-46, lon -87 to -84
                # Lake Huron: lat 43-46, lon -84 to -80
                # Lake Erie: lat 41-43, lon -84 to -78
                # Lake Ontario: lat 43-44, lon -80 to -76
                if 46 <= lat <= 49 and -92 <= lon <= -84:
                    continue  # Lake Superior
                if 42 <= lat <= 46 and -87 <= lon <= -84:
                    continue  # Lake Michigan (east of Chicago)
                if 43 <= lat <= 46 and -84 <= lon <= -80:
                    continue  # Lake Huron
                if 41 <= lat <= 43 and -84 <= lon <= -78:
                    continue  # Lake Erie
                if 43 <= lat <= 44 and -80 <= lon <= -76:
                    continue  # Lake Ontario
                land.add((lat, lon))

        # Florida peninsula detail
        for lat in range(25, 31):
            if lat >= 29:
                for lon in range(-88, -80):
                    land.add((lat, lon))
            elif lat >= 27:
                for lon in range(-83, -80):
                    land.add((lat, lon))
            else:
                for lon in range(-82, -80):
                    land.add((lat, lon))

        # Northern Canada and Canadian Arctic Archipelago
        for lat in range(55, 86):
            if lat >= 80:
                # High Arctic islands (Ellesmere, etc.)
                west, east = -120, -60
            elif lat >= 75:
                west, east = -130, -60
            elif lat >= 65:
                west, east = -140, -55
            else:
                west, east = -140, -55
            for lon in range(west, east + 1):
                # Exclude Hudson Bay
                if 52 <= lat <= 65 and -95 <= lon <= -78:
                    continue
                land.add((lat, lon))

        # Alaska (extend to Arctic coast)
        for lat in range(55, 75):
            for lon in range(-170, -130):
                land.add((lat, lon))

        # Mexico and Central America
        for lat in range(8, 33):
            if lat >= 25:
                west, east = -117, -87
            elif lat >= 18:
                west, east = -105, -86
            else:
                west, east = -92, -77
            for lon in range(west, east + 1):
                land.add((lat, lon))

        # South America (with Brazilian bulge and Patagonia)
        for lat in range(-56, 13):
            if lat >= 8:  # Northern SA / Venezuela / Colombia
                west, east = -82, -50
            elif lat >= 2:  # Ecuador / Northern Brazil (widest)
                west, east = -80, -35
            elif lat >= -5:  # Amazon region / Brazilian bulge eastward
                west, east = -78, -34
            elif lat >= -12:  # Central Brazil / Peru
                west, east = -78, -35
            elif lat >= -18:  # Bolivia / Central-Southern Brazil
                west, east = -72, -38
            elif lat >= -25:  # Paraguay / Southern Brazil
                west, east = -68, -42
            elif lat >= -35:  # Argentina / Uruguay / Chile narrowing
                west, east = -72, -52
            elif lat >= -42:  # Patagonia
                west, east = -73, -62
            elif lat >= -52:  # Southern Patagonia
                west, east = -75, -66
            else:
                # Tierra del Fuego / Cape Horn region
                west, east = -74, -65
            for lon in range(west, east + 1):
                land.add((lat, lon))

        # Extend Tierra del Fuego to Cape Horn (-56 to -58)
        for lat in range(-58, -55):
            for lon in range(-72, -66):
                land.add((lat, lon))

        # Europe - enhanced detail coverage
        # Great Britain (separate from continental Europe)
        for lat in range(50, 59):
            if lat >= 57:  # Northern Scotland / Highlands
                for lon in range(-7, -1):
                    land.add((lat, lon))
            elif lat >= 55:  # Scotland
                for lon in range(-6, 0):
                    land.add((lat, lon))
            elif lat >= 53:  # Northern England / Wales
                for lon in range(-5, 1):
                    land.add((lat, lon))
            elif lat >= 51:  # Southern England
                for lon in range(-6, 2):
                    land.add((lat, lon))
            else:  # Cornwall / Kent
                for lon in range(-6, 2):
                    land.add((lat, lon))
        # Ireland (island separate from Britain)
        for lat in range(51, 56):
            if lat >= 54:  # Northern Ireland / Donegal
                for lon in range(-11, -6):
                    land.add((lat, lon))
            else:  # Southern Ireland
                for lon in range(-11, -6):
                    land.add((lat, lon))

        # Iberian Peninsula (with better coastal definition)
        for lat in range(36, 44):
            if lat <= 37:  # Southern Spain/Gibraltar
                for lon in range(-9, 0):
                    land.add((lat, lon))
            elif lat <= 40:  # Central Spain/Portugal
                for lon in range(-10, 4):
                    land.add((lat, lon))
            else:  # Northern Spain
                for lon in range(-10, 4):
                    land.add((lat, lon))

        # France (with better coastal definition)
        for lat in range(42, 52):
            if lat <= 44:  # Southern France
                for lon in range(-2, 8):
                    land.add((lat, lon))
            elif lat <= 48:  # Central France
                for lon in range(-5, 9):
                    land.add((lat, lon))
            else:  # Northern France
                for lon in range(-5, 8):
                    land.add((lat, lon))

        # Benelux
        for lat in range(49, 54):
            for lon in range(2, 8):
                land.add((lat, lon))

        # Germany
        for lat in range(47, 55):
            for lon in range(6, 15):
                land.add((lat, lon))

        # Poland, Czech Republic
        for lat in range(49, 55):
            for lon in range(14, 24):
                land.add((lat, lon))

        # Austria, Switzerland, Hungary
        for lat in range(46, 49):
            for lon in range(6, 23):
                land.add((lat, lon))

        # Italy (boot shape with improved detail)
        for lat in range(36, 47):
            if lat == 36:  # Sicily (triangular)
                for lon in range(13, 16):
                    land.add((lat, lon))
            elif lat == 37:  # Sicily
                for lon in range(12, 16):
                    land.add((lat, lon))
            elif lat == 38:  # Sicily north / Calabria tip
                for lon in range(13, 17):
                    land.add((lat, lon))
            elif lat == 39:  # Calabria (narrow boot toe)
                for lon in range(15, 18):
                    land.add((lat, lon))
            elif lat == 40:  # Calabria / Campania
                for lon in range(14, 18):
                    land.add((lat, lon))
            elif lat == 41:  # Campania / Naples / Puglia
                for lon in range(13, 18):
                    land.add((lat, lon))
            elif lat == 42:  # Central Italy (Rome region)
                for lon in range(11, 17):
                    land.add((lat, lon))
            elif lat == 43:  # Tuscany / Marche
                for lon in range(10, 15):
                    land.add((lat, lon))
            elif lat == 44:  # Emilia-Romagna / Liguria
                for lon in range(8, 13):
                    land.add((lat, lon))
            elif lat == 45:  # Po Valley / Veneto
                for lon in range(7, 14):
                    land.add((lat, lon))
            else:  # Alps border (lat 46)
                for lon in range(7, 14):
                    land.add((lat, lon))
        # Sardinia
        for lat in range(39, 42):
            for lon in range(8, 10):
                land.add((lat, lon))
        # Corsica (French island)
        for lat in range(41, 43):
            for lon in range(8, 10):
                land.add((lat, lon))

        # Greece (with islands)
        for lat in range(35, 42):
            if lat <= 36:  # Crete
                for lon in range(23, 27):
                    land.add((lat, lon))
            elif lat <= 38:  # Southern Greece / Peloponnese
                for lon in range(21, 25):
                    land.add((lat, lon))
            elif lat <= 40:  # Central Greece
                for lon in range(20, 26):
                    land.add((lat, lon))
            else:  # Northern Greece
                for lon in range(19, 27):
                    land.add((lat, lon))

        # Balkans (Romania, Bulgaria, Serbia, etc.)
        for lat in range(40, 46):
            for lon in range(14, 30):
                # Exclude Adriatic Sea
                if lat <= 45 and lon <= 16 and lat >= 43:
                    continue
                land.add((lat, lon))

        # Turkey (European side)
        for lat in range(40, 42):
            for lon in range(26, 30):
                land.add((lat, lon))

        # Scandinavia (solid landmass)
        for lat in range(55, 72):
            if lat >= 70:  # Northern Norway / Arctic coast
                for lon in range(18, 32):
                    land.add((lat, lon))
            elif lat >= 65:  # Northern Sweden/Finland
                for lon in range(10, 30):
                    land.add((lat, lon))
            elif lat >= 60:  # Central Scandinavia (no fjord gaps at this resolution)
                for lon in range(5, 30):
                    land.add((lat, lon))
            elif lat >= 57:  # Southern Scandinavia
                for lon in range(8, 28):
                    land.add((lat, lon))
            else:  # Denmark / Southern Sweden
                for lon in range(8, 16):
                    land.add((lat, lon))

        # Svalbard
        for lat in range(77, 81):
            for lon in range(15, 28):
                land.add((lat, lon))

        # Baltic states, Eastern Europe
        for lat in range(48, 65):
            for lon in range(20, 45):
                land.add((lat, lon))

        # Russia / Northern Asia (extend to Arctic coast and islands)
        for lat in range(42, 82):
            if lat >= 75:
                # High Arctic (Novaya Zemlya, Franz Josef Land, Severnaya Zemlya)
                for lon in range(45, 180):
                    # Exclude Kara Sea
                    if 70 <= lon <= 75:
                        continue
                    land.add((lat, lon))
            elif lat >= 70:
                # Arctic coast
                for lon in range(30, 180):
                    # Exclude major Arctic seas
                    land.add((lat, lon))
            elif lat >= 60:
                # Northern Siberia
                for lon in range(30, 175):
                    land.add((lat, lon))
            elif lat >= 50:
                # Central Russia/Siberia (exclude Sea of Okhotsk)
                for lon in range(30, 170):
                    # Sea of Okhotsk exclusion
                    if lat <= 60 and 140 <= lon <= 160:
                        continue
                    land.add((lat, lon))
            else:
                # Southern Russia/Kazakhstan border
                for lon in range(40, 135):
                    land.add((lat, lon))

        # Kamchatka Peninsula
        for lat in range(51, 62):
            for lon in range(155, 165):
                land.add((lat, lon))

        # Sakhalin Island
        for lat in range(46, 55):
            for lon in range(141, 145):
                land.add((lat, lon))

        # Turkey (Asian side / Anatolia)
        for lat in range(36, 42):
            for lon in range(26, 45):
                # Exclude Mediterranean coast details
                land.add((lat, lon))

        # Middle East (better coastal definition)
        # Arabian Peninsula
        for lat in range(12, 32):
            if lat >= 28:  # Northern Arabia / Jordan
                for lon in range(34, 48):
                    land.add((lat, lon))
            elif lat >= 22:  # Central Arabia
                for lon in range(36, 56):
                    # Exclude Persian Gulf
                    if lon >= 48 and lat <= 28:
                        continue
                    land.add((lat, lon))
            elif lat >= 15:  # Southern Arabia / Yemen
                for lon in range(42, 55):
                    land.add((lat, lon))
            else:
                for lon in range(43, 52):
                    land.add((lat, lon))

        # Iran / Central Asia
        for lat in range(25, 40):
            for lon in range(44, 65):
                # Exclude Caspian Sea (more precise - don't exclude Tehran at lat 36)
                if 37 <= lat <= 48 and 48 <= lon <= 54:
                    continue
                land.add((lat, lon))

        # Central Asian republics (Kazakhstan, Turkmenistan, Uzbekistan, etc.)
        for lat in range(35, 55):
            for lon in range(50, 75):
                # Exclude Caspian Sea (more precise)
                if 37 <= lat <= 47 and 48 <= lon <= 54:
                    continue
                land.add((lat, lon))

        # India (triangular peninsula shape - distinctive subcontinent)
        for lat in range(6, 36):
            if lat >= 33:  # Kashmir / Himalayan foothills (narrow)
                for lon in range(74, 92):
                    land.add((lat, lon))
            elif lat >= 30:  # Northern India (wide)
                for lon in range(68, 95):
                    land.add((lat, lon))
            elif lat >= 26:  # Gangetic plain (widest part)
                for lon in range(68, 92):
                    land.add((lat, lon))
            elif lat >= 22:  # Central India / Gujarat
                for lon in range(68, 90):
                    land.add((lat, lon))
            elif lat >= 18:  # Maharashtra / Deccan plateau
                for lon in range(70, 88):
                    land.add((lat, lon))
            elif lat >= 14:  # Karnataka / Andhra (narrowing)
                for lon in range(72, 84):
                    land.add((lat, lon))
            elif lat >= 10:  # Tamil Nadu (narrower)
                for lon in range(75, 82):
                    land.add((lat, lon))
            elif lat >= 8:  # Southern tip of India
                for lon in range(76, 80):
                    land.add((lat, lon))
            else:  # Cape Comorin
                for lon in range(77, 79):
                    land.add((lat, lon))

        # Indochina Peninsula (Myanmar, Thailand, Vietnam, Cambodia, Laos)
        for lat in range(1, 28):
            if lat >= 22:  # Northern region (wide)
                for lon in range(92, 110):
                    land.add((lat, lon))
            elif lat >= 16:  # Central region
                for lon in range(93, 110):
                    land.add((lat, lon))
            elif lat >= 10:  # Southern region / Thailand
                for lon in range(97, 110):
                    land.add((lat, lon))
            elif lat >= 5:  # Malay Peninsula extending south
                for lon in range(99, 106):
                    land.add((lat, lon))
            else:  # Southern tip of Malaysia/Singapore
                for lon in range(100, 105):
                    land.add((lat, lon))

        # China (better coastal definition)
        for lat in range(18, 54):
            if lat >= 45:  # Northern China / Mongolia border
                for lon in range(75, 135):
                    land.add((lat, lon))
            elif lat >= 35:  # Central China
                for lon in range(75, 125):
                    land.add((lat, lon))
            elif lat >= 25:  # Southern China
                for lon in range(97, 122):
                    land.add((lat, lon))
            else:  # Hainan region
                for lon in range(105, 120):
                    land.add((lat, lon))

        # Korean Peninsula (better shape)
        for lat in range(33, 43):
            if lat >= 40:  # North Korea
                for lon in range(124, 131):
                    land.add((lat, lon))
            elif lat >= 37:  # Central Korea
                for lon in range(126, 130):
                    land.add((lat, lon))
            else:  # South Korea
                for lon in range(126, 130):
                    land.add((lat, lon))

        # Hainan Island
        for lat in range(18, 21):
            for lon in range(108, 111):
                land.add((lat, lon))

        # Africa - detailed continental shape with proper features
        for lat in range(-35, 38):
            if lat >= 35:  # Mediterranean coast (Morocco to Libya)
                west, east = -6, 25
            elif lat >= 32:  # North Africa with Egypt
                west, east = -8, 35
            elif lat >= 28:  # Sahara north
                west, east = -12, 35
            elif lat >= 22:  # Sahara / Sahel with Horn approach
                west, east = -17, 40
            elif lat >= 15:  # West Africa bulge + Horn of Africa
                west, east = -17, 52
            elif lat >= 10:  # West African bulge (max extent) + Ethiopia
                west, east = -17, 48
            elif lat >= 5:  # Gulf of Guinea coast + Somalia
                west, east = -8, 50
            elif lat >= 0:  # Equatorial (narrower west, wide east for Kenya)
                west, east = 8, 42
            elif lat >= -5:  # Congo basin / Tanzania
                west, east = 12, 40
            elif lat >= -10:  # Angola / Tanzania
                west, east = 12, 40
            elif lat >= -18:  # Zambia / Mozambique
                west, east = 12, 38
            elif lat >= -24:  # Botswana / Zimbabwe region
                west, east = 14, 36
            elif lat >= -30:  # South Africa proper
                west, east = 16, 32
            elif lat >= -33:  # Cape region
                west, east = 18, 30
            else:  # Cape of Good Hope
                west, east = 18, 28
            for lon in range(west, east + 1):
                land.add((lat, lon))

        # Horn of Africa detail (Somalia peninsula)
        for lat in range(0, 12):
            if lat >= 10:
                for lon in range(42, 52):
                    land.add((lat, lon))
            elif lat >= 5:
                for lon in range(45, 52):
                    land.add((lat, lon))
            else:
                for lon in range(47, 52):
                    land.add((lat, lon))

        # West Africa bulge detail (Senegal, Guinea)
        for lat in range(8, 16):
            for lon in range(-18, -12):
                land.add((lat, lon))

        # Madagascar (island off east coast)
        for lat in range(-26, -12):
            if lat >= -16:
                for lon in range(46, 51):
                    land.add((lat, lon))
            elif lat >= -22:
                for lon in range(44, 50):
                    land.add((lat, lon))
            else:
                for lon in range(44, 48):
                    land.add((lat, lon))

        # Additional islands and regions not covered by closed polygons
        # NOTE: Gaps between regions prevent continents from connecting
        islands = [
            (63, 66, -26, -16),   # Iceland (moved west, gap from Europe)
            (22, 26, 119, 122),   # Taiwan
            (20, 24, -85, -74),   # Cuba
            (18, 20, -75, -68),   # Hispaniola
            # Japan - main islands
            (30, 46, 129, 146),   # Honshu, Kyushu, Shikoku, Hokkaido
            # Indonesian archipelago - clear separation from Australia
            (-6, 6, 95, 106),     # Sumatra
            (-9, -6, 105, 115),   # Java (STOP at 115, well before Australia)
            (-5, 8, 108, 118),    # Borneo (Kalimantan)
            (-6, 2, 119, 126),    # Sulawesi (STOP at 126)
            # Philippines
            (5, 20, 117, 127),    # Philippine islands
            # Sri Lanka
            (6, 10, 79, 82),      # Sri Lanka
            # New Zealand (separate from Australia)
            (-47, -34, 166, 179), # New Zealand (both islands)
        ]
        for lat_min, lat_max, lon_min, lon_max in islands:
            for lat in range(lat_min, lat_max + 1):
                for lon in range(lon_min, lon_max + 1):
                    land.add((lat, lon))

        # Papua New Guinea - separate definition with clear gap from Australia
        for lat in range(-10, 0):
            if lat >= -5:
                for lon in range(130, 145):
                    land.add((lat, lon))
            else:
                for lon in range(135, 148):
                    land.add((lat, lon))

        # Australia - explicit definition with clear northern gap
        for lat in range(-44, -15):  # Start at -15, not -12, to ensure gap
            if lat >= -20:  # Northern Australia
                for lon in range(118, 152):  # Start at 118, gap from Indonesia
                    land.add((lat, lon))
            elif lat >= -30:  # Central Australia
                for lon in range(114, 154):
                    land.add((lat, lon))
            else:  # Southern Australia
                for lon in range(116, 152):
                    land.add((lat, lon))

        # Tasmania (separate island)
        for lat in range(-44, -40):
            for lon in range(144, 149):
                land.add((lat, lon))

        # Antarctica - MINIMAL display: only Antarctic Peninsula
        # The peninsula is the only recognizable feature at terminal resolution
        # Keep it small and well-separated from South America
        for lat in range(-68, -62):
            # Narrow peninsula pointing toward South America
            if lat >= -65:
                for lon in range(-62, -56):
                    land.add((lat, lon))
            else:
                for lon in range(-64, -54):
                    land.add((lat, lon))

        # =========================================
        # OCEAN EXCLUSION ZONES - Critical for preventing continent merging
        # These override any land definitions to ensure clear water gaps
        # Wide gaps ensure visibility at any terminal resolution
        # =========================================

        # Atlantic Ocean - WIDE gap to ensure Americas and Europe/Africa never connect
        # Extends from South America to Arctic
        for lat in range(-60, 80):
            # Wide Atlantic gap (lon -40 to -10)
            for lon in range(-40, -10):
                land.discard((lat, lon))

        # Preserve Iceland (lat 63-66, centered around lon -20)
        for lat in range(63, 67):
            for lon in range(-25, -13):
                land.add((lat, lon))

        # Davis Strait / Baffin Bay - separate Greenland from North America
        for lat in range(60, 80):
            for lon in range(-65, -50):
                land.discard((lat, lon))

        # Greenland - detailed island shape (completely separate from North America)
        for lat in range(59, 84):
            if lat >= 81:  # Northern tip (narrow)
                for lon in range(-38, -22):
                    land.add((lat, lon))
            elif lat >= 78:  # Northern Greenland
                for lon in range(-45, -18):
                    land.add((lat, lon))
            elif lat >= 75:  # North-Central (widening)
                for lon in range(-50, -18):
                    land.add((lat, lon))
            elif lat >= 70:  # Central Greenland (widest part)
                for lon in range(-52, -20):
                    land.add((lat, lon))
            elif lat >= 65:  # Central-South Greenland
                for lon in range(-50, -25):
                    land.add((lat, lon))
            elif lat >= 62:  # Southern Greenland (narrowing)
                for lon in range(-48, -38):
                    land.add((lat, lon))
            else:  # Cape Farewell (southern tip)
                for lon in range(-46, -42):
                    land.add((lat, lon))

        # Timor Sea / Arafura Sea - WIDE gap between Indonesia and Australia
        # This is the critical gap that prevents Asia from connecting to Australia
        for lat in range(-14, -6):
            for lon in range(115, 145):
                land.discard((lat, lon))

        # Re-add Timor and nearby Indonesian islands (small, above the gap)
        for lat in range(-10, -6):
            for lon in range(120, 130):
                land.add((lat, lon))

        # Torres Strait - between PNG and Australia (wider gap)
        for lat in range(-14, -10):
            for lon in range(138, 148):
                land.discard((lat, lon))

        # Bering Strait - between Alaska and Russia
        for lat in range(60, 70):
            for lon in range(-175, -163):
                land.discard((lat, lon))
            for lon in range(165, 178):
                land.discard((lat, lon))

        # Caspian Sea exclusion (more precise - don't exclude Tehran)
        # Caspian is roughly: lat 37-47, lon 47-54
        # Tehran is at lat 36, lon 51 - should NOT be excluded
        for lat in range(37, 48):
            for lon in range(48, 55):
                land.discard((lat, lon))

        # English Channel - narrow water between Britain and France
        for lat in range(49, 51):
            for lon in range(-1, 2):
                land.discard((lat, lon))

        # Irish Sea - water between Ireland and Britain (narrow)
        for lat in range(52, 55):
            for lon in range(-6, -4):
                land.discard((lat, lon))

        # North Sea (narrow strip between Britain and continental Europe)
        for lat in range(52, 58):
            for lon in range(2, 4):
                land.discard((lat, lon))

        # Skagerrak/Kattegat - between Denmark and Norway/Sweden
        for lat in range(56, 59):
            for lon in range(8, 11):
                land.discard((lat, lon))

        # Adriatic Sea exclusion (shifted east to not hit Rome)
        # Rome is at lat 42, lon 12 - should NOT be excluded
        # Adriatic is roughly: lat 39-46, lon 14-20
        for lat in range(39, 46):
            for lon in range(14, 20):
                land.discard((lat, lon))

        # Mediterranean Sea - key straits
        for lat in range(35, 38):
            for lon in range(-6, 0):  # Strait of Gibraltar area
                land.discard((lat, lon))

        # Sea of Japan - separate Japan islands from Korean peninsula/Russia
        for lat in range(34, 48):
            for lon in range(128, 135):
                land.discard((lat, lon))

        # Re-add Japan islands after Sea of Japan exclusion
        # Japan consists of: Hokkaido (north), Honshu (main), Shikoku, Kyushu (south)
        for lat in range(30, 46):
            if lat >= 42:  # Hokkaido
                for lon in range(139, 146):
                    land.add((lat, lon))
            elif lat >= 36:  # Northern/Central Honshu
                for lon in range(136, 142):
                    land.add((lat, lon))
            elif lat >= 34:  # Southern Honshu / Shikoku / Northern Kyushu (Fukuoka)
                for lon in range(129, 141):  # Extended west for Kyushu
                    land.add((lat, lon))
            elif lat >= 31:  # Kyushu (Kagoshima, etc.)
                for lon in range(129, 135):
                    land.add((lat, lon))
            else:  # Okinawa region
                for lon in range(127, 130):
                    land.add((lat, lon))

        # Yellow Sea / East China Sea - separate Korea from China
        # Yellow Sea: roughly lon 122-127 (don't include Chinese coast at 121)
        for lat in range(30, 40):
            for lon in range(122, 127):
                land.discard((lat, lon))

        # Re-add Korean Peninsula after Yellow Sea exclusion
        for lat in range(33, 43):
            if lat >= 38:  # North Korea
                for lon in range(124, 128):
                    land.add((lat, lon))
            else:  # South Korea
                for lon in range(126, 130):
                    land.add((lat, lon))

        # Re-add Taiwan
        for lat in range(22, 26):
            for lon in range(120, 123):
                land.add((lat, lon))

        # Re-add Chinese east coast (Shanghai, etc.)
        for lat in range(25, 35):
            for lon in range(120, 123):
                land.add((lat, lon))

        return land

    def _is_near_coastline(self, lat: float, lon: float, threshold: float) -> bool:
        """Check if point is near a coastline (land edge)."""
        for coastline in self.coastlines:
            for point in coastline.points:
                if abs(point.lat - lat) <= threshold and abs(point.lon - lon) <= threshold:
                    return True
        return False

    def get_country(self, name: str) -> Optional[Polygon]:
        """Get country boundary by name"""
        return self.countries.get(name)

    def get_all_countries(self) -> List[Polygon]:
        """Get all country polygons"""
        return list(self.countries.values())

    def get_coastlines(self) -> List[Polygon]:
        """Get major coastline polygons"""
        return self.coastlines

    def get_water_bodies(self) -> List[Polygon]:
        """Get internal water body polygons"""
        return self.water_bodies

    def is_land_at(self, lat: float, lon: float, resolution: int = 2) -> bool:
        """
        Check if a point is over land (not ocean).
        Uses precomputed land mask for accuracy and performance.

        Args:
            lat: Latitude
            lon: Longitude
            resolution: Grid resolution in degrees (for cache key rounding)

        Returns:
            True if point is over land
        """
        # Round to nearest integer for mask lookup
        grid_lat = round(lat)
        grid_lon = round(lon)

        return (grid_lat, grid_lon) in self._land_mask

    def get_terrain_char(self, lat: float, lon: float) -> Tuple[str, str]:
        """
        Get appropriate character and style for terrain at location.

        Returns:
            Tuple of (character, style) for the terrain
        """
        if self.is_land_at(lat, lon):
            # Check if near coastline for variation
            for coastline in self.coastlines:
                for point in coastline.points:
                    if abs(point.lat - lat) < 3 and abs(point.lon - lon) < 3:
                        return ('\u2591', 'green')  # Light land near coast
            return ('\u2592', 'dim green')  # Interior land
        else:
            return ('\u2591', 'dim blue')  # Ocean

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
