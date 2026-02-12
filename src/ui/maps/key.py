"""
Map Key/Legend Module
=====================

Provides consistent threat level, verification status, and heatmap legends
for all map visualizations. Includes both compact (inline) and detailed
(panel) rendering modes.
"""

from typing import List, Tuple, Optional

from rich.text import Text
from textual.widgets import Static

from .utils import THREAT_LEVELS, HEATMAP_GRADIENT, ORG_TYPE_COLORS


# Verification status indicators
VERIFICATION_LEVELS = [
    ("✓", "Verified", "bold green", "verified"),
    ("!", "Flagged", "bold yellow", "flagged"),
    ("?", "Pending", "dim", "pending"),
    ("✗", "Unknown", "bold red", "unknown"),
]

# Triangulation source indicators
TRIANGULATION_LEVELS = [
    ("4", "All sources agree", "bold green", 4),
    ("3", "Good agreement", "cyan", 3),
    ("2", "Partial agreement", "yellow", 2),
    ("1", "Single source", "dim", 1),
]


def get_verification_char(status: str) -> str:
    """Get character for verification status."""
    for char, _, _, stat in VERIFICATION_LEVELS:
        if status == stat:
            return char
    return "?"


def get_verification_color(status: str) -> str:
    """Get color for verification status."""
    for _, _, color, stat in VERIFICATION_LEVELS:
        if status == stat:
            return color
    return "dim"


def get_triangulation_char(sources: int) -> str:
    """Get character for triangulation source count."""
    for char, _, _, count in TRIANGULATION_LEVELS:
        if sources >= count:
            return char
    return "1"


def get_triangulation_color(sources: int) -> str:
    """Get color for triangulation source count."""
    for _, _, color, count in TRIANGULATION_LEVELS:
        if sources >= count:
            return color
    return "dim"


def render_compact_key(include_verification: bool = False) -> Text:
    """
    Render a single-line compact key.

    Args:
        include_verification: Include verification and triangulation indicators

    Returns:
        Rich Text object with formatted key
    """
    key = Text()
    key.append("Threat:", style="dim bold")

    for char, name, color, _ in THREAT_LEVELS:
        key.append(f" {char}", style=color)
        key.append(name[:4], style="dim")

    if include_verification:
        key.append(" │ ", style="dim")
        key.append("V:", style="dim bold")
        key.append(" ✓", style="bold green")
        key.append("=OK", style="dim")
        key.append(" !", style="bold yellow")
        key.append("=Flag", style="dim")
        key.append(" │ ", style="dim")
        key.append("T:", style="dim bold")
        key.append(" 4", style="bold green")
        key.append("=All", style="dim")
        key.append(" 3", style="cyan")
        key.append("=Good", style="dim")

    return key


def render_detailed_key(include_verification: bool = True) -> Text:
    """
    Render a multi-line detailed key.

    Args:
        include_verification: Include verification and triangulation sections

    Returns:
        Rich Text object with formatted key
    """
    key = Text()

    # Threat levels
    key.append("THREAT LEVELS\n", style="dim bold")
    for char, name, color, threshold in THREAT_LEVELS:
        key.append(f"  {char} ", style=color)
        key.append(f"{name:<8}", style=color)
        key.append(f" (>={threshold:.1f})\n", style="dim")

    if include_verification:
        # Verification status
        key.append("\nVERIFICATION STATUS\n", style="dim bold")
        for char, name, color, _ in VERIFICATION_LEVELS:
            key.append(f"  {char} ", style=color)
            key.append(f"{name}\n", style=color)

        # Triangulation
        key.append("\nTRIANGULATION (sources)\n", style="dim bold")
        for char, name, color, count in TRIANGULATION_LEVELS:
            key.append(f"  {char} ", style=color)
            key.append(f"{name}\n", style=color)

    # Heatmap
    key.append("\nHEATMAP INTENSITY: ", style="dim bold")
    for char, color in HEATMAP_GRADIENT:
        key.append(char, style=color)
    key.append(" (High → Low)", style="dim")

    return key


def render_key_box(width: int = 18, include_verification: bool = False) -> List[Tuple[str, Optional[str]]]:
    """
    Render key content for embedding in map canvas.

    Args:
        width: Box width (characters)
        include_verification: Include verification indicators

    Returns:
        List of (text, style) tuples for each line
    """
    lines = [
        ("─── KEY ───", "dim bold"),
        ("TERRAIN", "dim bold cyan"),
        ("░ Land  ∙ Ocean", "green"),
        ("▪ Coast • Water", "bold green"),
        ("", None),
        ("CONNECTION PING", "dim bold"),
        ("● Crit", "bold red"),
        ("◉ High", "bold yellow"),
        ("◯ Med  ○ Low", "yellow"),
        ("· Info", "green"),
    ]

    if include_verification:
        lines.extend([
            ("", None),
            ("VERIFY", "dim bold"),
            ("✓ OK  ! Flag", "bold green"),
        ])

    lines.extend([
        ("", None),
        ("HEATMAP DENSITY", "dim bold"),
        ("█▓▒░ Hi→Lo", "bold yellow"),
    ])

    return lines


def render_org_type_key() -> Text:
    """
    Render organization type color key.

    Returns:
        Rich Text with org type legend
    """
    key = Text()
    key.append("ORG TYPES\n", style="dim bold")

    for org_type, color in ORG_TYPE_COLORS.items():
        key.append(f"  ● ", style=color)
        key.append(f"{org_type.capitalize()}\n", style="dim")

    return key


class MapKeyWidget(Static):
    """
    Compact key/legend widget for map panels.

    Can be docked at the bottom of map panels for quick reference.

    Attributes:
        compact: Use single-line compact mode
        include_verification: Show verification indicators
    """

    DEFAULT_CSS = """
    MapKeyWidget {
        height: auto;
        width: 100%;
        background: $surface;
        color: $text;
        padding: 0 1;
    }
    """

    def __init__(
        self,
        compact: bool = True,
        include_verification: bool = False,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.compact = compact
        self.include_verification = include_verification

    def render(self) -> Text:
        """Render the map key."""
        if self.compact:
            return render_compact_key(self.include_verification)
        return render_detailed_key(self.include_verification)
