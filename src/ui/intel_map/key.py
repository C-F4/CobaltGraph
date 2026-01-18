"""
Intel Map Key/Legend Components
Provides consistent threat level and heatmap legends across all map visualizations.
"""

from typing import List, Tuple, Optional
from rich.text import Text
from textual.widgets import Static


# Threat level definitions - shared across all map types
THREAT_LEVELS = [
    ("●", "Critical", "bold red", 0.8),
    ("◉", "High", "bold yellow", 0.6),
    ("◯", "Medium", "yellow", 0.4),
    ("○", "Low", "cyan", 0.2),
    ("·", "Info", "green", 0.0),
]

# Heatmap intensity levels
HEATMAP_LEVELS = [
    ("█", "bold red"),
    ("▇", "bold red"),
    ("▆", "bold yellow"),
    ("▅", "yellow"),
    ("▄", "yellow"),
    ("▃", "cyan"),
    ("▂", "cyan"),
    ("▁", "green"),
]

# Organization type colors
ORG_TYPE_COLORS = {
    'cloud': 'cyan',
    'cdn': 'cyan',
    'hosting': 'blue',
    'isp': 'magenta',
    'vpn': 'bold magenta',
    'tor': 'bold red',
    'enterprise': 'bold green',
    'government': 'bold blue',
    'education': 'green',
    'unknown': 'dim white',
}


def get_threat_char(score: float) -> str:
    """Get character for threat intensity"""
    for char, _, _, threshold in THREAT_LEVELS:
        if score >= threshold:
            return char
    return "·"


def get_threat_color(score: float) -> str:
    """Get color for threat score"""
    for _, _, color, threshold in THREAT_LEVELS:
        if score >= threshold:
            return color
    return "green"


def render_map_key(compact: bool = True) -> Text:
    """
    Render a map key/legend as Rich Text.

    Args:
        compact: If True, render single-line compact key.
                 If False, render multi-line detailed key.

    Returns:
        Rich Text object with formatted key
    """
    key = Text()

    if compact:
        # Single-line compact key
        key.append("Key:", style="dim bold")
        for char, name, color, _ in THREAT_LEVELS:
            key.append(f" {char}", style=color)
            key.append(name[:4], style="dim")
    else:
        # Multi-line detailed key
        key.append("Threat Levels:\n", style="dim bold")
        for char, name, color, threshold in THREAT_LEVELS:
            key.append(f"  {char} ", style=color)
            key.append(f"{name:<8}", style=color)
            key.append(f" (>={threshold:.1f})\n", style="dim")

        key.append("\nHeatmap: ", style="dim bold")
        for char, color in HEATMAP_LEVELS[:4]:
            key.append(char, style=color)
        key.append(" = Intensity", style="dim")

    return key


def render_key_box(width: int = 18, height: int = 10) -> List[Tuple[str, Optional[str]]]:
    """
    Render key box content for embedding in canvas.

    Returns:
        List of (text, style) tuples for each line
    """
    lines = [
        ("Threat Level:", None),
        ("●=Crit  ◉=High", "bold red"),
        ("◯=Med  ○=Low", "yellow"),
        ("·=Info", "green"),
        ("", None),
        ("Heatmap:", None),
        ("█▇▆▅▄▃▂▁", "bold yellow"),
        ("High → Low", "dim"),
    ]
    return lines


class IntelMapKey(Static):
    """
    Compact key/legend widget for intel map visualization.
    Can be docked at the bottom of map panels.
    """

    DEFAULT_CSS = """
    IntelMapKey {
        dock: bottom;
        height: auto;
        max-height: 3;
        padding: 0 1;
        background: $surface;
    }
    """

    def __init__(self, compact: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.compact = compact

    def render(self) -> Text:
        """Render the map key"""
        return render_map_key(compact=self.compact)
