"""
Shared SOC display conventions: severity order, colours, detection badges, flags.

Decisions about severity and colour live here so the detection queue, connection
table, threat posture panel, drill-down and detections log stay consistent.
"""

from typing import Dict, List, Optional

from src.utils.thresholds import get_alert_threshold

# severity -> (rich style, glyph, rank). Higher rank = more urgent.
SEVERITY_STYLE: Dict[str, tuple] = {
    "CRITICAL": ("bold red", "●", 4),
    "HIGH": ("bold yellow", "▲", 3),
    "MEDIUM": ("yellow", "■", 2),
    "LOW": ("cyan", "○", 1),
    "INFO": ("dim", "·", 0),
}
SEVERITY_ORDER: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# recorded event type -> (short badge, rich style)
DETECTION_BADGES: Dict[str, tuple] = {
    "beaconing": ("BCN", "bold yellow"),
    "dga_like": ("DGA", "bold magenta"),
    "consensus_uncertain": ("UNC", "yellow"),
    "high_threat": ("THR", "bold red"),
    "anomaly": ("ANM", "bold cyan"),
}

# One name per detection type, used by the log column, the filter and the legend
TYPE_LABELS: Dict[str, str] = {
    "beaconing": "beacon",
    "dga_like": "dga-like",
    "consensus_uncertain": "uncertain",
    "high_threat": "high-threat",
    "anomaly": "anomaly",
}

BADGE_LEGEND = "  ".join(f"{badge} {TYPE_LABELS[etype]}" for etype, (badge, _) in DETECTION_BADGES.items())

# per-connection flags shown in the connection table
FLAG_GLYPHS = {"beaconing": "B", "dga": "D", "scan": "S", "asn_mismatch": "M"}


def severity_rank(severity: Optional[str]) -> int:
    """Urgency rank for a severity label (unknown -> 0)."""
    return SEVERITY_STYLE.get((severity or "").upper(), ("", "", 0))[2]


def severity_style(severity: Optional[str]) -> str:
    """Rich style for a severity label."""
    return SEVERITY_STYLE.get((severity or "").upper(), ("dim", "", 0))[0]


def threat_style(score: float) -> str:
    """Rich style for a 0-1 threat score. The 'high' cut-point follows the alert threshold."""
    high = get_alert_threshold()
    if score >= 0.8:
        return "bold red"
    if score >= high:
        return "bold yellow"
    if score >= 0.5:
        return "yellow"
    if score >= 0.3:
        return "cyan"
    return "green"


def connection_flags(conn: Dict) -> str:
    """Compact flag string for one connection row, e.g. 'BD'. Empty when nothing is flagged."""
    flags = ""
    if conn.get("beaconing_detected"):
        flags += FLAG_GLYPHS["beaconing"]
    if conn.get("dga_detected"):
        flags += FLAG_GLYPHS["dga"]
    if conn.get("tcp_is_scan"):
        flags += FLAG_GLYPHS["scan"]
    if conn.get("domain_asn_mismatch"):
        flags += FLAG_GLYPHS["asn_mismatch"]
    return flags
