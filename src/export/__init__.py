"""
CobaltGraph Export Module
Lightweight export system for consensus assessments

Features:
- JSON Lines (detailed, machine-readable)
- CSV (summary, human-readable)
- Automatic rotation
- Minimal memory footprint
"""

from .consensus_exporter import ConsensusExporter

__all__ = ['ConsensusExporter']
