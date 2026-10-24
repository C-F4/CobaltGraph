#!/usr/bin/env python3
"""
Seed a database with synthetic connections and detections for visual checks and tests.

Refuses to write to the live application database (database/cobaltgraph.db) or to any
existing file, so it cannot pollute real capture data.

Usage:
    python3 tools/seed_demo_db.py /tmp/cobalt_demo.db
"""

import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.storage.database import Database  # noqa: E402

LIVE_DB = (PROJECT_ROOT / "database" / "cobaltgraph.db").resolve()


def seed(path: str) -> None:
    target = Path(path).resolve()
    if target == LIVE_DB:
        sys.exit("refusing to seed the live database")
    if target.exists():
        sys.exit(f"refusing to overwrite existing file: {target}")

    db = Database(str(target))
    now = time.time()

    # Regular-interval destination: one new flow every 30 s for the last 40 minutes
    for i in range(80):
        db.add_connection_immediate({
            "timestamp": now - 2400 + i * 30.0,
            "src_ip": "192.168.1.20", "dst_ip": "203.0.113.77", "dst_port": 8443,
            "protocol": "TCP", "dst_org": "Example Hosting", "dst_org_type": "hosting",
            "dst_country": "NL", "threat_score": 0.74, "confidence": 0.8,
            "score_statistical": 0.7, "score_rule_based": 0.8, "score_heuristic": 0.6,
            "score_organization": 0.7, "score_spread": 0.2,
            "beaconing_detected": True, "beaconing_interval": 30.0, "beaconing_jitter": 3.0,
            "dga_detected": False, "tls_sni": "update.example-hosting.test",
        })

    # DGA-like name, high score
    db.add_connection_immediate({
        "timestamp": now - 300, "src_ip": "192.168.1.31", "dst_ip": "198.51.100.23",
        "dst_port": 443, "protocol": "TCP", "dst_org": "Unknown VPS", "dst_org_type": "vpn",
        "threat_score": 0.91, "confidence": 0.7, "high_uncertainty": True,
        "score_statistical": 0.9, "score_rule_based": 0.95, "score_heuristic": 0.8,
        "score_organization": 0.9, "score_spread": 0.45, "dga_detected": True,
        "dns_query": "x7k2qz9lm4.example.test", "domain_asn_mismatch": True,
    })

    # Ordinary low-risk traffic
    for n in range(20):
        db.add_connection_immediate({
            "timestamp": now - 60 * n, "src_ip": "192.168.1.20",
            "dst_ip": f"151.101.{n}.1", "dst_port": 443, "protocol": "TCP",
            "dst_org": "CDN Edge", "dst_org_type": "cdn", "dst_country": "US",
            "threat_score": 0.12, "confidence": 0.9,
        })

    db.flush()

    db.add_event("beaconing", "Regular-interval traffic to 203.0.113.77:8443 (interval 30.0s, jitter 3%)",
                 "HIGH", src_ip="192.168.1.20", dst_ip="203.0.113.77", dst_port=8443,
                 threat_score=0.74, org_name="Example Hosting")
    db.add_event("high_threat", "High threat: 203.0.113.77:8443 (Example Hosting)", "HIGH",
                 src_ip="192.168.1.20", dst_ip="203.0.113.77", dst_port=8443,
                 threat_score=0.74, org_name="Example Hosting")
    db.add_event("dga_like", "DGA-like domain 'x7k2qz9lm4.example.test' for 198.51.100.23:443",
                 "HIGH", src_ip="192.168.1.31", dst_ip="198.51.100.23", dst_port=443,
                 threat_score=0.91, org_name="Unknown VPS")
    db.add_event("high_threat", "High threat: 198.51.100.23:443 (Unknown VPS)", "CRITICAL",
                 src_ip="192.168.1.31", dst_ip="198.51.100.23", dst_port=443,
                 threat_score=0.91, org_name="Unknown VPS")
    db.add_event("consensus_uncertain", "Uncertain consensus: 198.51.100.23:443 (spread too high)",
                 "MEDIUM", src_ip="192.168.1.31", dst_ip="198.51.100.23", dst_port=443,
                 threat_score=0.91)

    db.close()
    os.chmod(target, 0o644)
    print(f"seeded {target} (80 beacon flows, 1 DGA-like flow, 20 benign, 5 events)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    seed(sys.argv[1])
