"""
End-to-end recording path for DataPipeline._process_connection.

Network enrichment and the consensus scorer are stubbed; the database, the beaconing
tap, dedup, detection cooldown and persistence are real.
"""

import time

import pytest

from src.analytics.beaconing_detector import BeaconingDetector
from src.core.orchestrator import DataPipeline
from src.storage.database import Database


class FakeScorer:
    """Stands in for ConsensusThreatScorer: fixed score and details."""

    def __init__(self, score):
        self.score = score

    def check_ip(self, dst_ip, threat_intel=None, geo_data=None, connection_metadata=None):
        details = {
            "confidence": 0.9,
            "high_uncertainty": False,
            "score_statistical": 0.5,
            "score_rule_based": 0.6,
            "score_heuristic": 0.4,
            "score_neural_net": None,
            "score_organization": 0.3,
            "score_spread": 0.1,
            "dga_detected": False,
            "domain_asn_mismatch": False,
            "dst_org": "Example Cloud",
            "dst_org_type": "cloud",
        }
        return self.score, details

    def enrich_with_asn(self, dst_ip, ttl=0):
        return {}


@pytest.fixture
def pipeline(tmp_path):
    db_path = str(tmp_path / "pipeline.db")
    p = DataPipeline({"database_path": db_path, "alert_threshold": 0.7})
    p.database = Database(db_path)
    p.beaconing_detector = BeaconingDetector(min_connections=5, max_jitter=20.0)
    p.consensus_scorer = FakeScorer(0.9)
    p._enrich_geo = lambda dst_ip: {"country": "US"}
    p._enrich_threat_intel = lambda dst_ip: {"threat_score": 0.9}
    yield p
    p.database.close()
    p.beaconing_detector.shutdown()


def _raw(dst_ip, dst_port, timestamp, new_flow=True):
    return {
        "type": "connection",
        "timestamp": timestamp,
        "src_ip": "192.168.1.5",
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": "TCP",
        "new_flow": new_flow,
    }


@pytest.mark.integration
def test_dedup_suppresses_scoring_but_timing_tap_still_records(pipeline):
    now = time.time()
    first = pipeline._process_connection(_raw("203.0.113.30", 443, now))
    repeat = pipeline._process_connection(_raw("203.0.113.30", 443, now + 2))

    assert first is not None
    assert repeat is None  # deduplicated within the 60 s window
    result = pipeline.beaconing_detector._connections["203.0.113.30"]
    assert len(result) == 2  # both sightings recorded for timing


@pytest.mark.integration
def test_periodic_destination_is_flagged_and_persisted(pipeline, monkeypatch):
    monkeypatch.setattr(pipeline, "_is_duplicate", lambda dst_ip, dst_port: False)
    base = time.time() - 400
    event = None
    for i in range(8):
        event = pipeline._process_connection(_raw("203.0.113.40", 443, base + i * 30.0))

    assert event is not None
    assert event.beaconing_detected is True
    assert event.beaconing_interval == pytest.approx(30.0, rel=0.05)
    assert event.to_dict()["beaconing_detected"] is True

    pipeline.database.flush()
    rows = pipeline.database.conn.execute(
        "SELECT beaconing_detected, score_heuristic, dga_detected FROM connections "
        "WHERE dst_ip = ? ORDER BY id DESC LIMIT 1",
        ("203.0.113.40",),
    ).fetchone()
    assert rows[0] == 1
    assert rows[1] == pytest.approx(0.4)
    assert rows[2] == 0


@pytest.mark.integration
def test_detection_rows_are_cooled_down(pipeline, monkeypatch):
    monkeypatch.setattr(pipeline, "_is_duplicate", lambda dst_ip, dst_port: False)
    base = time.time() - 400
    for i in range(10):
        pipeline._process_connection(_raw("203.0.113.50", 443, base + i * 30.0))

    beacon_rows = pipeline.database.conn.execute(
        "SELECT COUNT(*) FROM events WHERE event_type = 'beaconing' AND dst_ip = ?",
        ("203.0.113.50",),
    ).fetchone()[0]
    assert beacon_rows == 1
    high_rows = pipeline.database.conn.execute(
        "SELECT COUNT(*) FROM events WHERE event_type = 'high_threat' AND dst_ip = ?",
        ("203.0.113.50",),
    ).fetchone()[0]
    assert high_rows == 1


@pytest.mark.integration
def test_infrastructure_asn_is_not_flagged_as_beaconing(pipeline, monkeypatch):
    """Scheduled infrastructure (DNS/NTP/CA ASNs) must not be flagged regular-interval."""
    monkeypatch.setattr(pipeline, "_is_duplicate", lambda dst_ip, dst_port: False)
    original = pipeline.consensus_scorer.check_ip

    def infra_check_ip(dst_ip, threat_intel=None, geo_data=None, connection_metadata=None):
        score, details = original(dst_ip, threat_intel, geo_data, connection_metadata)
        details["asn_reputation"] = "infrastructure"
        return score, details

    pipeline.consensus_scorer.check_ip = infra_check_ip
    base = time.time() - 400
    event = None
    for i in range(8):
        event = pipeline._process_connection(_raw("192.0.2.4", 53, base + i * 30.0))
    assert event is not None
    assert event.beaconing_detected is False
