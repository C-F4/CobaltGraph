"""Tests for regular-interval (beaconing) detection."""

import random
import threading
import time

import pytest

from src.analytics.beaconing_detector import BeaconingDetector


@pytest.fixture
def detector():
    det = BeaconingDetector(min_connections=5, max_jitter=20.0)
    yield det
    det.shutdown()


@pytest.mark.unit
def test_regular_interval_is_flagged(detector):
    start = time.time() - 600
    for i in range(12):
        detector.record_connection("203.0.113.9", start + i * 30.0, dst_port=443)

    data = detector.get_beacon_data("203.0.113.9")

    assert data is not None
    assert data["is_beaconing"] is True
    assert data["interval_seconds"] == pytest.approx(30.0, rel=0.05)


@pytest.mark.unit
def test_irregular_intervals_are_not_flagged(detector):
    rng = random.Random(7)
    start = time.time() - 3000
    t = start
    for _ in range(15):
        t += rng.uniform(5, 300)
        detector.record_connection("198.51.100.4", t, dst_port=80)

    assert detector.get_beacon_data("198.51.100.4") is None


@pytest.mark.unit
def test_below_minimum_connections_not_analysed(detector):
    start = time.time() - 120
    for i in range(3):
        detector.record_connection("192.0.2.7", start + i * 30.0)

    assert detector.get_beacon_data("192.0.2.7") is None


@pytest.mark.unit
def test_tracked_ips_are_bounded(monkeypatch):
    monkeypatch.setattr(BeaconingDetector, "MAX_TRACKED_IPS", 3)
    det = BeaconingDetector(min_connections=5)
    for n in range(5):
        det.record_connection(f"203.0.113.{n + 1}")
    assert len(det._connections) <= 3


@pytest.mark.unit
def test_concurrent_record_and_analyze_do_not_fail(detector):
    errors = []

    def writer(offset):
        try:
            for i in range(200):
                detector.record_connection(f"203.0.113.{offset}", time.time() - (200 - i) * 10)
        except Exception as e:  # pragma: no cover - failure path
            errors.append(e)

    def reader():
        try:
            for _ in range(200):
                detector.analyze("203.0.113.1", use_cache=False)
        except Exception as e:  # pragma: no cover - failure path
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(n,)) for n in (1, 2)]
    threads.append(threading.Thread(target=reader))
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors
