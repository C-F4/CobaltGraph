"""Periodic re-emits of a live socket must not feed the inter-arrival (beaconing) heuristic."""

import pytest

from src.consensus.statistical_scorer import StatisticalScorer


@pytest.mark.unit
def test_refresh_does_not_record_timing():
    scorer = StatisticalScorer()
    scorer._update_baseline("198.51.100.1", None, None, 1000.0, record_timing=False)
    baseline = scorer._get_or_create_baseline("198.51.100.1")
    assert baseline.total_connections == 1
    assert len(baseline.recent_timestamps) == 0


@pytest.mark.unit
def test_new_flow_records_timing():
    scorer = StatisticalScorer()
    scorer._update_baseline("198.51.100.2", None, None, 1000.0, record_timing=True)
    baseline = scorer._get_or_create_baseline("198.51.100.2")
    assert list(baseline.recent_timestamps) == [1000.0]
