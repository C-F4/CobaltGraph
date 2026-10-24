"""Tests for the shared alert threshold accessor."""

import pytest

from src.analytics.alert_engine import AlertEngine
from src.utils import thresholds


@pytest.fixture(autouse=True)
def _restore_threshold():
    original = thresholds.get_alert_threshold()
    yield
    thresholds.set_alert_threshold(original)


@pytest.mark.unit
def test_default_threshold_is_point_seven():
    thresholds.set_alert_threshold(thresholds.DEFAULT_ALERT_THRESHOLD)
    assert thresholds.get_alert_threshold() == pytest.approx(0.7)


@pytest.mark.unit
def test_set_threshold_is_visible_to_readers():
    thresholds.set_alert_threshold(0.5)
    assert thresholds.get_alert_threshold() == pytest.approx(0.5)


@pytest.mark.unit
@pytest.mark.parametrize("bad", [-0.1, 1.1, "high", None])
def test_rejects_invalid_values(bad):
    with pytest.raises((ValueError, TypeError)):
        thresholds.set_alert_threshold(bad)


@pytest.mark.unit
def test_alert_engine_critical_threshold_follows_setting():
    thresholds.set_alert_threshold(0.55)
    engine = AlertEngine()
    assert engine.CRITICAL_THRESHOLD == pytest.approx(0.55)
