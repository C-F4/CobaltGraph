"""
Shared alert/malicious threshold accessor.

A single process-wide value, set once from ``alert_threshold`` in the config
(see ``DataPipeline.__init__``). Decision sites read it through
``get_alert_threshold()`` instead of hardcoding 0.7.
"""

import threading

DEFAULT_ALERT_THRESHOLD = 0.7

_lock = threading.Lock()
_alert_threshold = DEFAULT_ALERT_THRESHOLD


def get_alert_threshold() -> float:
    """Return the current alert threshold (0.0-1.0)."""
    with _lock:
        return _alert_threshold


def set_alert_threshold(value) -> float:
    """
    Set the alert threshold. Raises ValueError outside 0.0-1.0.

    Returns the stored value.
    """
    global _alert_threshold
    value = float(value)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"alert threshold must be between 0.0 and 1.0, got {value}")
    with _lock:
        _alert_threshold = value
    return value
