"""Tests for flow identity (src_port, new_flow) in device mode."""

from types import SimpleNamespace

import pytest

from src.capture import device_monitor
from src.capture.device_monitor import DeviceMonitor


@pytest.mark.unit
def test_ss_line_keeps_source_port():
    monitor = DeviceMonitor()
    parsed = monitor._parse_ss_line("tcp ESTAB 0 0 192.168.1.10:52234 203.0.113.46:443")
    assert parsed is not None
    assert parsed["src_ip"] == "192.168.1.10"
    assert parsed["src_port"] == 52234
    assert parsed["dst_ip"] == "203.0.113.46"
    assert parsed["dst_port"] == 443


@pytest.mark.unit
def test_refresh_of_live_socket_is_not_a_new_flow(monkeypatch):
    """First sighting is a new flow; the 60 s re-emit of the same 4-tuple is not."""
    clock = {"t": 1000.0, "sleeps": 0}

    def fake_sleep(_seconds):
        clock["t"] += 35.0
        clock["sleeps"] += 1
        if clock["sleeps"] >= 3:
            monitor._running = False

    monkeypatch.setattr(device_monitor, "time", SimpleNamespace(
        time=lambda: clock["t"], sleep=fake_sleep,
    ))

    monitor = DeviceMonitor({"poll_interval": 35.0})
    monitor._running = True
    monitor.get_connections = lambda: [{
        "src_ip": "192.168.1.10", "src_port": 52234,
        "dst_ip": "203.0.113.46", "dst_port": 443,
    }]

    emitted = []
    monitor.set_callback(lambda conn: emitted.append(dict(conn)))
    monitor._monitor_loop()

    # Polls at t=0, 35, 70: emitted at 0 (new) and 70 (60 s refresh), not at 35
    assert len(emitted) == 2
    assert emitted[0]["new_flow"] is True
    assert emitted[1]["new_flow"] is False


@pytest.mark.unit
@pytest.mark.parametrize("line, expected", [
    # macOS netstat: ip.port, Recv-Q/Send-Q columns present
    ("tcp4 0 0 192.168.1.5.52234 203.0.113.46.443 ESTABLISHED", ("203.0.113.46", 443, "192.168.1.5", 52234)),
    # Windows netstat: ip:port, no queue columns
    ("  TCP    192.168.1.5:52234      203.0.113.46:443      ESTABLISHED", ("203.0.113.46", 443, "192.168.1.5", 52234)),
])
def test_netstat_parses_macos_and_windows_layouts(line, expected):
    parsed = DeviceMonitor()._parse_netstat_line(line)
    assert parsed is not None
    assert (parsed["dst_ip"], parsed["dst_port"], parsed["src_ip"], parsed["src_port"]) == expected


@pytest.mark.unit
@pytest.mark.parametrize("line", [
    "tcp4 0 0 192.168.1.5.52234 192.168.1.1.443 ESTABLISHED",  # private destination
    "tcp4 0 0 *.22 *.* LISTEN",                                  # not established
    "garbage line",
])
def test_netstat_rejects_non_outbound_lines(line):
    assert DeviceMonitor()._parse_netstat_line(line) is None
