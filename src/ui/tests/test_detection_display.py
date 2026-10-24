"""
Display layer for recorded detections: theme rules, queries, queue rendering,
export, and headless runs of the detections log and the dashboard.
"""

import asyncio
import csv
import json
import time
from io import StringIO

import pytest
from rich.console import Console

from src.export.events_export import EXPORT_FIELDS, export_events
from src.storage.database import Database
from src.ui import theme
from src.ui.dashboard_enhanced import DetectionQueuePanel
from src.ui.unified_dashboard import DataManager
from src.utils import thresholds


@pytest.fixture
def populated_db(tmp_path):
    """A database with a mix of recorded detections across destinations."""
    path = str(tmp_path / "display.db")
    db = Database(path)
    now = time.time()
    db.add_event("high_threat", "High threat: 203.0.113.1", "CRITICAL",
                 src_ip="10.0.0.2", dst_ip="203.0.113.1", dst_port=443,
                 threat_score=0.95, org_name="Alpha")
    db.add_event("beaconing", "Regular-interval traffic", "MEDIUM",
                 src_ip="10.0.0.2", dst_ip="203.0.113.2", dst_port=8443,
                 threat_score=0.5, org_name="Beta")
    db.add_event("dga_like", "DGA-like domain", "HIGH",
                 src_ip="10.0.0.3", dst_ip="203.0.113.2", dst_port=8443,
                 threat_score=0.6, org_name="Beta")
    db.add_event("consensus_uncertain", "Uncertain consensus", "MEDIUM",
                 src_ip="10.0.0.4", dst_ip="203.0.113.3", dst_port=80,
                 threat_score=0.4, org_name="Gamma")
    db.add_connection_immediate({
        "timestamp": now, "src_ip": "10.0.0.2", "dst_ip": "203.0.113.2",
        "dst_port": 8443, "protocol": "TCP", "threat_score": 0.5,
    })
    db.flush()
    db.close()
    return path


@pytest.fixture
def data_manager(populated_db):
    dm = DataManager(populated_db)
    assert dm.connect()
    yield dm
    dm.db_conn.close()


# ----------------------------------------------------------------- theme

@pytest.mark.unit
def test_connection_flags_reflect_each_signal():
    assert theme.connection_flags({}) == ""
    assert theme.connection_flags({"beaconing_detected": 1, "dga_detected": 1,
                                   "tcp_is_scan": 1, "domain_asn_mismatch": 1}) == "BDSM"


@pytest.mark.unit
def test_threat_style_high_cut_follows_alert_threshold():
    original = thresholds.get_alert_threshold()
    try:
        thresholds.set_alert_threshold(0.6)
        assert theme.threat_style(0.65) == "bold yellow"
        assert theme.threat_style(0.55) == "yellow"
    finally:
        thresholds.set_alert_threshold(original)


@pytest.mark.unit
def test_severity_rank_orders_urgency():
    ranks = [theme.severity_rank(s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
    assert ranks == sorted(ranks, reverse=True)
    assert theme.severity_rank(None) == 0


# ----------------------------------------------------------------- queries

@pytest.mark.unit
def test_detection_queue_is_grouped_and_most_urgent_first(data_manager):
    queue = data_manager.get_detection_queue()

    assert [row["dst_ip"] for row in queue] == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    assert queue[0]["severity"] == "CRITICAL"
    beta = next(row for row in queue if row["dst_ip"] == "203.0.113.2")
    assert beta["count"] == 2
    assert set(beta["types"]) == {"beaconing", "dga_like"}
    assert beta["severity"] == "HIGH"


@pytest.mark.unit
def test_detection_counts_are_distinct_destinations(data_manager):
    counts = data_manager.get_detection_counts(window_s=3600)
    assert counts["beaconing"] == 1
    assert counts["dga_like"] == 1
    assert counts["high_threat"] == 1


@pytest.mark.unit
def test_query_events_filters_by_severity_and_type(data_manager):
    high_plus = data_manager.query_events(min_severity="HIGH")
    assert {row["event_type"] for row in high_plus} == {"high_threat", "dga_like"}

    beacons = data_manager.query_events(event_type="beaconing")
    assert len(beacons) == 1 and beacons[0]["dst_ip"] == "203.0.113.2"

    by_ip = data_manager.query_events(ip="203.0.113.3")
    assert len(by_ip) == 1 and by_ip[0]["event_type"] == "consensus_uncertain"


@pytest.mark.unit
def test_latest_connection_for_drill_down(data_manager):
    conn = data_manager.get_latest_connection("203.0.113.2")
    assert conn is not None and conn["dst_port"] == 8443
    assert data_manager.get_latest_connection("192.0.2.200") is None


# ----------------------------------------------------------------- rendering

def _render_text(renderable) -> str:
    console = Console(record=True, width=140, file=StringIO())
    console.print(renderable)
    return console.export_text()


@pytest.mark.unit
def test_queue_panel_empty_state_has_no_fabricated_rows():
    panel = DetectionQueuePanel()
    text = _render_text(panel.render())
    assert "No detections recorded" in text
    assert "203." not in text


@pytest.mark.unit
def test_queue_panel_renders_recorded_destinations(data_manager):
    panel = DetectionQueuePanel()
    panel.anomalies = data_manager.get_detection_queue()
    text = _render_text(panel.render())
    assert "203.0.113.1" in text
    assert "CRITICAL" in text
    assert "BCN" in text and "DGA" in text
    assert "beacons 1" in text


# ----------------------------------------------------------------- export

@pytest.mark.unit
def test_export_writes_jsonl_and_csv(tmp_path, data_manager):
    rows = data_manager.query_events()

    path, error = export_events(rows, "jsonl", directory=str(tmp_path / "out"))
    assert error is None and path.suffix == ".jsonl"
    lines = path.read_text().splitlines()
    assert len(lines) == len(rows)
    assert set(json.loads(lines[0])) == set(EXPORT_FIELDS)

    path, error = export_events(rows, "csv", directory=str(tmp_path / "out"))
    assert error is None and path.suffix == ".csv"
    with open(path, newline="") as fh:
        reader = list(csv.DictReader(fh))
    assert len(reader) == len(rows)


@pytest.mark.unit
def test_export_falls_back_when_directory_unwritable(tmp_path):
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("file in the way")
    fallback = tmp_path / "fallback"

    path, error = export_events([{"event_type": "high_threat"}], "jsonl",
                                directory=str(blocker / "sub"), fallback_dir=str(fallback))
    assert error is None
    assert path.parent == fallback


@pytest.mark.unit
def test_export_rejects_unknown_format(tmp_path):
    path, error = export_events([], "xml", directory=str(tmp_path))
    assert path is None and "unsupported" in error


# ----------------------------------------------------------------- headless UI

@pytest.mark.integration
def test_detections_log_screen_filters_and_drills_down(populated_db, data_manager):
    from textual.app import App

    from src.ui.detections_log import DetectionsLogScreen

    class Harness(App):
        def on_mount(self):
            self.push_screen(DetectionsLogScreen(data_manager, export_directory="/tmp"))

    async def scenario():
        app = Harness()
        async with app.run_test(size=(160, 50)) as pilot:
            screen = app.screen
            await pilot.pause()
            total = len(screen._rows)
            assert total == 4
            await pilot.press("s")  # min severity -> MEDIUM: all four events qualify
            await pilot.pause()
            assert len(screen._rows) == total
            await pilot.press("s")  # -> HIGH: high_threat and dga_like
            await pilot.pause()
            assert len(screen._rows) == 2
            await pilot.press("s")  # -> CRITICAL: only the critical high_threat
            await pilot.pause()
            assert len(screen._rows) == 1
            await pilot.press("s")  # wrap back to any
            await pilot.pause()
            assert len(screen._rows) == total
            await pilot.press("o")  # sort by severity
            await pilot.pause()
            assert screen._rows[0]["severity"] == "CRITICAL"

    asyncio.run(scenario())


@pytest.mark.e2e
def test_dashboard_smoke_with_detections(populated_db):
    from src.ui.dashboard_enhanced import CobaltGraphDashboardEnhanced

    async def scenario():
        app = CobaltGraphDashboardEnhanced(db_path=populated_db, mode="device")
        async with app.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


@pytest.mark.integration
def test_intelligence_modal_panels_render_full_and_sparse_rows():
    """Every panel must render a full row and a sparse row without raising."""
    from textual.app import App

    from src.ui.connection_modal import ConnectionIntelligenceModal

    full = {
        "dst_ip": "203.0.113.2", "dst_port": 8443, "src_ip": "10.0.0.2", "threat_score": 0.74,
        "confidence": 0.8, "high_uncertainty": 0, "dst_org": "Example", "dst_org_type": "hosting",
        "score_statistical": 0.7, "score_rule_based": 0.8, "score_heuristic": 0.6,
        "score_neural_net": None, "score_organization": 0.7, "score_spread": 0.2,
        "beaconing_detected": 1, "beaconing_interval": 30.0, "beaconing_jitter": 3.0,
        "dga_detected": 1, "dns_query": "x7k2qz9lm4.example.test", "tls_sni": None,
        "verification_status": "verified", "verification_confidence": 0.8,
        "timestamp": time.time(), "hop_count": 4, "ttl_observed": 52,
    }
    sparse = {"dst_ip": "192.0.2.9", "dst_port": 80}

    class Harness(App):
        def on_mount(self):
            # Shapes as produced by the analytics layer: attack paths are lists of IPs
            self.graph_analytics_cache = {
                "potential_attack_paths": [["10.0.0.2", "203.0.113.2", "198.51.100.1"]],
                "high_centrality_ips": [{"ip": "203.0.113.2", "centrality": 0.06}],
                "threat_clusters": [{"size": 2, "ips": ["203.0.113.2", "198.51.100.1"]}],
            }

    async def scenario():
        app = Harness()
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            for connection in (full, sparse):
                modal = ConnectionIntelligenceModal(connection)
                await app.push_screen(modal)
                await pilot.pause()
                for panel in modal.query(".modal_panel"):
                    panel.render()
                app.pop_screen()
                await pilot.pause()

    asyncio.run(scenario())


@pytest.mark.unit
def test_new_detection_rows_are_read_incrementally(data_manager):
    baseline = data_manager.get_max_event_id()
    assert baseline > 0
    assert data_manager.get_detections_after(baseline) == []
    rows = data_manager.get_detections_after(0)
    assert [r["id"] for r in rows] == sorted(r["id"] for r in rows)


@pytest.mark.integration
def test_new_high_severity_detections_toast_once(populated_db):
    """First refresh records a baseline (no flood); later HIGH/CRITICAL rows toast once each."""
    from src.storage.database import Database
    from src.ui.dashboard_enhanced import CobaltGraphDashboardEnhanced

    toasts = []

    async def scenario():
        app = CobaltGraphDashboardEnhanced(db_path=populated_db, mode="device")
        async with app.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            app.notify = lambda message, **kw: toasts.append((message, kw))
            app._toast_last_id = None
            app._notify_new_detections()          # baseline: existing rows are not toasted
            assert toasts == []

            db = Database(populated_db)
            db.add_event("high_threat", "New critical host", "CRITICAL", dst_ip="192.0.2.50", threat_score=0.97)
            db.add_event("beaconing", "Low-grade rhythm", "LOW", dst_ip="192.0.2.51")
            db.close()

            app._notify_new_detections()
            app._notify_new_detections()          # second call: nothing new, nothing repeated
            await pilot.pause()

    asyncio.run(scenario())
    assert [t[0] for t in toasts] == ["New critical host"]
    assert toasts[0][1]["severity"] == "error"


@pytest.mark.unit
def test_placeholder_modal_actions_are_gone():
    from src.ui.connection_modal import ConnectionIntelligenceModal

    keys = {binding.key for binding in ConnectionIntelligenceModal.BINDINGS}
    assert {"b", "w", "e"}.isdisjoint(keys)
    assert not hasattr(ConnectionIntelligenceModal, "action_add_blocklist")
    assert not hasattr(ConnectionIntelligenceModal, "action_export_stix")


@pytest.mark.integration
def test_log_empty_state_names_the_problem(populated_db, data_manager):
    """When filters match nothing the log says so, instead of showing a blank table."""
    from textual.app import App

    from src.ui.detections_log import DetectionsLogScreen

    class Harness(App):
        def on_mount(self):
            self.push_screen(DetectionsLogScreen(data_manager, export_directory="/tmp"))

    async def scenario():
        app = Harness()
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            screen = app.screen
            # severity -> MEDIUM, HIGH, CRITICAL; then the type filter: beaconing is HIGH-level, so no match
            for key in ("s", "s", "s"):
                await pilot.press(key)
                await pilot.pause()
            await pilot.press("t")  # type -> beacon
            await pilot.pause()
            assert screen._rows == []
            status = str(screen.query_one("#log_status").render())
            assert "No detections match" in status

    asyncio.run(scenario())


@pytest.mark.e2e
def test_globe_key_pauses_the_shown_map(populated_db):
    """g pauses the animation of the map currently displayed, and resumes it on the next press."""
    from src.ui.dashboard_enhanced import CobaltGraphDashboardEnhanced

    async def scenario():
        app = CobaltGraphDashboardEnhanced(db_path=populated_db, mode="device")
        async with app.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            panel = app.globe_panel
            shown = {
                "flat": panel.world_map,
                "rotating": panel.enhanced_globe,
                "simple": panel.simple_globe,
            }[panel._current_map_type]
            assert shown.paused is False
            app.action_toggle_globe()
            assert shown.paused is True
            assert app.sub_title == "Map animation paused"
            app.action_toggle_globe()
            assert shown.paused is False

    asyncio.run(scenario())
