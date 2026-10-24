"""Safety rules of tools/db_utils.py: fail closed, fractional days, no silent defaults."""

import importlib.util
import sqlite3
import time
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[3] / "tools" / "db_utils.py"


def _load():
    spec = importlib.util.spec_from_file_location("db_utils", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_db(path, ages_days):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE connections (id INTEGER PRIMARY KEY, timestamp REAL, dst_ip TEXT)")
    now = time.time()
    for n, age in enumerate(ages_days):
        conn.execute("INSERT INTO connections (timestamp, dst_ip) VALUES (?, ?)", (now - age * 86400, f"10.0.0.{n}"))
    conn.commit()
    conn.close()


@pytest.mark.unit
def test_option_without_value_exits_instead_of_defaulting():
    db_utils = _load()
    with pytest.raises(SystemExit) as exc:
        db_utils._option(["vacuum", "--yes", "--db"], "--db", "database/cobaltgraph.db")
    assert exc.value.code == 2


@pytest.mark.unit
def test_prune_accepts_fractional_days(tmp_path):
    db_utils = _load()
    path = str(tmp_path / "f.db")
    _make_db(path, [0.1, 5])  # one row 2.4 hours old, one 5 days old
    assert db_utils.prune_connections(path, days=1.0, dry_run=True) == 0
    assert db_utils.prune_connections(path, days=1.0) == 0
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0] == 1
    conn.close()


@pytest.mark.unit
def test_prune_refuses_non_positive_days(tmp_path):
    db_utils = _load()
    path = str(tmp_path / "z.db")
    _make_db(path, [1])
    assert db_utils.prune_connections(path, days=0) == 1


@pytest.mark.unit
def test_merge_command_is_gone():
    db_utils = _load()
    assert not hasattr(db_utils, "merge_databases")


@pytest.mark.unit
def test_holders_reports_another_process_with_the_database_open(tmp_path):
    import subprocess
    import sys

    db_utils = _load()
    path = tmp_path / "held.db"
    _make_db(str(path), [1])
    holder = subprocess.Popen([sys.executable, "-c",
                               f"import sqlite3,time; c=sqlite3.connect({str(path)!r}); c.execute('select 1').fetchall(); time.sleep(30)"])
    try:
        for _ in range(50):
            if db_utils._holders(str(path)):
                break
            time.sleep(0.1)
        assert holder.pid in db_utils._holders(str(path))
    finally:
        holder.kill()
        holder.wait()
    assert db_utils._holders(str(path)) == []
