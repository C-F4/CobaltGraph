#!/usr/bin/env python3
"""
CobaltGraph database utilities.

Operates on the database the application writes (database/cobaltgraph.db by default).
Use --db PATH to point any command at another file.

Commands:
    list                         Show size and counts
    prune [--days N] [--dry-run] Delete connections older than N days (default 30)
    vacuum [--yes]               Rewrite the file to reclaim space (dry run unless --yes)

Stop the application before prune or vacuum. Both write to the file.
"""

import math
import shutil
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

# Anchored to the project root, so the tool works from any directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = str(PROJECT_ROOT / "database" / "cobaltgraph.db")


def _holders(db_path):
    """
    PIDs of other processes that have the database (or its WAL/SHM files) open.

    Linux only: reads /proc. Elsewhere returns [] and the caller relies on the
    documented "stop the application first" instruction.
    """
    proc = Path("/proc")
    if not proc.is_dir():
        return []
    targets = {str(Path(db_path).resolve()), str(Path(db_path).resolve()) + "-wal",
               str(Path(db_path).resolve()) + "-shm"}
    me = str(__import__("os").getpid())
    pids = set()
    for pid_dir in proc.iterdir():
        if not pid_dir.name.isdigit() or pid_dir.name == me:
            continue
        try:
            for fd in (pid_dir / "fd").iterdir():
                try:
                    if str(fd.resolve()) in targets:
                        pids.add(int(pid_dir.name))
                        break
                except OSError:
                    continue
        except OSError:
            continue
    return sorted(pids)


def _connection_stats(db_path):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    try:
        total, unique_ips, first, last = conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT dst_ip), MIN(timestamp), MAX(timestamp) FROM connections"
        ).fetchone()
        return {"total": total, "unique_ips": unique_ips, "first": first, "last": last}
    finally:
        conn.close()


def list_database(db_path):
    """Print size and counts for one database file."""
    path = Path(db_path)
    print("=" * 70)
    print(f"CobaltGraph database: {path}")
    print("=" * 70)
    if not path.exists():
        print("❌ Not found. The application creates it on first run; pass --db to inspect another file.")
        return 1

    size = path.stat().st_size
    print(f"Size:        {size / 1048576:,.1f} MiB")
    try:
        stats = _connection_stats(path)
    except sqlite3.Error as e:
        print(f"❌ Could not read connections: {e}")
        return 1
    print(f"Connections: {stats['total']:,}")
    print(f"Unique IPs:  {stats['unique_ips']:,}")
    if stats["first"]:
        first = datetime.fromtimestamp(stats["first"]).strftime("%Y-%m-%d %H:%M")
        last = datetime.fromtimestamp(stats["last"]).strftime("%Y-%m-%d %H:%M")
        print(f"Time range:  {first} → {last}")
    return 0


def prune_connections(db_path, days, dry_run=False, batch_size=2000):
    """
    Delete connection rows older than `days` (may be fractional), in batches.

    Scope: the connections table only. The application expires old events itself
    (events are kept for at most 7 days), so they are not touched here.

    Reads and writes the file directly rather than through the application's
    Database class, so no schema migration runs against the target.
    """
    if days <= 0:
        print("❌ --days must be greater than zero")
        return 1
    if not Path(db_path).exists():
        print(f"❌ Database not found: {db_path}")
        return 1

    cutoff = time.time() - days * 86400
    conn = sqlite3.connect(db_path, timeout=30)
    try:
        old = conn.execute("SELECT COUNT(*) FROM connections WHERE timestamp < ?", (cutoff,)).fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
        print(f"{db_path}: {old:,} of {total:,} connections are older than {days:g} days")
        if dry_run:
            print("   (dry run: nothing deleted)")
            return 0
        if old == 0:
            print("   nothing to delete")
            return 0

        deleted = 0
        while True:
            cursor = conn.execute(
                "DELETE FROM connections WHERE id IN "
                "(SELECT id FROM connections WHERE timestamp < ? LIMIT ?)",
                (cutoff, batch_size),
            )
            conn.commit()
            deleted += cursor.rowcount
            if cursor.rowcount < batch_size:
                break
            print(f"   deleted {deleted:,} so far...", flush=True)
        print(f"✅ Deleted {deleted:,} connections")
        print("   Run 'vacuum --yes' to return the freed space to the filesystem.")
        return 0
    except sqlite3.Error as e:
        print(f"❌ {db_path} is not a readable CobaltGraph database: {e}")
        return 1
    finally:
        conn.close()


def vacuum_database(db_path, confirmed=False):
    """
    Rewrite the database file to reclaim free pages.

    Needs roughly the database's size in free disk space and exclusive access to the
    file. Does nothing without --yes, so it is never started by accident.
    """
    path = Path(db_path)
    if not path.exists():
        print(f"❌ Database not found: {db_path}")
        return 1

    size = path.stat().st_size
    free = shutil.disk_usage(path.parent).free
    print(f"{db_path}: {size / 1048576:,.1f} MiB, {free / 1048576:,.1f} MiB free on the volume")
    if free < size:
        print("❌ Not enough free space for VACUUM (it needs about the database's size)")
        return 1
    if not confirmed:
        print("   Dry run. Re-run with --yes to rewrite the file (stop the app first).")
        return 0

    conn = sqlite3.connect(db_path, timeout=60)
    try:
        conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
        conn.execute("VACUUM")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    print(f"✅ Vacuumed {db_path}: {size / 1048576:,.1f} MiB -> {path.stat().st_size / 1048576:,.1f} MiB")
    return 0


def _option(args, name, default=None):
    """Value after `name`. A flag given without a value is an error, never a silent default."""
    if name in args:
        idx = args.index(name)
        if idx + 1 < len(args) and not args[idx + 1].startswith("--"):
            return args[idx + 1]
        print(f"❌ {name} needs a value")
        sys.exit(2)
    return default


def _usage():
    print("CobaltGraph database utilities")
    print()
    print("Usage:")
    print("  python3 tools/db_utils.py list     [--db PATH]")
    print("  python3 tools/db_utils.py prune    [--db PATH] [--days N] [--dry-run]")
    print("  python3 tools/db_utils.py vacuum   [--db PATH] [--yes]")
    print()
    print(f"Default --db is {DEFAULT_DB}, the database the application writes.")
    print("Stop the application before prune or vacuum.")


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        _usage()
        sys.exit(0 if args else 1)

    command = args[0].lower()
    known = {"--db", "--days", "--dry-run", "--yes", "--force"}
    unknown = [a for a in args[1:] if a.startswith("--") and a not in known]
    if unknown:
        print(f"❌ Unknown option(s): {', '.join(unknown)}")
        _usage()
        sys.exit(2)
    db_path = _option(args, "--db", DEFAULT_DB)

    if command == "list":
        sys.exit(list_database(db_path))
    if command in ("prune", "vacuum") and "--force" not in args and "--dry-run" not in args \
            and not ("vacuum" == command and "--yes" not in args):
        holders = _holders(db_path)
        if holders:
            print(f"❌ {db_path} is open by process(es) {holders}. Stop the application first, "
                  f"or pass --force if you are sure it is not running.")
            sys.exit(1)
    if command == "prune":
        try:
            days = float(_option(args, "--days", "30"))
        except ValueError:
            print("❌ --days must be a number")
            sys.exit(2)
        if not math.isfinite(days):
            print("❌ --days must be a finite number")
            sys.exit(2)
        sys.exit(prune_connections(db_path, days, dry_run="--dry-run" in args))
    if command == "vacuum":
        sys.exit(vacuum_database(db_path, confirmed="--yes" in args))

    print(f"Unknown command: {command}")
    _usage()
    sys.exit(2)


if __name__ == "__main__":
    main()
