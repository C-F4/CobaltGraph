"""
Export recorded detections (rows from the events table) as JSON Lines or CSV.
"""

import csv
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

EXPORT_FIELDS = [
    "timestamp",
    "event_type",
    "severity",
    "dst_ip",
    "dst_port",
    "src_ip",
    "threat_score",
    "org_name",
    "message",
    "metadata",
]


def export_events(
    rows: List[Dict],
    fmt: str,
    directory: str = "exports",
    fallback_dir: str = "data/exports",
) -> Tuple[Optional[Path], Optional[str]]:
    """
    Write detection rows to <directory>/detections_<timestamp>.<fmt>.

    Falls back to fallback_dir when the primary directory cannot be written.

    Returns (path, None) on success or (None, error_message) on failure.
    """
    fmt = fmt.lower()
    if fmt not in ("jsonl", "csv"):
        return None, f"unsupported export format: {fmt}"

    stamp = time.strftime("%Y%m%d_%H%M%S")
    last_error = "no writable export directory"
    for target in (directory, fallback_dir):
        try:
            out_dir = Path(target)
            out_dir.mkdir(parents=True, exist_ok=True)
            path = out_dir / f"detections_{stamp}.{fmt}"
            with open(path, "w", encoding="utf-8", newline="") as fh:
                if fmt == "jsonl":
                    for row in rows:
                        record = {key: row.get(key) for key in EXPORT_FIELDS}
                        fh.write(json.dumps(record, default=str) + "\n")
                else:
                    writer = csv.DictWriter(fh, fieldnames=EXPORT_FIELDS, extrasaction="ignore")
                    writer.writeheader()
                    for row in rows:
                        writer.writerow(row)
            return path, None
        except OSError as e:
            last_error = f"{target}: {e}"
            logger.warning(f"Detection export to {target} failed: {e}")
    return None, last_error
