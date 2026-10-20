"""The backup sets held locally, and the retention policy.

A set is the group of files that share one backup identifier:
the archive, its checksum manifest, and the database archive
when the run included one.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from naming import (
    BACKUP_FILE_RE,
    backup_id_from_archive_name,
    parse_backup_id,
)

# ---------------------------------------------------------------------------
# Local backup sets and retention
# ---------------------------------------------------------------------------


def find_backup_sets(backup_dir: Path) -> dict[str, list[Path]]:
    """
    Map each backup timestamp to the local files belonging to that set.

    Groups that contain no archive (e.g. an orphaned .sha256 file left
    behind after its tarball was deleted) are omitted: such a group has
    no backup id extractable from an archive name, and including it would
    make set selection fail on a group that can never be restored.

    Groups whose backup id parses to an invalid date (e.g. month 13 in
    '20261301T0000Z' — the filename regex only checks the shape) are also
    omitted, so an unparseable id can never reach date-based selection
    logic and crash it.

    Args:
        backup_dir: The directory containing the backup files.

    Returns:
        A dictionary where the keys are backup timestamps and the values are
        lists of Paths to the corresponding backup files.
    """
    sets: dict[str, list[Path]] = {}
    if not backup_dir.is_dir():
        return sets
    for path in sorted(backup_dir.iterdir()):
        if path.is_symlink() or not path.is_file():
            continue
        match = BACKUP_FILE_RE.match(path.name)
        if match:
            sets.setdefault(match.group("bid"), []).append(path)
    result: dict[str, list[Path]] = {}
    for bid, files in sets.items():
        if not any(
            backup_id_from_archive_name(path.name) for path in files
        ):
            continue
        try:
            parse_backup_id(bid)
        except ValueError:
            continue
        result[bid] = files
    return result


def prune_local_backups(
    backup_dir: Path,
    retention_days: int,
    now: datetime | None = None,
) -> list[str]:
    """
    Delete whole backup sets older than retention_days.

    Args:
        backup_dir: The directory containing the backup files.
        retention_days: The number of days to retain backups.
        now: The current datetime for comparison (defaults to UTC now).

    Returns:
        The timestamps of the removed sets. A retention_days of 0
        disables pruning.
    """
    if retention_days <= 0:
        return []
    now_dt = now or datetime.now(timezone.utc)
    cutoff = now_dt - timedelta(days=retention_days)
    removed: list[str] = []
    for bid, files in find_backup_sets(backup_dir).items():
        try:
            bid_dt = parse_backup_id(bid)
        except ValueError:
            continue
        if bid_dt < cutoff:
            for path in files:
                path.unlink(missing_ok=True)
            removed.append(bid)
    return removed
