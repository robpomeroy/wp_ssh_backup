"""Choosing which local backup set to restore.

These are pure functions over the sets found in the backup directory:
they read no remote host and make no connection, so they can be
exercised without one. The rules they enforce are:

- A backup set is complete only when it holds every artifact the
  requested restore needs, together with that artifact's checksum file.
- A --timestamp may name a full backup id or a bare timestamp; a bare
  timestamp must match exactly one set.
- When no timestamp is given, the newest COMPLETE set is chosen. The
  documented schedules can produce a database-only set newer than the
  newest files set, so an incomplete set must never block a restore
  that could otherwise proceed.
- Two sets can share the same minute (the run suffix is random, not
  chronological), so the newest set is only chosen when it is
  unambiguous; otherwise the caller is asked for a full backup id.
"""

from __future__ import annotations

from pathlib import Path

from common import (
    MissingArtifactError,
    backup_id_from_archive_name,
    checksum_name,
    db_archive_name,
    files_archive_name,
    find_backup_sets,
    parse_backup_id,
    utc_timestamp,
)

__all__ = [
    "choose_set",
    "latest_set",
    "list_backup_sets",
    "required_artifacts",
    "resolve_timestamp",
    "set_is_complete",
    "ts_of",
]


def list_backup_sets(backup_dir: Path) -> dict[str, dict[str, Path]]:
    """Return {timestamp: {archive_name: local_path}} for complete sets.

    Args:
        backup_dir: The directory the backup sets live in.

    Returns:
        A mapping of backup id to the set's files, keyed by file name.
    """
    sets: dict[str, dict[str, Path]] = {}
    for ts, files in find_backup_sets(backup_dir).items():
        by_name = {path.name: path for path in files}
        sets[ts] = by_name
    return sets


def required_artifacts(
    bid: str, include_files: bool, include_database: bool
) -> list[str]:
    """Archive names a restore of the given kind needs (checksums implied).

    Args:
        bid: The backup identifier the names are derived from.
        include_files: Whether the files archive is needed.
        include_database: Whether the database archive is needed.

    Returns:
        The required archive names.
    """
    required: list[str] = []
    if include_files:
        required.append(files_archive_name(bid))
    if include_database:
        required.append(db_archive_name(bid))
    return required


def set_is_complete(
    set_files: dict[str, Path],
    include_files: bool,
    include_database: bool,
) -> bool:
    """True if the set contains every required archive and its checksum.

    Args:
        set_files: The set's files, keyed by name.
        include_files: Whether the files archive is needed.
        include_database: Whether the database archive is needed.

    Returns:
        True if the set holds every required artifact and its checksum.
    """
    bid = ts_of(set_files)
    return all(
        name in set_files and checksum_name(name) in set_files
        for name in required_artifacts(bid, include_files, include_database)
    )


def resolve_timestamp(
    sets: dict[str, dict[str, Path]],
    timestamp: str,
) -> str:
    """
    Resolve a --timestamp value to an exact backup id in sets.

    Accepts a full backup id ('20261014T0930Z-a1b2c3') or a bare timestamp
    ('20261014T0930Z'). A bare timestamp resolves only when exactly one set
    matches; if several backups share the minute — including a legacy
    suffix-less set alongside suffixed ones — the error lists their full
    ids so the caller can disambiguate. Raises MissingArtifactError when
    nothing matches.

    Args:
        sets: The available backup sets, keyed by backup id.
        timestamp: The user-supplied value.

    Returns:
        The exact backup id of the requested set.
    """
    if "-" in timestamp:
        # A full id can only match itself; the bare-timestamp path below
        # would also match it, but the exact shortcut is unambiguous.
        if timestamp in sets:
            return timestamp
        available = ", ".join(sorted(sets)) or "(none)"
        raise MissingArtifactError(
            f"No backup set with timestamp {timestamp}. "
            f"Available: {available}"
        )
    matches = [bid for bid in sets if bid.split("-", 1)[0] == timestamp]
    if not matches:
        available = ", ".join(sorted(sets)) or "(none)"
        raise MissingArtifactError(
            f"No backup set with timestamp {timestamp}. "
            f"Available: {available}"
        )
    if len(matches) > 1:
        raise MissingArtifactError(
            f"Several backup sets share the timestamp {timestamp}; "
            "specify a full backup id instead. Available ids: "
            + ", ".join(sorted(matches))
        )
    return matches[0]


def ts_of(set_files: dict[str, Path]) -> str:
    """Extract the backup identifier from any archive filename in the set.

    Args:
        set_files: The set's files, keyed by name.

    Returns:
        The backup identifier.

    Raises:
        MissingArtifactError: If the set contains no archive files.
    """
    for name in set_files:
        bid = backup_id_from_archive_name(name)
        if bid:
            return bid
    raise MissingArtifactError("Backup set contains no archive files.")


def latest_set(
    candidates: list[dict[str, Path]],
    backup_dir: Path,
) -> dict[str, Path]:
    """
    Pick the most recent candidate set, rejecting same-minute ambiguity.

    The backup id's timestamp has minute resolution, so two complete sets
    can share it while differing only by their random run suffix. The
    suffix is random, not chronological, so comparing ids (or suffixes)
    cannot tell which run finished last. Rather than silently guessing,
    this raises and asks for an explicit full backup id.

    Args:
        candidates: Complete candidate sets.
        backup_dir: The backup directory, for the error message.

    Returns:
        The single most recent candidate set.

    Raises:
        MissingArtifactError: If two or more candidates share the newest
            timestamp.
    """
    newest = max(parse_backup_id(ts_of(files)) for files in candidates)
    newest_ids = [
        ts_of(files)
        for files in candidates
        if parse_backup_id(ts_of(files)) == newest
    ]
    if len(newest_ids) > 1:
        raise MissingArtifactError(
            f"Several backup sets in {backup_dir} share the newest "
            f"timestamp {utc_timestamp(newest)}; the run suffix is random, "
            "so recency cannot be determined. Specify a full backup id "
            "with --timestamp. Available ids: "
            + ", ".join(sorted(newest_ids))
        )
    return next(files for files in candidates if ts_of(files) == newest_ids[0])


def choose_set(
    sets: dict[str, dict[str, Path]],
    timestamp: str | None,
    include_files: bool,
    include_database: bool,
    backup_dir: Path,
) -> dict[str, Path]:
    """
    Pick the backup set to restore, validating required artifacts exist.

    The timestamp argument accepts a full backup id
    ('20261014T0930Z-a1b2c3') or a bare timestamp ('20261014T0930Z'); a
    bare timestamp must match exactly one set. Without an explicit
    timestamp, sets are filtered to those containing the requested
    artifacts before the latest is chosen — the documented schedules can
    produce a database-only set newer than the latest files set, and that
    newer set must not block a files restore. An explicit timestamp is
    strict: it must exist and contain the requested artifacts, with no
    fallback to older sets.

    Args:
        sets: The available backup sets, keyed by backup id.
        timestamp: The user-supplied timestamp, or None to pick the
            newest matching set.
        include_files: Whether the files archive is needed.
        include_database: Whether the database archive is needed.
        backup_dir: The backup directory, for the error messages.

    Returns:
        The chosen set's files, keyed by name.

    Raises:
        MissingArtifactError: If no set matches, if the match is
            ambiguous, or if the chosen set is missing an artifact.
    """
    if not sets:
        raise MissingArtifactError(f"No backup sets found in {backup_dir}.")
    if timestamp:
        chosen = sets[resolve_timestamp(sets, timestamp)]
    else:
        candidates = [
            files
            for files in sets.values()
            if set_is_complete(files, include_files, include_database)
        ]
        if not candidates:
            wanted = ", ".join(
                required_artifacts("*", include_files, include_database)
            )
            raise MissingArtifactError(
                "No backup set contains the requested artifact(s) "
                f"({wanted or 'none'}). "
                f"Searched {len(sets)} set(s) in {backup_dir}."
            )
        chosen = latest_set(candidates, backup_dir)
        print(
            f"No --timestamp given; using latest matching backup set: "
            f"{ts_of(chosen)}"
        )

    bid = ts_of(chosen)
    missing = [
        name
        for name in required_artifacts(bid, include_files, include_database)
        if name not in chosen or checksum_name(name) not in chosen
    ]
    if missing:
        raise MissingArtifactError(
            "Backup set is missing required artifact(s): " + ", ".join(missing)
        )
    return chosen
