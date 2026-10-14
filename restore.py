"""Restore a WordPress site from a WP SSH Backup set.

Uploads a chosen backup set to the remote host, verifies SHA-256 checksums
remotely, extracts the files tarball into the site root and imports the
database dump.
"""

from __future__ import annotations

import argparse
import posixpath
import sys
import time
from pathlib import Path

import paramiko

from common import (
    ChecksumError,
    Config,
    MissingArtifactError,
    WPSSHBackupError,
    backup_id,
    backup_id_from_archive_name,
    checksum_name,
    connect,
    db_archive_name,
    detect_wp_cli,
    files_archive_name,
    find_backup_sets,
    load_config,
    mysql_client_config,
    parse_backup_id,
    parse_sha256sum_output,
    read_remote_file,
    read_wp_db_settings,
    remove_remote_file,
    remove_remote_staging,
    run_remote_cmd,
    run_remote_cmd_checked,
    shquote,
    split_db_host,
    staging_dir_for,
    trap_rm_action,
    utc_timestamp,
    write_remote_file,
)


# ---------------------------------------------------------------------------
# Local backup set selection
# ---------------------------------------------------------------------------


def list_backup_sets(backup_dir: Path) -> dict[str, dict[str, Path]]:
    """Return {timestamp: {archive_name: local_path}} for complete sets."""
    sets: dict[str, dict[str, Path]] = {}
    for ts, files in find_backup_sets(backup_dir).items():
        by_name = {path.name: path for path in files}
        sets[ts] = by_name
    return sets


def required_artifacts(
    bid: str, include_files: bool, include_database: bool
) -> list[str]:
    """Archive names a restore of the given kind needs (checksums implied)."""
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
    """True if the set contains every required archive and its checksum."""
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


def ts_of(set_files: dict[str, Path]) -> str:
    """Extract the backup identifier from any archive filename in the set."""
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


# ---------------------------------------------------------------------------
# Remote restore
# ---------------------------------------------------------------------------


def upload_artifacts(
    sftp: paramiko.SFTPClient,
    set_files: dict[str, Path],
    archive_names: list[str],
    staging: str,
) -> None:
    for name in archive_names:
        sftp_upload_checked(
            sftp, set_files[name], posixpath.join(staging, name)
        )
        sftp_upload_checked(
            sftp,
            set_files[checksum_name(name)],
            posixpath.join(staging, checksum_name(name)),
        )


def sftp_upload_checked(
    sftp: paramiko.SFTPClient, local: Path, remote: str
) -> None:
    if not local.is_file():
        raise MissingArtifactError(f"Local file missing: {local}")
    sftp.put(str(local), remote)


def verify_remote_checksums(
    client: paramiko.SSHClient,
    staging: str,
    archive_names: list[str],
) -> None:
    """
    Verify each uploaded archive against its uploaded .sha256 manifest.

    The manifest is not trusted blindly: `sha256sum -c` checks whatever
    filename the manifest names, so a manifest pointing at another file
    with a matching digest would pass while the requested archive stays
    corrupt. Instead the manifest is read and must contain exactly one
    entry naming exactly the requested archive (no path separators, so no
    traversal), and the archive's bytes are then hashed directly with
    `sha256sum` and compared to the manifest's digest.
    """
    sftp = client.open_sftp()
    try:
        for name in archive_names:
            checksum_remote = posixpath.join(staging, checksum_name(name))
            try:
                text = read_remote_file(sftp, checksum_remote)
            except FileNotFoundError as exc:
                raise ChecksumError(
                    f"Remote checksum file missing: {checksum_remote}"
                ) from exc
            entries = parse_sha256sum_output(text)
            # Reject any path component in ANY entry name before anything
            # else: a manifest may only reference plain filenames inside
            # the staging directory, never paths (no traversal).
            for entry_name in entries:
                if (
                    "/" in entry_name
                    or "\\" in entry_name
                    or posixpath.basename(entry_name) != entry_name
                    or entry_name in (".", "..")
                ):
                    raise ChecksumError(
                        f"{checksum_name(name)} names a path outside the "
                        f"staging directory: {entry_name}"
                    )
            if len(entries) != 1:
                raise ChecksumError(
                    f"{checksum_name(name)} must contain exactly one "
                    f"entry, found {len(entries)}"
                )
            if name not in entries:
                raise ChecksumError(
                    f"{checksum_name(name)} does not name {name}; the "
                    "manifest cannot be trusted for this archive"
                )
            # Hash the archive's bytes directly; the manifest only supplies
            # the expected digest.
            command = (
                f"cd {shquote(staging)} && "
                f"sha256sum {shquote(name)}"
            )
            code, out, err = run_remote_cmd(client, command)
            if code != 0:
                raise ChecksumError(
                    f"Could not hash {name} on the remote host: "
                    f"{err.strip()}"
                )
            actual = parse_sha256sum_output(out)
            if actual.get(name) != entries[name]:
                raise ChecksumError(
                    f"Remote checksum verification failed for {name}: "
                    f"expected {entries[name]}, got "
                    f"{actual.get(name, '(none)')}"
                )
    finally:
        sftp.close()


def extract_files(
    client: paramiko.SSHClient,
    config: Config,
    staging: str,
    ts: str,
) -> None:
    archive = posixpath.join(staging, files_archive_name(ts))
    command = f"tar xzf {shquote(archive)} -C {shquote(config.wp_site_root)}"
    run_remote_cmd_checked(client, command, timeout=3600)


def import_database(
    client: paramiko.SSHClient,
    config: Config,
    staging: str,
    ts: str,
) -> None:
    """Import the database from the DB tarball in the staging dir."""
    archive = posixpath.join(staging, db_archive_name(ts))
    dump_name = f"wp-db-{ts}.sql"
    dump_path = posixpath.join(staging, dump_name)
    wp_cli = detect_wp_cli(client, config)

    # Extract the SQL dump from the tarball first.
    run_remote_cmd_checked(
        client,
        f"tar xzf {shquote(archive)} -C {shquote(staging)}",
        timeout=1800,
    )

    if wp_cli:
        command = (
            f"cd {shquote(config.wp_site_root)} && "
            f"{shquote(wp_cli)} db import {shquote(dump_path)}"
        )
        run_remote_cmd_checked(client, command, timeout=3600)
        return

    sftp = client.open_sftp()
    try:
        settings = read_wp_db_settings(sftp, config.wp_site_root)
    finally:
        sftp.close()

    host, port, socket_path = split_db_host(settings["DB_HOST"])
    cnf_name = f"my-{ts}.cnf"
    cnf_path = posixpath.join(staging, cnf_name)
    cnf_body = mysql_client_config(
        host=host,
        user=settings["DB_USER"],
        password=settings["DB_PASSWORD"],
        port=port,
        socket=socket_path,
    )

    sftp = client.open_sftp()
    try:
        write_remote_file(sftp, cnf_path, cnf_body, mode=0o600)
    finally:
        sftp.close()

    command = (
        f"cd {shquote(staging)} && "
        f"trap {trap_rm_action(cnf_path)} EXIT && "
        f"mysql --defaults-extra-file={shquote(cnf_path)} "
        f"{shquote(settings['DB_NAME'])} < {shquote(dump_path)}"
    )
    try:
        run_remote_cmd_checked(client, command, timeout=3600)
    finally:
        # Best-effort: if the connection dropped, the removal must not
        # mask the original mysql import failure.
        remove_remote_file(client, cnf_path)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_restore(
    client: paramiko.SSHClient,
    config: Config,
    set_files: dict[str, Path],
    include_files: bool,
    include_database: bool,
    staging_bid: str | None = None,
) -> None:
    """
    Restore the chosen backup set to the remote host.

    Args:
        client: An active SSH client connected to the remote host.
        config: The backup configuration.
        set_files: The local backup set to restore, keyed by filename.
        include_files: Whether to restore the WordPress files.
        include_database: Whether to restore the WordPress database.
        staging_bid: Backup identifier for the staging directory name.
            Defaults to a fresh unique identifier.
    """
    backup_bid = ts_of(set_files)
    staging_ts = staging_bid or backup_id()
    staging = staging_dir_for(config.wp_site_root, staging_ts)
    archive_names: list[str] = []
    if include_files:
        archive_names.append(files_archive_name(backup_bid))
    if include_database:
        archive_names.append(db_archive_name(backup_bid))

    # Bare mkdir (no -p): the staging dir is exclusive to this run, and a
    # collision aborts instead of sharing artifacts with another run.
    code, _, err = run_remote_cmd(client, f"mkdir {shquote(staging)}")
    if code != 0:
        raise WPSSHBackupError(
            f"Could not create staging directory {staging}: "
            f"{err.strip() or 'already exists?'}"
        )
    print(f"Remote staging directory: {staging}")

    try:
        with client.open_sftp() as sftp:
            upload_artifacts(sftp, set_files, archive_names, staging)
        verify_remote_checksums(client, staging, archive_names)
        print("Remote checksum verification passed.")

        if include_files:
            started = _now()
            extract_files(client, config, staging, backup_bid)
            print(f"Files extracted ({_now() - started:.1f}s).")

        if include_database:
            started = _now()
            import_database(client, config, staging, backup_bid)
            print(f"Database imported ({_now() - started:.1f}s).")
    except (
        WPSSHBackupError,
        OSError,
        paramiko.SSHException,
    ):
        # Covers every WPSSHBackupError subclass — including base-class
        # errors such as an invalid WP_CLI_PATH — plus transport failures.
        # Restore always cleans staging: a failed verification means the
        # upload must be repeated.
        remove_remote_staging(client, staging)
        raise

    remove_remote_staging(client, staging)


def _now() -> float:
    return time.monotonic()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Restore a WordPress site from a WP SSH Backup set."
    )
    parser.add_argument(
        "--timestamp",
        help="Backup set to restore: a full backup id (e.g. "
        "20261014T0930Z-a1b2c3) or a bare timestamp (e.g. 20261014T0930Z, "
        "which must match exactly one set). Defaults to the latest "
        "matching set.",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--files",
        action="store_true",
        help="Restore only the WordPress files.",
    )
    group.add_argument(
        "--database",
        action="store_true",
        help="Restore only the WordPress database.",
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="Restore both files and database (the default).",
    )
    args = parser.parse_args(argv)

    neither = not (args.files or args.database)
    include_files = args.files or args.all or neither
    include_database = args.database or args.all or neither

    try:
        config = load_config()
        sets = list_backup_sets(config.backup_dir)
        set_files = choose_set(
            sets,
            args.timestamp,
            include_files,
            include_database,
            config.backup_dir,
        )
        client = connect(config)
    except WPSSHBackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        run_restore(client, config, set_files, include_files, include_database)
    except (WPSSHBackupError, OSError, paramiko.SSHException) as exc:
        # run_restore cleans up staging and re-raises transport/SFTP
        # failures; report them here rather than letting them escape as a
        # traceback.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()

    print("Restore complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
