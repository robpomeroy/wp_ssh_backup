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
    RemoteCommandError,
    WPSSHBackupError,
    checksum_name,
    connect,
    db_archive_name,
    detect_wp_cli,
    files_archive_name,
    find_backup_sets,
    load_config,
    mysql_client_config,
    read_wp_db_settings,
    remove_remote_staging,
    run_remote_cmd,
    run_remote_cmd_checked,
    shquote,
    split_db_host,
    staging_dir_for,
    timestamp_from_archive_name,
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


def choose_set(
    sets: dict[str, dict[str, Path]],
    timestamp: str | None,
    include_files: bool,
    include_database: bool,
    backup_dir: Path,
) -> dict[str, Path]:
    """Pick the backup set to restore, validating required artifacts exist."""
    if not sets:
        raise MissingArtifactError(f"No backup sets found in {backup_dir}.")
    if timestamp:
        if timestamp not in sets:
            available = ", ".join(sorted(sets)) or "(none)"
            raise MissingArtifactError(
                f"No backup set with timestamp {timestamp}. "
                f"Available: {available}"
            )
        chosen = sets[timestamp]
    else:
        latest = max(sets)
        chosen = sets[latest]
        print(f"No --timestamp given; using latest backup set: {latest}")

    required: list[str] = []
    if include_files:
        required.append(files_archive_name(ts_of(chosen)))
    if include_database:
        required.append(db_archive_name(ts_of(chosen)))
    missing = [
        name
        for name in required
        if name not in chosen or checksum_name(name) not in chosen
    ]
    if missing:
        raise MissingArtifactError(
            "Backup set is missing required artifact(s): " + ", ".join(missing)
        )
    return chosen


def ts_of(set_files: dict[str, Path]) -> str:
    """Extract the timestamp from any archive filename in the set."""
    for name in set_files:
        ts = timestamp_from_archive_name(name)
        if ts:
            return ts
    raise MissingArtifactError("Backup set contains no archive files.")


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
    """Run `sha256sum -c` remotely for each uploaded archive."""
    for name in archive_names:
        # sha256sum -c expects the filename relative to the checksum file.
        command = (
            f"cd {shquote(staging)} && "
            f"sha256sum -c {shquote(checksum_name(name))}"
        )
        code, _, err = run_remote_cmd(client, command)
        if code != 0:
            raise ChecksumError(
                f"Remote checksum verification failed for {name}: "
                f"{err.strip()}"
            )


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
        f"trap 'rm -f {shquote(cnf_path)}' EXIT && "
        f"mysql --defaults-extra-file={shquote(cnf_path)} "
        f"{shquote(settings['DB_NAME'])} < {shquote(dump_path)}"
    )
    try:
        run_remote_cmd_checked(client, command, timeout=3600)
    finally:
        run_remote_cmd(client, f"rm -f {shquote(cnf_path)}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_restore(
    client: paramiko.SSHClient,
    config: Config,
    set_files: dict[str, Path],
    include_files: bool,
    include_database: bool,
    ts: str | None = None,
) -> None:
    backup_ts = ts_of(set_files)
    staging_ts = ts or utc_timestamp()
    staging = staging_dir_for(config.wp_site_root, staging_ts)
    archive_names: list[str] = []
    if include_files:
        archive_names.append(files_archive_name(backup_ts))
    if include_database:
        archive_names.append(db_archive_name(backup_ts))

    run_remote_cmd_checked(client, f"mkdir -p {shquote(staging)}")
    print(f"Remote staging directory: {staging}")

    try:
        with client.open_sftp() as sftp:
            upload_artifacts(sftp, set_files, archive_names, staging)
        verify_remote_checksums(client, staging, archive_names)
        print("Remote checksum verification passed.")

        if include_files:
            started = _now()
            extract_files(client, config, staging, backup_ts)
            print(f"Files extracted ({_now() - started:.1f}s).")

        if include_database:
            started = _now()
            import_database(client, config, staging, backup_ts)
            print(f"Database imported ({_now() - started:.1f}s).")
    except (
        ChecksumError,
        RemoteCommandError,
        MissingArtifactError,
        OSError,
        paramiko.SSHException,
    ):
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
        help="Backup set timestamp to restore (e.g. 20261014T0930Z). "
        "Defaults to the latest set.",
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
    except WPSSHBackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()

    print("Restore complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
