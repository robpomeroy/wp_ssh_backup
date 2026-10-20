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
from typing import BinaryIO

import paramiko

from archive_validation import (
    audit_destination_tree,
    extract_verified_archive,
    require_gnu_tar,
    validate_db_members,
    validate_local_member_types,
    validate_members,
)
from cli import add_scope_arguments, add_version_argument, resolve_scope
import safe_fs
from selection import choose_set, list_backup_sets, ts_of
from common import (
    ChecksumError,
    Config,
    WPSSHBackupError,
    backup_id,
    checksum_name,
    connect,
    db_archive_name,
    detect_wp_cli,
    files_archive_name,
    load_config,
    mysql_client_config,
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
    write_remote_file,
)


# ---------------------------------------------------------------------------
# Local backup set selection
# ---------------------------------------------------------------------------


def upload_artifacts(
    sftp: paramiko.SFTPClient,
    set_files: dict[str, Path],
    handles: dict[Path, BinaryIO],
    archive_names: list[str],
    staging: str,
) -> None:
    for name in archive_names:
        sftp_upload_checked(
            sftp, handles[set_files[name]], posixpath.join(staging, name)
        )
        sftp_upload_checked(
            sftp,
            handles[set_files[checksum_name(name)]],
            posixpath.join(staging, checksum_name(name)),
        )


def sftp_upload_checked(
    sftp: paramiko.SFTPClient, handle: BinaryIO, remote: str
) -> None:
    """Upload from an already-opened, held file object.

    The caller opens the local file no-follow and keeps the descriptor
    open until validation and upload are done, so the bytes uploaded are
    the bytes the local checks inspected — not whatever a concurrent
    writer may have swapped into the pathname meanwhile.
    """
    sftp.putfo(handle, remote)


def verify_remote_checksums(
    client: paramiko.SSHClient,
    staging: str,
    archive_names: list[str],
) -> dict[str, str]:
    """
    Verify each uploaded archive against its uploaded .sha256 manifest.

    The manifest is not trusted blindly: `sha256sum -c` checks whatever
    filename the manifest names, so a manifest pointing at another file
    with a matching digest would pass while the requested archive stays
    corrupt. Instead the manifest is read and must contain exactly one
    entry naming exactly the requested archive (no path separators, so no
    traversal), and the archive's bytes are then hashed directly with
    `sha256sum` and compared to the manifest's digest.

    Returns:
        Mapping of archive name to the digest the remote host computed
        for the uploaded archive bytes. Callers can use these digests to
        bind later local checks to the exact uploaded bytes.
    """
    sftp = client.open_sftp()
    try:
        digests: dict[str, str] = {}
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
            digests[name] = actual[name]
        return digests
    finally:
        sftp.close()


def extract_files(
    client: paramiko.SSHClient,
    config: Config,
    staging: str,
    ts: str,
    expected_digest: str,
) -> None:
    """Validate and extract the files archive into the site root.

    The archive's checksum was verified earlier (verify_remote_checksums)
    while the file was still a mutable pathname: a process running as
    the same SSH user could replace the staging archive afterwards, so
    tar would validate or extract bytes that were never covered by the
    returned digest. To keep the validated bytes the consumed bytes, the
    digest is re-derived and compared inside the SAME remote command
    that extracts: `sha256sum ... | cut ... | grep -qx <digest> && tar
    xzf ...` — extraction never starts unless the archive's bytes at
    that instant still match the digest this run verified.

    Member validation and the destination-tree audit still run first
    (they are checks, not consumption); the consuming extraction is the
    one bound to the verified digest, so a swap at any earlier point is
    caught before tar writes anything.

    Args:
        client: An active SSH client connected to the remote host.
        config: The backup configuration.
        staging: The remote staging directory holding the archive.
        ts: The backup identifier the archive name is derived from.
        expected_digest: The SHA-256 digest verify_remote_checksums()
            computed for the uploaded archive; extraction aborts unless
            the archive still has it.
    """
    name = files_archive_name(ts)
    writes = validate_members(posixpath.join(staging, name), client)
    audit_destination_tree(client, config.wp_site_root, writes)
    extract_verified_archive(
        client, staging, name, expected_digest, config.wp_site_root
    )


def import_database(
    client: paramiko.SSHClient,
    config: Config,
    staging: str,
    ts: str,
    expected_digest: str,
) -> None:
    """Import the database from the DB tarball in the staging dir.

    Like extract_files, the DB archive is revalidated (digest compared)
    inside the same remote command that extracts it, so a same-user
    process that replaced the staging archive after the earlier checksum
    verification cannot make tar extract bytes that were never covered
    by the returned digest.

    Args:
        client: An active SSH client connected to the remote host.
        config: The backup configuration.
        staging: The remote staging directory holding the archive.
        ts: The backup identifier the archive name is derived from.
        expected_digest: The SHA-256 digest verify_remote_checksums()
            computed for the uploaded DB archive; extraction aborts
            unless the archive still has it.
    """
    archive = posixpath.join(staging, db_archive_name(ts))
    dump_name = f"wp-db-{ts}.sql"
    dump_path = posixpath.join(staging, dump_name)
    wp_cli = detect_wp_cli(client, config)

    # The tarball is checksum-verified but its members are not trusted:
    # require exactly the expected regular SQL dump before tar runs.
    validate_db_members(archive, client, ts)

    # Extract the SQL dump from the tarball, revalidating the digest in
    # the same remote command that extracts.
    extract_verified_archive(
        client, staging, db_archive_name(ts), expected_digest, staging
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
        write_remote_file(client, sftp, cnf_path, cnf_body, mode=0o600)
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
    # -m 700 creates it owner-only in the mkdir itself, so a permissive
    # umask never leaves it writable by others before the later chmod.
    # The 0700 chmod is issued separately INSIDE the try block below:
    # chained 'mkdir && chmod' would orphan the directory if mkdir
    # succeeded but chmod failed, before the cleanup block was entered.
    code, _, err = run_remote_cmd(
        client,
        f"mkdir -m 700 {shquote(staging)}",
    )
    if code != 0:
        raise WPSSHBackupError(
            f"Could not create staging directory {staging}: "
            f"{err.strip() or 'already exists?'}"
        )
    print(f"Remote staging directory: {staging}")

    try:
        # Mode 0700 keeps other host users out of the directory that will
        # hold the database credentials file. If the chmod fails, the
        # handler below removes the directory this run just created.
        run_remote_cmd_checked(
            client, f"chmod 700 {shquote(staging)}"
        )

        # GNU tar is needed for archive validation; check before any
        # upload so an unsupported host fails fast and cleanly.
        require_gnu_tar(client)

        # Every local artifact is opened once through a no-follow
        # descriptor and held open until it has been validated and
        # uploaded, so a writer swapping a pathname for a symlink (or a
        # different file) after the initial open cannot make the restore
        # upload or validate different bytes than the ones it inspected.
        with safe_fs.held_local_files(
            [set_files[name] for name in archive_names]
            + [set_files[checksum_name(name)] for name in archive_names]
        ) as handles:
            with client.open_sftp() as sftp:
                upload_artifacts(
                    sftp, set_files, handles, archive_names, staging
                )
            remote_digests = verify_remote_checksums(
                client, staging, archive_names
            )
            print("Remote checksum verification passed.")

            if include_files:
                # Checked after checksum verification so a corrupt archive is
                # reported as a checksum failure, and before any extraction.
                # The digest returned here is computed over the exact bytes
                # the type check inspected; requiring it to equal the digest
                # the remote host computed for the uploaded archive binds the
                # type verdict to the uploaded bytes, so a pathname swapped
                # between upload and this check cannot smuggle a different
                # archive past the type validation.
                files_name = files_archive_name(backup_bid)
                local_digest = validate_local_member_types(
                    set_files[files_name], handles[set_files[files_name]]
                )
                if local_digest != remote_digests[files_name]:
                    raise ChecksumError(
                        "Local files archive changed after upload: the member "
                        "type check inspected different bytes than the "
                        "uploaded archive. Refusing to extract."
                    )
                started = _now()
                extract_files(
                    client,
                    config,
                    staging,
                    backup_bid,
                    expected_digest=remote_digests[files_name],
                )
                print(f"Files extracted ({_now() - started:.1f}s).")

            if include_database:
                started = _now()
                import_database(
                    client,
                    config,
                    staging,
                    backup_bid,
                    expected_digest=remote_digests[
                        db_archive_name(backup_bid)
                    ],
                )
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
        prog="restore.py",
        description="Restore a WordPress site from a WP SSH Backup set.",
    )
    add_version_argument(parser)
    parser.add_argument(
        "--timestamp",
        help="Backup set to restore: a full backup id (e.g. "
        "20261014T0930Z-a1b2c3) or a bare timestamp (e.g. 20261014T0930Z, "
        "which must match exactly one set). Defaults to the latest "
        "matching set.",
    )
    add_scope_arguments(
        parser,
        files_help="Restore only the WordPress files.",
        database_help="Restore only the WordPress database.",
        all_help="Restore both files and database (the default).",
    )
    args = parser.parse_args(argv)
    include_files, include_database = resolve_scope(args)

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
    except (WPSSHBackupError, OSError) as exc:
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
