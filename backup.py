"""Backup a WordPress site over SSH.

Creates gzip tarballs of the WordPress database and/or site root on the remote
host, downloads them via SFTP, verifies SHA-256 checksums locally, removes the
remote staging directory and prunes old local backups.
This module is the orchestration layer: it creates the remote artifacts and
drives the download, verification and publication. The mechanics live in
publish.py (publishing verified downloads), publish_lock.py (the publication
lock), safe_fs.py (local-filesystem primitives) and common.py (the shared
low-level layer)."""

from __future__ import annotations

import argparse
import hashlib
import os
import posixpath
import sys
from pathlib import Path
from typing import BinaryIO

import paramiko

from cli import add_scope_arguments, add_version_argument, resolve_scope
import safe_fs
from publish import publish_downloads
from common import (
    REMOTE_FAILURES,
    ChecksumError,
    Config,
    WPSSHBackupError,
    backup_id,
    checksum_name,
    connect,
    create_staging_dir,
    db_archive_name,
    detect_wp_cli,
    files_archive_name,
    human_size,
    load_config,
    parse_sha256sum_output,
    prune_local_backups,
    remove_remote_file,
    remove_remote_staging,
    run_remote_cmd_checked,
    shquote,
    sftp_download,
    timed,
    trap_rm_action,
    validate_manifest_entries,
    write_mysql_client_config,
)


# ---------------------------------------------------------------------------
# Remote artifact creation
# ---------------------------------------------------------------------------


def tar_db_dump(
    client: paramiko.SSHClient,
    staging: str,
    dump_name: str,
    ts: str,
) -> str:
    """
    Tar the SQL dump in the staging dir; return the tarball filename.

    Args:
        client: An active SSH client connected to the remote host.
        staging: The remote staging directory containing the SQL dump.
        dump_name: The filename of the SQL dump within the staging directory.
        ts: A timestamp string used to generate the archive name.

    Returns:
        The filename of the created tarball.
    """
    archive_name = db_archive_name(ts)
    archive_path = posixpath.join(staging, archive_name)
    tar_command = (
        f"tar czf {shquote(archive_path)} -C {shquote(staging)} "
        f"{shquote(dump_name)}"
    )
    run_remote_cmd_checked(client, tar_command, timeout=1800)
    return archive_name


def create_db_dump(
    client: paramiko.SSHClient,
    config: Config,
    staging: str,
    ts: str,
) -> str:
    """
    Create a tarball of a SQL dump in the staging dir.

    Args:
        client: An active SSH client connected to the remote host.
        config: The configuration object containing site and database details.
        staging: The remote staging directory where the SQL dump will be
            created.
        ts: A timestamp string used to generate the archive name.

    Returns:
        The filename of the created tarball.
    """
    dump_name = f"wp-db-{ts}.sql"
    dump_path = posixpath.join(staging, dump_name)
    wp_cli = detect_wp_cli(client, config)

    if wp_cli:
        command = (
            f"cd {shquote(config.wp_site_root)} && "
            f"{shquote(wp_cli)} db export {shquote(dump_path)} "
            f"--add-drop-table"
        )
        run_remote_cmd_checked(client, command, timeout=1800)
        return tar_db_dump(client, staging, dump_name, ts)

    # Fallback: parse wp-config.php and run mysqldump with a temporary
    # defaults-extra-file so the password never appears on a command line.
    cnf_path, db_name = write_mysql_client_config(
        client, config.wp_site_root, staging, ts
    )

    # trap guarantees the credentials file is removed even if mysqldump fails.
    command = (
        f"cd {shquote(staging)} && "
        f"trap {trap_rm_action(cnf_path)} EXIT && "
        f"mysqldump --defaults-extra-file={shquote(cnf_path)} "
        f"{shquote(db_name)} > {shquote(dump_path)}"
    )
    try:
        run_remote_cmd_checked(client, command, timeout=1800)
    finally:
        # Belt and braces: remove the cnf even if the shell above died
        # oddly. Best-effort: if the connection dropped, the removal must
        # not mask the original mysqldump failure.
        remove_remote_file(client, cnf_path)

    return tar_db_dump(client, staging, dump_name, ts)


def create_files_archive(
    client: paramiko.SSHClient,
    config: Config,
    staging: str,
    ts: str,
) -> str:
    """
    Create a tarball of the site root in the staging dir.

    Args:
        client: An active SSH client connected to the remote host.
        config: The configuration object containing site and database details.
        staging: The remote staging directory where the tarball will be
            created.
        ts: A timestamp string used to generate the archive name.

    Returns:
        The filename of the created tarball.
    """
    archive_name = files_archive_name(ts)
    archive_path = posixpath.join(staging, archive_name)
    # The staging dir is a sibling of the site root, so it is never included
    # in a tar of the site root's contents; only cache dirs need excluding.
    # GNU tar treats options after the member operand as positional: they
    # have no effect and it exits with status 2, so --exclude must come
    # before the "." member.
    command = (
        f"tar czf {shquote(archive_path)} "
        f"--exclude=./wp-content/cache "
        f"-C {shquote(config.wp_site_root)} ."
    )
    run_remote_cmd_checked(client, command, timeout=3600)
    return archive_name


def generate_remote_checksums(
    client: paramiko.SSHClient,
    staging: str,
    archive_names: list[str],
) -> None:
    """
    Write a .sha256 file next to each archive on the remote host.

    Args:
        client: An active SSH client connected to the remote host.
        staging: The remote staging directory containing the archives.
        archive_names: A list of archive filenames for which to generate
            checksums.

    Returns:
        None. The function writes .sha256 files next to each archive on the
        remote host.
    """
    for name in archive_names:
        command = (
            f"cd {shquote(staging)} && "
            f"sha256sum {shquote(name)} > {shquote(checksum_name(name))}"
        )
        run_remote_cmd_checked(client, command)


# ---------------------------------------------------------------------------
# Download and verification
# ---------------------------------------------------------------------------


def _temp_download_name(name: str) -> str:
    """Temporary name used until a download has been verified."""
    return name + ".part"


def _discard_temp_downloads(
    created_paths: list[tuple[Path, tuple[int, int]]],
) -> None:
    """Remove only owned temporary files without masking the original error.

    Each entry records the (st_dev, st_ino) of the inode this run
    created. The path is unlinked only while it still refers to that
    inode: a concurrent writer who replaced the .part pathname (after a
    download or a transfer failure) planted a different inode, and
    removing it would delete another run's file. A replaced path is left
    in place with a warning. The check and the unlink are atomic: the
    path is first renamed to a unique quarantine name only this process
    knows, so a concurrent writer cannot swap the pathname between the
    identity check and the unlink (see _unlink_if_same_inode_atomic).
    """
    for path, identity in created_paths:
        safe_fs.unlink_if_same_inode_atomic(path, identity)


def download_artifacts(
    sftp: paramiko.SFTPClient,
    staging: str,
    archive_names: list[str],
    backup_dir: Path,
    *,
    created_paths: list[tuple[Path, tuple[int, int]]] | None = None,
) -> tuple[dict[str, Path], dict[Path, int]]:
    """
    Download each archive and its .sha256 file into backup_dir.

    Files land under temporary names (the final name plus a ".part"
    suffix) so a failed or interrupted transfer can never be mistaken for
    a backup set: the suffix does not match the backup filename pattern,
    and publish_downloads() links the files under their final names only
    after checksum verification has passed.

    The descriptor each download wrote through is handed to the caller,
    so verification hashes and publication links the very inode the
    transfer created. A writer who can modify BACKUP_DIR cannot
    substitute a self-consistent (archive, manifest) pair after the
    transfer: hashing and linking the held descriptors (never re-opening
    the .part pathnames) binds the checksum to the downloaded bytes. The
    caller owns every descriptor in the returned mapping and must close
    them.

    Args:
        sftp: An active SFTP client connected to the remote host.
        staging: The remote staging directory containing the archives.
        archive_names: A list of archive filenames to download.
        backup_dir: The local directory where the files will be stored.
        created_paths: If supplied, records (path, (st_dev, st_ino)) of
            files created by this run, even if a transfer fails before
            this function returns, so cleanup can remove a path only
            while it still refers to this run's inode.

    Returns:
        A tuple of (temp_paths, downloaded_fds): temp_paths maps each
        archive's final name (and its checksum filename) to the local
        .part Path it was downloaded to; downloaded_fds maps each of
        those paths to the open descriptor of the inode the download
        created. The caller takes ownership of every descriptor and must
        close it after verification and publication.
    """
    local_paths: dict[str, Path] = {}
    downloaded_fds: dict[Path, int] = {}
    try:
        for name in archive_names:
            local_paths[name] = sftp_download(
                sftp,
                posixpath.join(staging, name),
                backup_dir / _temp_download_name(name),
                created_paths=created_paths,
                downloaded_fds=downloaded_fds,
            )
            local_paths[checksum_name(name)] = sftp_download(
                sftp,
                posixpath.join(staging, checksum_name(name)),
                backup_dir / _temp_download_name(checksum_name(name)),
                created_paths=created_paths,
                downloaded_fds=downloaded_fds,
            )
    except BaseException:
        # A later transfer failed; close the descriptors already handed
        # over so the caller's _discard_temp_downloads() can unlink the
        # .part files even on platforms that refuse to unlink a file
        # held open (Windows). The unlinked path cleanup is the
        # caller's job via created_paths.
        for fd in downloaded_fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    return local_paths, downloaded_fds


def _open_nofollow_regular(path: Path) -> int:
    """
    Open a local file through a descriptor that cannot follow a symlink
    at the final path component.

    On POSIX, O_NOFOLLOW makes the open fail with ELOOP when the leaf is
    a symlink. Windows has no O_NOFOLLOW, so the descriptor is opened
    and then compared against lstat(): a symlink leaf resolves to a
    different device/inode pair than the link itself, and the mismatch
    is rejected the same way. The descriptor is also required to be a
    regular file, so a directory or any other non-regular object is
    rejected.

    Raises:
        MissingArtifactError: If the path does not exist.
        WPSSHBackupError: If the leaf is a symlink or not a regular
            file.
    """
    return safe_fs.open_nofollow_regular(
        path,
        verb="publish",
        missing_message=f"Downloaded file missing: {path}",
    )


def _assert_nofollow_regular(fd: int, path: Path) -> None:
    """Reject a descriptor whose leaf was (or is) a symlink or non-file.

    On platforms without O_NOFOLLOW the open itself cannot detect a
    symlinked leaf, so the descriptor's identity is compared against the
    leaf's lstat(): a symlink resolves to the target's device/inode,
    which differs from the link's own. The caller owns the descriptor
    and closes it when this check rejects.
    """
    safe_fs.assert_nofollow_regular(fd, path)


def _sha256_handle(handle: BinaryIO) -> str:
    """SHA-256 of the opened file's bytes, from the current position."""
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def verify_downloads(
    local_paths: dict[str, Path],
    archive_names: list[str],
    downloaded_fds: dict[Path, int],
) -> dict[str, str]:
    """
    Recompute SHA-256 locally using the downloaded .sha256 files.

    Verification is bound to the inodes sftp_download() created: the
    descriptors handed over by the download are hashed directly, never
    re-opened through a pathname. A writer who can modify BACKUP_DIR
    cannot substitute a self-consistent (archive, manifest) pair after
    the download — the pair is a different inode, so hashing the held
    descriptors verifies the bytes the transfer wrote, not whatever a
    replaced .part pathname now points at. The manifest is parsed and
    the digests are computed through the held descriptors.

    Args:
        local_paths: A dictionary mapping each archive and its checksum
            filename to the corresponding local Path object.
        archive_names: A list of archive filenames to verify.
        downloaded_fds: The open descriptors of the .part files
            returned by download_artifacts(), keyed by their Paths.
            They are kept open after verification so publication can
            reuse the same inode-bound descriptors; the caller (or the
            final publication) closes them.

    Returns:
        A dictionary mapping each final name to the digest its bytes
        must still have at publication time: each archive is bound to
        the digest its manifest records, and each checksum file to its
        own digest at verification time, so publish_downloads() can
        re-verify every published file against the bytes that were
        verified here.
    """
    digests: dict[str, str] = {}
    finals: list[str] = []
    for name in archive_names:
        finals.extend((name, checksum_name(name)))
    with safe_fs.held_temp_downloads(
        local_paths, finals, downloaded_fds, close_on_exit=False
    ) as handles:
        for name in archive_names:
            local_path = local_paths[name]
            checksum_file = local_paths[checksum_name(name)]
            # The manifest is decoded from the held descriptor's bytes:
            # the same inode publication will trust, never a re-opened
            # path that may have been swapped since verification began.
            manifest_handle = handles[checksum_name(name)]
            manifest_handle.seek(0)
            try:
                text = manifest_handle.read().decode("utf-8")
            except UnicodeDecodeError as exc:
                # An undecodable manifest is a checksum failure, not a
                # crash: raising ChecksumError keeps the remote staging
                # dir for retry and reports the problem through the
                # normal error path.
                raise ChecksumError(
                    f"{checksum_file} is not valid UTF-8 and cannot be "
                    f"parsed as a checksum manifest: {exc}"
                ) from exc
            parsed = parse_sha256sum_output(text)
            # The manifest must contain exactly one entry naming exactly
            # the requested archive, matching verify_remote_checksums():
            # a manifest with the valid entry plus arbitrary extras would
            # be accepted here and published as a complete backup set,
            # only to be rejected later by restore's remote verifier.
            expected = validate_manifest_entries(
                parsed, name, checksum_file.name
            )
            archive_handle = handles[name]
            archive_handle.seek(0)
            actual = _sha256_handle(archive_handle)
            if actual.lower() != expected.lower():
                raise ChecksumError(
                    f"Checksum mismatch for {local_path}: expected "
                    f"{expected}, got {actual}"
                )
            digests[name] = expected
            manifest_handle.seek(0)
            digests[checksum_name(name)] = _sha256_handle(manifest_handle)
    return digests


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_backup(
    client: paramiko.SSHClient,
    config: Config,
    include_files: bool,
    include_database: bool,
    bid: str,
) -> dict[str, Path]:
    """
    Run the full backup flow; return local artifact paths by name.

    Args:
        client: An active SSH client connected to the remote host.
        config: The backup configuration.
        include_files: Whether to include the WordPress files in the backup.
        include_database: Whether to include the WordPress database in the
            backup.
        bid: This run's unique backup identifier.

    Returns:
        A dictionary mapping each archive and its checksum filename to the
        corresponding local Path object.
    """
    staging = create_staging_dir(client, config.wp_site_root, bid)
    backup_dir = config.backup_dir
    print(f"Remote staging directory: {staging}")

    archive_names: list[str] = []
    try:
        # Mode 0700 keeps other host users out of the directory that will
        # hold the database credentials file and the archives. It runs
        # INSIDE the cleanup block: if it fails, the directory this run
        # just created is removed instead of being orphaned on the host.
        run_remote_cmd_checked(
            client, f"chmod 700 {shquote(staging)}"
        )

        if include_database:
            with timed("Database archive created"):
                db_archive = create_db_dump(client, config, staging, bid)
            archive_names.append(db_archive)

        if include_files:
            with timed("Files archive created"):
                files_archive = create_files_archive(
                    client, config, staging, bid
                )
            archive_names.append(files_archive)

        generate_remote_checksums(client, staging, archive_names)

        # Download under temporary names and publish only verified files:
        # a bad pair left in BACKUP_DIR under its final name would be
        # advertised by find_backup_sets() as a complete set, and a
        # default restore could then select the corrupt newest backup
        # instead of a valid older one.
        published = False
        created_paths: list[tuple[Path, tuple[int, int]]] = []
        downloaded_fds: dict[Path, int] = {}
        try:
            with client.open_sftp() as sftp:
                temp_paths, downloaded_fds = download_artifacts(
                    sftp, staging, archive_names, backup_dir,
                    created_paths=created_paths,
                )
            digests = verify_downloads(
                temp_paths, archive_names, downloaded_fds
            )
            local_paths = publish_downloads(
                temp_paths, archive_names, backup_dir, digests,
                downloaded_fds,
            )
            published = True
        finally:
            if not published:
                # Close the download descriptors first (a failure before
                # or inside verify/publish leaves them open; closing is
                # idempotent). Then remove every file this run
                # downloaded, whether the failure was a checksum
                # mismatch or a dropped transfer. The remote staging
                # decision is made by the handlers below (kept for a
                # checksum retry, removed otherwise). Closing first lets
                # _discard_temp_downloads() unlink the .part files even
                # on platforms that refuse to unlink a file held open.
                for fd in downloaded_fds.values():
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                _discard_temp_downloads(created_paths)
        print("Local checksum verification passed.")
    except ChecksumError:
        # Keep the remote staging dir so the transfer can be retried.
        print(
            "ERROR: checksum verification failed. The remote staging "
            f"directory {staging} has been kept for retry.",
            file=sys.stderr,
        )
        raise
    except REMOTE_FAILURES:
        # Any other failure — including base WPSSHBackupError raised by, for
        # example, an invalid WP_CLI_PATH — must not leave staging behind.
        # ChecksumError is handled above and keeps staging for retry.
        remove_remote_staging(client, staging)
        raise

    remove_remote_staging(client, staging)
    return local_paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="backup.py",
        description="Back up a WordPress site over SSH.",
    )
    add_version_argument(parser)
    add_scope_arguments(
        parser,
        files_help="Back up only the WordPress files.",
        database_help="Back up only the WordPress database.",
        all_help="Back up both files and database (the default).",
    )
    args = parser.parse_args(argv)
    include_files, include_database = resolve_scope(args)

    try:
        config = load_config()
        bid = backup_id()
        client = connect(config)
    except WPSSHBackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        local_paths = run_backup(
            client, config, include_files, include_database, bid
        )
    except (WPSSHBackupError, OSError, paramiko.SSHException) as exc:
        # run_backup cleans up staging and re-raises transport/SFTP failures;
        # report them here rather than letting them escape as a traceback.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()

    try:
        removed = prune_local_backups(config.backup_dir, config.retention_days)
        if removed:
            print(f"Pruned local backup sets: {', '.join(removed)}")

        total = sum(p.stat().st_size for p in local_paths.values())
    except OSError as exc:
        print(
            f"ERROR: Backup {bid} was downloaded and verified in "
            f"{config.backup_dir}, but local post-processing failed: {exc}",
            file=sys.stderr,
        )
        return 1
    print(f"Backup complete: {bid} ({human_size(total)} downloaded).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
