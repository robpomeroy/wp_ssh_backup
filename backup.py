"""Backup a WordPress site over SSH.

Creates gzip tarballs of the WordPress database and/or site root on the remote
host, downloads them via SFTP, verifies SHA-256 checksums locally, removes the
remote staging directory and prunes old local backups.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Generator
import errno
import hashlib
import os
import posixpath
import stat
import sys
import time

import paramiko

from common import (
    ChecksumError,
    Config,
    MissingArtifactError,
    WPSSHBackupError,
    backup_id,
    checksum_name,
    connect,
    db_archive_name,
    detect_wp_cli,
    files_archive_name,
    human_size,
    load_config,
    mysql_client_config,
    parse_sha256sum_output,
    prune_local_backups,
    read_wp_db_settings,
    remove_remote_file,
    remove_remote_staging,
    run_remote_cmd,
    run_remote_cmd_checked,
    sha256_file,
    shquote,
    sftp_download,
    split_db_host,
    staging_dir_for,
    trap_rm_action,
    write_remote_file,
    verify_local_checksum,
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

    # trap guarantees the credentials file is removed even if mysqldump fails.
    command = (
        f"cd {shquote(staging)} && "
        f"trap {trap_rm_action(cnf_path)} EXIT && "
        f"mysqldump --defaults-extra-file={shquote(cnf_path)} "
        f"{shquote(settings['DB_NAME'])} > {shquote(dump_path)}"
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


def _discard_temp_downloads(created_paths: list[Path]) -> None:
    """Remove only owned temporary files without masking the original error."""
    for path in created_paths:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            print(
                f"WARNING: could not remove temporary download {path}: {exc}",
                file=sys.stderr,
            )


def download_artifacts(
    sftp: paramiko.SFTPClient,
    staging: str,
    archive_names: list[str],
    backup_dir: Path,
    *,
    created_paths: list[Path] | None = None,
) -> dict[str, Path]:
    """
    Download each archive and its .sha256 file into backup_dir.

    Files land under temporary names (the final name plus a ".part"
    suffix) so a failed or interrupted transfer can never be mistaken for
    a backup set: the suffix does not match the backup filename pattern,
    and publish_downloads() links the files under their final names only
    after checksum verification has passed.

    Args:
        sftp: An active SFTP client connected to the remote host.
        staging: The remote staging directory containing the archives.
        archive_names: A list of archive filenames to download.
        backup_dir: The local directory where the files will be stored.
        created_paths: If supplied, records files created by this run, even
            if a transfer fails before this function returns.

    Returns:
        A dictionary mapping each archive's final name (and its checksum
        filename) to the temporary local Path it was downloaded to.
    """
    local_paths: dict[str, Path] = {}
    for name in archive_names:
        local_paths[name] = sftp_download(
            sftp,
            posixpath.join(staging, name),
            backup_dir / _temp_download_name(name),
            created_paths=created_paths,
        )
        local_paths[checksum_name(name)] = sftp_download(
            sftp,
            posixpath.join(staging, checksum_name(name)),
            backup_dir / _temp_download_name(checksum_name(name)),
            created_paths=created_paths,
        )
    return local_paths


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
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        # A no-op for regular files, but stops a planted FIFO from
        # blocking the open forever on POSIX; the S_ISREG check below
        # rejects it.
        | getattr(os, "O_NONBLOCK", 0)
    )
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags | nofollow)
    except OSError as exc:
        # ELOOP from open() always means a symlink problem: either
        # O_NOFOLLOW rejected a symlinked leaf, or the path itself
        # contains a symlink loop. Translate it either way.
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise WPSSHBackupError(
                f"Refusing to publish through symlink: {path}"
            ) from exc
        if exc.errno == errno.ENOENT:
            raise MissingArtifactError(
                f"Downloaded file missing: {path}"
            ) from exc
        raise WPSSHBackupError(
            f"Refusing to publish {path.name}: cannot open local file: "
            f"{exc}"
        ) from exc


def _assert_nofollow_regular(fd: int, path: Path) -> None:
    """Reject a descriptor whose leaf was (or is) a symlink or non-file.

    On platforms without O_NOFOLLOW the open itself cannot detect a
    symlinked leaf, so the descriptor's identity is compared against the
    leaf's lstat(): a symlink resolves to the target's device/inode,
    which differs from the link's own. The caller owns the descriptor
    and closes it when this check rejects.
    """
    fd_stat = os.fstat(fd)
    if not stat.S_ISREG(fd_stat.st_mode):
        raise WPSSHBackupError(
            f"Refusing to publish {path.name}: not a regular file"
        )
    if not getattr(os, "O_NOFOLLOW", 0):
        leaf_stat = os.lstat(path)
        if (leaf_stat.st_dev, leaf_stat.st_ino) != (
            fd_stat.st_dev,
            fd_stat.st_ino,
        ):
            raise WPSSHBackupError(
                f"Refusing to publish through symlink: {path}"
            )


@contextmanager
def _held_temp_downloads(
    temp_paths: dict[str, Path],
    finals: list[str],
) -> Generator[dict[str, BinaryIO]]:
    """
    Open each temporary download once through a no-follow descriptor and
    hold it open for the whole context.

    Publication must read from the same opened file it links: a writer
    that swaps a .part pathname for a symlink (or replaces the file)
    after verification cannot make publication link different bytes
    than the ones that were verified.
    """
    handles: dict[str, BinaryIO] = {}
    try:
        for final in finals:
            path = temp_paths[final]
            fd = _open_nofollow_regular(path)
            try:
                _assert_nofollow_regular(fd, path)
                handles[final] = os.fdopen(fd, "rb")
            except BaseException:
                # fdopen took ownership only on success; after a failed
                # assertion the descriptor is still ours to close.
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
        yield handles
    finally:
        for handle in handles.values():
            handle.close()


def _publish_no_replace(
    handle: BinaryIO,
    temp_path: Path,
    final_path: Path,
) -> BinaryIO:
    """
    Publish the already-opened temp file at final_path, never replacing.

    The link is created from the held descriptor's inode, not from the
    pathname: a writer that swapped temp_path for a symlink after
    verification would otherwise have os.link() follow it and publish
    the target's unverified inode. The caller confirms that the created
    link references the held inode and re-verifies its digest.

    Uses os.link() so the publication either happens or fails with
    FileExistsError: there is no window in which another process can
    create final_path and have it silently overwritten. On filesystems
    without hard-link support (some Windows volumes), falls back to
    os.rename(), which on Windows also refuses to replace an existing
    destination; the descriptor is closed first because Windows refuses
    to rename an open file, and the renamed file is re-opened no-follow
    and re-identified so the fallback publishes the same inode that was
    verified.

    Returns:
        The descriptor-holding file object the published inode must be
        verified through: the held handle, or — on the rename fallback —
        a fresh handle for the renamed file.

    Raises:
        FileExistsError: If final_path already exists.
    """
    try:
        os.link(temp_path, final_path)
    except FileExistsError as exc:
        raise FileExistsError(
            f"Refusing to overwrite existing backup file: {final_path}"
        ) from exc
    except OSError:
        if os.name != "nt":
            raise
        return _publish_by_rename(handle, temp_path, final_path)
    return handle


def _publish_by_rename(
    handle: BinaryIO,
    temp_path: Path,
    final_path: Path,
) -> BinaryIO:
    """Rename fallback publishing an already-verified inode.

    Windows refuses to rename a file it holds open, so the held
    descriptor is closed first and the renamed file is re-opened
    no-follow and re-identified; the caller verifies the published
    inode through the returned handle. If the renamed file cannot be
    re-opened and identified, it is removed so no unverified file is
    left under a final name.
    """
    handle.close()
    try:
        os.rename(temp_path, final_path)
    except FileExistsError as exc:
        raise FileExistsError(
            f"Refusing to overwrite existing backup file: {final_path}"
        ) from exc
    try:
        fd = _open_nofollow_regular(final_path)
    except BaseException:
        try:
            final_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    try:
        _assert_nofollow_regular(fd, final_path)
        new_handle = os.fdopen(fd, "rb")
    except BaseException:
        # fdopen took ownership only on success; after a failed
        # assertion the descriptor is still ours to close.
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            final_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return new_handle


def _assert_published_inode(handle: BinaryIO, final_path: Path) -> None:
    """
    Reject a publication whose final path is not the verified inode.

    os.link() follows a symlink at the source path on some platforms,
    so the link is confirmed by comparing the final path's own directory
    entry (lstat) against the held descriptor's inode. A missing entry
    is rejected the same way: the published file is gone. The final path
    is already recorded for rollback, so a rejection removes the link
    after the held descriptors are closed — unless the entry was
    replaced, in which case it no longer references this run's inode and
    the replacement is left in place.
    """
    try:
        final_stat = os.lstat(final_path)
    except FileNotFoundError as exc:
        raise WPSSHBackupError(
            f"Refusing to publish {final_path}: the published file was "
            "replaced after verification"
        ) from exc
    fd_stat = os.fstat(handle.fileno())
    if (final_stat.st_dev, final_stat.st_ino) != (
        fd_stat.st_dev,
        fd_stat.st_ino,
    ):
        raise WPSSHBackupError(
            f"Refusing to publish {final_path}: the temporary download "
            "was replaced after verification"
        )


def _verify_published_inode(
    handle: BinaryIO,
    final_path: Path,
    expected_sha256: str,
) -> None:
    """
    Re-verify the published file through the held descriptor.

    A hard link shares the temporary file's inode, so bytes written to
    the .part path after verification would also change the published
    backup. Re-reading the digest from the descriptor at publication
    time binds the verified checksum to the inode that was linked.

    The digest alone cannot prove what the final name contains: the
    final directory entry can be unlinked and replaced while the digest
    is being re-read, leaving an attacker-controlled file at the
    published name while the verified inode's digest still passes. The
    entry is therefore re-checked against the held inode after hashing,
    so a replacement is rejected and the window left to a replacement
    ends at this check.
    """
    handle.seek(0)
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    actual = digest.hexdigest()
    if actual.lower() != expected_sha256.lower():
        raise ChecksumError(
            f"Published backup {final_path} changed after verification: "
            f"expected {expected_sha256}, got {actual}"
        )
    _assert_published_inode(handle, final_path)


def publish_downloads(
    temp_paths: dict[str, Path],
    archive_names: list[str],
    backup_dir: Path,
    digests: dict[str, str],
) -> dict[str, Path]:
    """
    Publish verified temporary downloads under their final names.

    Only called after verify_downloads() has accepted every file, so a
    file that reaches BACKUP_DIR under its final name is always a
    checksum-verified artifact.

    Every temporary download is opened once through a no-follow
    descriptor and held open across publication, so the bytes published
    are the bytes that were verified: a writer that swaps a .part path
    for a symlink (or replaces the file) after verification cannot make
    publication link different bytes than the ones that were verified.

    Publication is transactional and atomic: each final path is created
    with a no-replace operation from the held descriptor's inode (hard
    link, or a no-replace rename on filesystems without hard-link
    support), so a file that appears at a final name after the pre-check
    — from another backup process or a local attacker who can write
    BACKUP_DIR — can never be silently overwritten. The created link
    must reference the verified inode, and because a hard link shares
    that inode, the digest is re-verified through the held descriptor
    after linking: bytes written to a .part path between verification
    and publication would otherwise change the published backup too.
    The final directory entry can still be unlinked and replaced while
    the digest is re-read, so it is checked against the held inode once
    more after hashing; a replacement is rejected instead of being
    reported as a successful publication. If publication fails
    part-way, the final paths this run created are removed so the
    caller's cleanup can discard the still intact temporary downloads
    (a path that was replaced after publication no longer references
    this run's inode and is left in place with a warning). A failed run
    therefore never leaves a partial final-name set in BACKUP_DIR.

    Args:
        temp_paths: Mapping from final names to the temporary paths
            returned by download_artifacts().
        archive_names: The archive filenames that were downloaded.
        backup_dir: The local directory that receives the final names.
        digests: The digest each final name's bytes must still have at
            publication time, as returned by verify_downloads().

    Returns:
        A dictionary mapping each archive and its checksum filename to
        the final local Path object.

    Raises:
        FileExistsError: If any final path already exists, including one
            created between the pre-check and publication.
        WPSSHBackupError: If a temporary download is a symlink, the
            created link does not reference the verified inode, or the
            final path is replaced during publication.
        ChecksumError: If a published file's digest no longer matches
            the digest verify_downloads() captured.
    """
    finals: list[str] = []
    for name in archive_names:
        finals.extend((name, checksum_name(name)))

    # Pre-check: refuse to overwrite anything that already exists under
    # a final name (e.g. a file from another run) BEFORE publishing the
    # first file, so the common conflict case fails fast with a friendly
    # error and no half-done publication. This check alone is not the
    # guarantee — the no-replace publication below is: it fails if a
    # path appears here between the check and the publication. Symlinks
    # are rejected too, including dangling ones: Path.exists() is False
    # for a broken link, but publication would silently replace it,
    # breaking the preservation promise.
    for final in finals:
        final_path = backup_dir / final
        if final_path.exists() or final_path.is_symlink():
            raise FileExistsError(
                f"Refusing to overwrite existing backup file: {final_path}"
            )

    published: list[tuple[Path, tuple[int, int]]] = []
    try:
        with _held_temp_downloads(temp_paths, finals) as handles:
            for final in finals:
                final_path = backup_dir / final
                # Record the held inode before publication: it is the
                # inode this run verified and intends to publish, and
                # rollback must recognize it even when publication
                # linked a replacement instead.
                fd_stat = os.fstat(handles[final].fileno())
                identity = (fd_stat.st_dev, fd_stat.st_ino)
                published_handle = _publish_no_replace(
                    handles[final], temp_paths[final], final_path
                )
                handles[final] = published_handle
                published.append((final_path, identity))
                _assert_published_inode(published_handle, final_path)
                _verify_published_inode(
                    published_handle, final_path, digests[final]
                )
    except BaseException:
        # Roll back the final paths this run created. They were made by
        # this run's no-replace publications, so unlinking them can
        # never remove a pre-existing file. A path that was unlinked and
        # replaced after publication no longer references this run's
        # inode; the replacement is left in place with a warning rather
        # than unlinking a file this run did not create. The temporary
        # downloads were not unlinked, so the caller's
        # _discard_temp_downloads() cleanup — which must never touch
        # final paths it did not create — discards them.
        for final_path, identity in reversed(published):
            try:
                final_stat = os.lstat(final_path)
            except FileNotFoundError:
                continue
            except OSError as exc:
                print(
                    "WARNING: could not roll back published backup file "
                    f"{final_path}: {exc}",
                    file=sys.stderr,
                )
                continue
            if (final_stat.st_dev, final_stat.st_ino) != identity:
                print(
                    "WARNING: published backup file "
                    f"{final_path} was replaced during publication; "
                    "leaving the replacement in place",
                    file=sys.stderr,
                )
                continue
            try:
                final_path.unlink(missing_ok=True)
            except OSError as exc:
                print(
                    "WARNING: could not roll back published backup file "
                    f"{final_path}: {exc}",
                    file=sys.stderr,
                )
        raise
    # Publication succeeded: remove the temporary downloads. A leftover
    # temp is only a warning — the finals are complete and verified, so
    # publication is not undone over a cleanup failure.
    for final in finals:
        temp_path = temp_paths[final]
        try:
            temp_path.unlink(missing_ok=True)
        except OSError as exc:
            print(
                f"WARNING: could not remove temporary download {temp_path}: "
                f"{exc}",
                file=sys.stderr,
            )
    return {final: backup_dir / final for final in finals}


def verify_downloads(
    local_paths: dict[str, Path],
    archive_names: list[str],
) -> dict[str, str]:
    """
    Recompute SHA-256 locally using the downloaded .sha256 files.

    Args:
        local_paths: A dictionary mapping each archive and its checksum
            filename to the corresponding local Path object.
        archive_names: A list of archive filenames to verify.

    Returns:
        A dictionary mapping each final name to the digest its bytes
        must still have at publication time: each archive is bound to
        the digest its manifest records, and each checksum file to its
        own digest at verification time, so publish_downloads() can
        re-verify every published file against the bytes that were
        verified here.
    """
    digests: dict[str, str] = {}
    for name in archive_names:
        local_path = local_paths[name]
        if not local_path.is_file():
            raise MissingArtifactError(
                f"Downloaded file missing: {local_path}"
            )
        checksum_file = local_paths[checksum_name(name)]
        try:
            text = checksum_file.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            # An undecodable manifest is a checksum failure, not a crash:
            # raising ChecksumError keeps the remote staging dir for retry
            # and reports the problem through the normal error path.
            raise ChecksumError(
                f"{checksum_file} is not valid UTF-8 and cannot be parsed "
                f"as a checksum manifest: {exc}"
            ) from exc
        parsed = parse_sha256sum_output(text)
        if name not in parsed:
            raise ChecksumError(
                f"{checksum_file} contains no digest for {name}"
            )
        verify_local_checksum(local_path, parsed[name])
        digests[name] = parsed[name]
        digests[checksum_name(name)] = sha256_file(checksum_file)
    return digests


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def create_staging_dir(
    client: paramiko.SSHClient, config: Config, bid: str
) -> str:
    """
    Create this run's exclusive remote staging directory.

    Uses a bare mkdir (no -p) so the command fails if the directory already
    exists: two concurrent runs in the same minute have different backup ids
    and therefore different directories, and a collision (astronomically
    unlikely) aborts instead of sharing artifacts.

    The directory is created with -m 700 so a permissive umask (e.g. a
    shared-group 0002) never leaves it writable by other accounts between
    creation and the later 0700 chmod.

    The 0700 chmod is issued separately by the caller (inside its cleanup
    scope): mkdir and chmod chained with && would leave an orphaned
    directory on the host if mkdir succeeded but chmod failed, before
    run_backup's cleanup block was entered.

    Args:
        client: An active SSH client connected to the remote host.
        config: The backup configuration.
        bid: This run's backup identifier.

    Returns:
        The staging directory path.

    Raises:
        WPSSHBackupError: If the staging directory already exists.
    """
    staging = staging_dir_for(config.wp_site_root, bid)
    code, _, err = run_remote_cmd(
        client, f"mkdir -m 700 {shquote(staging)}"
    )
    if code != 0:
        raise WPSSHBackupError(
            f"Could not create staging directory {staging}: "
            f"{err.strip() or 'already exists?'}"
        )
    return staging


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
    staging = create_staging_dir(client, config, bid)
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
            started = time.monotonic()
            db_archive = create_db_dump(client, config, staging, bid)
            archive_names.append(db_archive)
            elapsed = time.monotonic() - started
            print(f"Database archive created ({elapsed:.1f}s)")

        if include_files:
            started = time.monotonic()
            files_archive = create_files_archive(client, config, staging, bid)
            archive_names.append(files_archive)
            elapsed = time.monotonic() - started
            print(f"Files archive created ({elapsed:.1f}s)")

        generate_remote_checksums(client, staging, archive_names)

        # Download under temporary names and publish only verified files:
        # a bad pair left in BACKUP_DIR under its final name would be
        # advertised by find_backup_sets() as a complete set, and a
        # default restore could then select the corrupt newest backup
        # instead of a valid older one.
        published = False
        created_paths: list[Path] = []
        try:
            with client.open_sftp() as sftp:
                temp_paths = download_artifacts(
                    sftp, staging, archive_names, backup_dir,
                    created_paths=created_paths,
                )
            digests = verify_downloads(temp_paths, archive_names)
            local_paths = publish_downloads(
                temp_paths, archive_names, backup_dir, digests
            )
            published = True
        finally:
            if not published:
                # Remove every file this run downloaded, whether the
                # failure was a checksum mismatch or a dropped transfer.
                # The remote staging decision is made by the handlers
                # below (kept for a checksum retry, removed otherwise).
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
    except (
        WPSSHBackupError,
        OSError,
        paramiko.SSHException,
    ):
        # Any other failure — including base WPSSHBackupError raised by, for
        # example, an invalid WP_CLI_PATH — must not leave staging behind.
        # ChecksumError is handled above and keeps staging for retry.
        remove_remote_staging(client, staging)
        raise

    remove_remote_staging(client, staging)
    return local_paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Back up a WordPress site over SSH."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--files",
        action="store_true",
        help="Back up only the WordPress files.",
    )
    group.add_argument(
        "--database",
        action="store_true",
        help="Back up only the WordPress database.",
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="Back up both files and database (the default).",
    )
    args = parser.parse_args(argv)

    neither = not (args.files or args.database)
    include_files = args.files or args.all or neither
    include_database = args.database or args.all or neither

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
