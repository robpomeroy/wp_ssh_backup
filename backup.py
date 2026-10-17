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
import ctypes
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
    shquote,
    sftp_download,
    split_db_host,
    staging_dir_for,
    trap_rm_action,
    write_remote_file,
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
        _unlink_if_same_inode_atomic(path, identity)


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
    downloaded_fds: dict[Path, int],
    *,
    close_on_exit: bool = True,
) -> Generator[dict[str, BinaryIO]]:
    """
    Wrap the descriptors handed over by the download as held file handles.

    Verification and publication consume the very descriptors the
    download wrote through, never re-open the .part pathnames: a writer
    who swaps a .part path for a symlink (or replaces the file) cannot
    make verification hash or publication link different bytes than the
    ones the download created. On POSIX publication links the held
    inode itself through linkat(AT_EMPTY_PATH) directly from this
    descriptor; on Windows the held descriptor prevents the pathname
    from being replaced.

    Each descriptor is wrapped in a file object positioned at the start.
    Ownership of every descriptor is transferred here: the caller must
    not close them elsewhere. On exit the handles are closed unless
    close_on_exit is False, in which case the descriptors stay open for
    a later consumer (verification keeps them open so publication can
    reuse the same inode-bound descriptors).
    """
    handles: dict[str, BinaryIO] = {}
    wrapped: list[BinaryIO] = []
    try:
        for final in finals:
            path = temp_paths[final]
            fd = downloaded_fds[path]
            # closefd=False: the handle reads the caller's descriptor
            # but does not own it, so wrapping cannot close the fd out
            # from under a later consumer (verify keeps the same
            # descriptors open for publication).
            handle = os.fdopen(fd, "rb", closefd=False)
            wrapped.append(handle)
            handle.seek(0)
            handles[final] = handle
        yield handles
    finally:
        if close_on_exit:
            for handle in wrapped:
                # The rename fallback (_publish_by_rename) closes the
                # handle it consumed, so only close handles that are
                # still open.
                try:
                    fd = handle.fileno()
                except ValueError:
                    continue
                handle.close()
                try:
                    os.close(fd)
                except OSError:
                    pass


def _link_inode_no_replace(link_fd: int, final_path: Path) -> None:
    """
    Create final_path as a hard link to the inode referenced by link_fd.

    The link is created from the descriptor itself (linkat() with
    AT_EMPTY_PATH), not from a pathname: a writer who can modify
    BACKUP_DIR cannot make publication link a different inode than the
    one the caller verified, even by replacing the .part pathname
    between verification and publication. The operation is no-replace:
    if final_path already exists (or appears before the link), it fails
    with FileExistsError instead of overwriting.

    On POSIX, link_fd may be any descriptor referencing the file whose
    inode is to be published (the download's own O_RDWR descriptor
    works). AT_EMPTY_PATH requires the fd to reference a file the caller
    can read; it needs no privileges. Not available on Windows; callers
    there must use the rename fallback (_publish_by_rename) instead.

    Raises:
        FileExistsError: If final_path already exists.
        NotImplementedError: On platforms without linkat()/AT_EMPTY_PATH.
        OSError: If the link cannot be created for any other reason.
    """
    if os.name != "posix":
        raise NotImplementedError(
            "inode-based publication is not available on this platform"
        )
    libc = _linkat_libc()
    final_bytes = os.fsencode(str(final_path))
    rc = libc.linkat(
        link_fd,
        b"",
        _AT_FDCWD,
        final_bytes,
        _AT_EMPTY_PATH,
    )
    if rc != 0:
        err = ctypes.get_errno()
        if err == errno.EEXIST:
            raise FileExistsError(
                f"Refusing to overwrite existing backup file: {final_path}"
            )
        raise OSError(err, os.strerror(err), str(final_path))


# linkat() and its flags: Python does not expose AT_EMPTY_PATH, so the
# libc call is wrapped here. Loaded lazily and cached: the return value
# is a plain ctypes function object that stays valid for the process
# lifetime.
_AT_FDCWD = -100
_AT_EMPTY_PATH = 0x1000
_linkat_cache: ctypes.CDLL | None = None


def _linkat_libc() -> ctypes.CDLL:
    global _linkat_cache
    if _linkat_cache is None:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.linkat.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        libc.linkat.restype = ctypes.c_int
        _linkat_cache = libc
    return _linkat_cache


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

    On POSIX the hard link is created by linking the held descriptor's
    inode itself (linkat with AT_EMPTY_PATH on the O_RDWR descriptor the
    download handed over) — the source-inode binding and the no-replace
    creation are one atomic operation: a writer who can modify
    BACKUP_DIR cannot make publication link a replacement inode, even by
    swapping the .part pathname after verification. linkat(AT_EMPTY_PATH)
    is Linux-specific: on macOS/BSD and on filesystems or kernels that
    reject the flag (EINVAL, ENOTSUP, EOPNOTSUPP, ENOSYS, or a
    permission error from a filesystem that refuses it), publication
    falls back to _publish_by_rename, which on POSIX creates the final
    entry with an atomic no-replace hard link (os.rename would silently
    replace a destination that appeared after the pre-check) and
    re-opens it no-follow and re-identifies it so the fallback publishes
    the same inode that was verified. On Windows, os.link() by pathname
    is used: the held descriptor (the download's own O_RDWR fd on the
    inode it wrote) prevents the .part pathname from being unlinked or
    replaced while it is held, so linking the pathname cannot publish a
    different inode than the one verified; on volumes without hard-link
    support this also falls back to the no-replace rename.

    Returns:
        The descriptor-holding file object the published inode must be
        verified through: the held handle, or — on the rename fallback —
        a fresh handle for the renamed file.

    Raises:
        FileExistsError: If final_path already exists.
    """
    if os.name == "posix":
        # POSIX path: link the held inode itself, not the pathname.
        # linkat(AT_EMPTY_PATH) publishes exactly the inode the held
        # download descriptor references even if the .part pathname was
        # replaced after verification, and fails with FileExistsError if
        # the final path already exists (no-replace).
        try:
            _link_inode_no_replace(handle.fileno(), final_path)
        except FileExistsError:
            raise
        except OSError as exc:
            # linkat(AT_EMPTY_PATH) is Linux-specific: macOS/BSD reject
            # the flag with EINVAL, and some filesystems/kernels return
            # ENOTSUP/EOPNOTSUPP/ENOSYS (or EPERM/EACCES when the
            # operation is refused). Fall back to the no-replace rename,
            # which is portable and re-identifies the published inode.
            # Any other error (e.g. ENOENT from a nameless inode on
            # tmpfs) is a genuine failure and must propagate.
            if exc.errno in (
                errno.EINVAL,
                errno.ENOTSUP,
                errno.EOPNOTSUPP,
                errno.ENOSYS,
                errno.EPERM,
                errno.EACCES,
            ):
                return _publish_by_rename(handle, temp_path, final_path)
            raise
        return handle

    # Windows path: link by pathname. The held descriptor (the
    # download's own O_RDWR fd on the inode it wrote) prevents the .part
    # pathname from being unlinked or replaced while it is held, so
    # linking the pathname cannot publish a different inode than the one
    # verified. os.link() keeps the temporary file in place; a later
    # rollback removes only the final links this run created.
    try:
        os.link(temp_path, final_path)
    except FileExistsError as exc:
        raise FileExistsError(
            f"Refusing to overwrite existing backup file: {final_path}"
        ) from exc
    except OSError:
        # Hard links unsupported (some Windows volumes): fall back to
        # rename, which also refuses to replace an existing destination.
        # The descriptor is closed first because Windows refuses to
        # rename an open file; the renamed file is re-opened no-follow
        # and re-identified so the fallback publishes the same inode
        # that was verified.
        return _publish_by_rename(handle, temp_path, final_path)
    return handle


_quarantine_counter = 0


def _quarantine_name(path: Path) -> Path:
    """A unique same-directory name only this process knows.

    The name is generated in the same directory as path so the rename
    below is atomic (same filesystem), and it is never guessable by a
    concurrent writer: only the cleaner knows it, so a later
    lstat/compare/unlink on the quarantine name cannot be raced by a
    writer swapping the original pathname.
    """
    global _quarantine_counter
    _quarantine_counter += 1
    return path.with_name(
        f".{path.name}.quarantine-{os.getpid()}-{_quarantine_counter}"
    )


def _unlink_if_same_inode_atomic(
    path: Path,
    identity: tuple[int, int] | None,
    *,
    warn: bool = True,
    what: str = "temporary download",
    check_error_message: str = "could not check {what} {path}: {exc}",
    remove_error_message: str = "could not remove {what} {path}: {exc}",
    replaced_message: str = (
        "{what} {path} was replaced by another file; leaving it in place"
    ),
) -> None:
    """Remove path only while it still references identity; else leave it.

    The check-then-unlink sequence is made atomic by first renaming the
    path to a unique quarantine name only this process knows: the
    rename claims whatever is currently at path in one atomic step, so
    a concurrent writer can no longer swap the pathname between the
    identity check and the unlink. The quarantined inode is then
    compared against identity and unlinked only on a match; a
    replacement (a different inode) is restored to path with a
    no-replace hard link (best-effort) and left in place with a
    warning; if the destination reappeared after the claim, the
    quarantined entry is left in place instead of overwriting the
    newcomer. If path was already gone, the rename fails with
    FileNotFoundError and nothing is done.

    Args:
        path: The pathname to remove while it still references identity.
        identity: The (st_dev, st_ino) of the inode this run created;
            None means "no identity recorded" and nothing is removed.
        warn: Whether to print warnings to stderr. The silent callers
            (the rename fallback's failure cleanup) pass False.
        what: The kind of file named in warnings, e.g. "temporary
            download" or "published backup file".
        check_error_message: Warning template when the path cannot be
            claimed; may use {what}, {path} and {exc}.
        remove_error_message: Warning template when the owned inode
            cannot be unlinked; may use {what}, {path} and {exc}.
        replaced_message: Warning template for a replaced path; may use
            {what} and {path}.
    """
    if identity is None:
        return
    quarantine = _quarantine_name(path)
    try:
        os.rename(path, quarantine)
    except FileNotFoundError:
        # Already gone (e.g. published and unlinked); nothing to do.
        return
    except OSError as exc:
        if warn:
            print(
                "WARNING: "
                + check_error_message.format(what=what, path=path, exc=exc),
                file=sys.stderr,
            )
        return
    try:
        st = os.lstat(quarantine)
    except OSError:
        # The quarantine name is only known to this process, so a
        # missing entry means the rename did not take effect; nothing
        # to do.
        return
    if (st.st_dev, st.st_ino) == identity:
        try:
            os.unlink(quarantine)
        except OSError as exc:
            # The owned inode could not be removed (e.g. a permission
            # error or a platform that refuses to unlink an open file).
            # Restore it to the original pathname so the file is not
            # stranded under the quarantine name, then warn.
            try:
                os.rename(quarantine, path)
            except OSError:
                pass
            if warn:
                print(
                    "WARNING: "
                    + remove_error_message.format(
                        what=what, path=path, exc=exc
                    ),
                    file=sys.stderr,
                )
        return
    # The quarantined inode is not this run's: the path had been
    # replaced before the rename. Restore the replacement (best-effort)
    # and warn rather than deleting a file this run did not create.
    # The restore must not clobber a file another process created at
    # path after the claim: os.rename would replace it, so the
    # restoration is a no-replace hard link. If the destination
    # reappeared, the quarantined entry is left in place (it is never
    # deleted) instead of overwriting the newcomer.
    try:
        os.link(quarantine, path)
    except OSError as exc:
        if warn:
            print(
                f"WARNING: could not restore replaced {what} {path}: {exc}",
                file=sys.stderr,
            )
        return
    try:
        os.unlink(quarantine)
    except OSError as exc:
        # The replacement is back at path; the quarantine name is now a
        # second link to it and removing it is best-effort. On failure
        # the entry lingers under the hidden name rather than deleting
        # a file this run does not own.
        if warn:
            print(
                f"WARNING: could not restore replaced {what} {path}: {exc}",
                file=sys.stderr,
            )
        return
    if warn:
        print(
            "WARNING: " + replaced_message.format(what=what, path=path),
            file=sys.stderr,
        )


def _unlink_if_same_inode(
    path: Path, identity: tuple[int, int] | None
) -> None:
    """Remove path only while it still references identity; else leave it.

    Used by the rename fallback's failure cleanup: the fallback created
    the final entry, so it may remove it — but only while the entry
    still references the inode it published. A replacement installed by
    another process after the publication no longer references that
    inode and is left in place rather than deleted. The check and the
    unlink are atomic: the path is first renamed to a unique quarantine
    name only this process knows, so a concurrent writer cannot swap
    the pathname between the identity check and the unlink.
    """
    _unlink_if_same_inode_atomic(path, identity, warn=False)


def _publish_by_rename(
    handle: BinaryIO,
    temp_path: Path,
    final_path: Path,
) -> BinaryIO:
    """Fallback publishing an already-verified inode without replacing.

    Used when the inode-link publication is unavailable: on Windows
    (which refuses to rename a file it holds open, so the held
    descriptor is closed first) and on POSIX platforms/filesystems
    where linkat(AT_EMPTY_PATH) is not supported. The publication is
    no-replace on both platforms: Windows os.rename() refuses to
    replace an existing destination, and on POSIX a hard link is used
    instead of os.rename() (which would silently replace a destination
    that appeared after the caller's pre-check). The published file is
    re-opened no-follow and re-identified; the caller verifies the
    published inode through the returned handle. If the published file
    cannot be re-opened and identified, it is removed — but only while
    it still references the inode this run published; a replacement
    installed by another process is left in place.
    """
    if os.name == "posix":
        # POSIX: os.rename() replaces an existing destination, so the
        # no-replace guarantee is provided by a hard link instead,
        # which fails with FileExistsError if the destination exists.
        # The temporary pathname is kept in place; the caller's cleanup
        # removes it later. The source pathname could have been swapped
        # for a symlink after verification (os.link follows a symlink
        # source on POSIX); the caller's identity re-check rejects that
        # and rolls the final entry back.
        try:
            os.link(temp_path, final_path)
        except FileExistsError as exc:
            raise FileExistsError(
                f"Refusing to overwrite existing backup file: {final_path}"
            ) from exc
        try:
            linked = os.lstat(final_path)
            linked_identity = (linked.st_dev, linked.st_ino)
        except OSError:
            linked_identity = None
        try:
            fd = _open_nofollow_regular(final_path)
        except BaseException:
            _unlink_if_same_inode(final_path, linked_identity)
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
            _unlink_if_same_inode(final_path, linked_identity)
            raise
        return new_handle

    # Windows: os.rename() refuses to replace an existing destination,
    # so it is the no-replace primitive here. The descriptor is closed
    # first because Windows refuses to rename an open file. The handle
    # wraps the caller's descriptor without owning it (closefd=False),
    # so the raw descriptor is closed once here and the wrapper is then
    # marked closed; the caller's cleanup skips it via fileno().
    try:
        fd = handle.fileno()
    except ValueError:
        fd = None
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        handle.close()
    except OSError:
        pass
    try:
        os.rename(temp_path, final_path)
    except FileExistsError as exc:
        raise FileExistsError(
            f"Refusing to overwrite existing backup file: {final_path}"
        ) from exc
    try:
        renamed = os.lstat(final_path)
        renamed_identity = (renamed.st_dev, renamed.st_ino)
    except OSError:
        renamed_identity = None
    try:
        fd = _open_nofollow_regular(final_path)
    except BaseException:
        _unlink_if_same_inode(final_path, renamed_identity)
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
        _unlink_if_same_inode(final_path, renamed_identity)
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
    downloaded_fds: dict[Path, int],
) -> dict[str, Path]:
    """
    Publish verified temporary downloads under their final names.

    Only called after verify_downloads() has accepted every file, so a
    file that reaches BACKUP_DIR under its final name is always a
    checksum-verified artifact.

    The descriptors the download handed over are held open across
    publication, and the links are created from those descriptors'
    inodes — never by re-opening the .part pathnames: a writer that
    swaps a .part path for a symlink (or replaces the file) after
    verification cannot make publication link different bytes than the
    ones that were verified.

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
        downloaded_fds: The open descriptors handed over by
            download_artifacts() for the .part files that were
            verified. Ownership is transferred; they are closed after
            publication.

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

    # Record the inode each temporary download was created with, so the
    # success-path cleanup below removes a temp only while it still
    # references that inode. A writer who replaced a .part pathname
    # after the download planted a different inode; removing it would
    # delete another run's file, so the replacement is left in place
    # with a warning.
    temp_identities: dict[Path, tuple[int, int]] = {}
    for final in finals:
        temp_path = temp_paths[final]
        fd = downloaded_fds[temp_path]
        fd_stat = os.fstat(fd)
        temp_identities[temp_path] = (fd_stat.st_dev, fd_stat.st_ino)

    published: list[tuple[Path, tuple[int, int]]] = []
    # Handles _publish_no_replace() returned for a renamed publication
    # (the fallback used when inode-link publication is unavailable).
    # _held_temp_downloads only tracks the original download handles,
    # so these replacement handles are closed here after verification.
    replacement_handles: list[BinaryIO] = []
    try:
        with _held_temp_downloads(
            temp_paths, finals, downloaded_fds
        ) as handles:
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
                if published_handle is not handles[final]:
                    replacement_handles.append(published_handle)
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
            _unlink_if_same_inode_atomic(
                final_path,
                identity,
                what="published backup file",
                check_error_message=(
                    "could not roll back {what} {path}: {exc}"
                ),
                remove_error_message=(
                    "could not roll back {what} {path}: {exc}"
                ),
                replaced_message=(
                    "{what} {path} was replaced during publication; "
                    "leaving the replacement in place"
                ),
            )
        raise
    finally:
        # Close the replacement handles the rename fallback returned:
        # without this it leaked one descriptor per artifact.
        for handle in replacement_handles:
            try:
                handle.close()
            except OSError:
                pass
    # Publication succeeded: remove the temporary downloads. A leftover
    # temp is only a warning — the finals are complete and verified, so
    # publication is not undone over a cleanup failure. A temp path is
    # removed only while it still references the inode this run created
    # (recorded above); a path replaced by another process is left in
    # place with a warning rather than deleted.
    for final in finals:
        temp_path = temp_paths[final]
        identity = temp_identities[temp_path]
        _unlink_if_same_inode_atomic(
            temp_path,
            identity,
            replaced_message=(
                "{what} {path} was replaced during publication; "
                "leaving the replacement in place"
            ),
        )
    return {final: backup_dir / final for final in finals}


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
    with _held_temp_downloads(
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
            # Reject any path component in ANY entry name before anything
            # else: a manifest may only reference plain filenames, never
            # paths (no traversal).
            for entry_name in parsed:
                if (
                    "/" in entry_name
                    or "\\" in entry_name
                    or posixpath.basename(entry_name) != entry_name
                    or entry_name in (".", "..")
                ):
                    raise ChecksumError(
                        f"{checksum_file} names a path outside the "
                        f"staging directory: {entry_name}"
                    )
            if len(parsed) != 1:
                raise ChecksumError(
                    f"{checksum_file} must contain exactly one entry, "
                    f"found {len(parsed)}"
                )
            if name not in parsed:
                raise ChecksumError(
                    f"{checksum_file} contains no digest for {name}"
                )
            archive_handle = handles[name]
            archive_handle.seek(0)
            actual = _sha256_handle(archive_handle)
            if actual.lower() != parsed[name].lower():
                raise ChecksumError(
                    f"Checksum mismatch for {local_path}: expected "
                    f"{parsed[name]}, got {actual}"
                )
            digests[name] = parsed[name]
            manifest_handle.seek(0)
            digests[checksum_name(name)] = _sha256_handle(manifest_handle)
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
