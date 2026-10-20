"""Publishing verified downloads under their final names.

A backup file must never replace an existing one, and the bytes that
appear under the final name must be the bytes that were verified. This
module provides the primitives that guarantee both:

- The published entry is created from the *held descriptor's inode*,
  never from a re-opened pathname, so a writer that swaps the
  temporary pathname after verification cannot publish different bytes.
- The creation is a no-replace operation, so a file that appears at a
  final name after the pre-check can never be silently overwritten.
- The published entry is re-opened and re-identified, and the digest is
  re-verified through the held descriptor, so a replacement installed
  during publication is rejected rather than reported as success.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
from pathlib import Path
from typing import BinaryIO

import safe_fs
from common import ChecksumError, WPSSHBackupError, checksum_name
from publish_lock import exclusive_publish_lock

__all__ = [
    "assert_published_inode",
    "final_all_finals_recheck",
    "link_inode_no_replace",
    "publish_by_rename",
    "publish_downloads",
    "publish_no_replace",
    "verify_published_inode",
]


# ---------------------------------------------------------------------------
# Inode-bound publication
# ---------------------------------------------------------------------------

# linkat() and its flags: Python does not expose AT_EMPTY_PATH, so the
# libc call is wrapped here. Loaded lazily and cached: the return value
# is a plain ctypes function object that stays valid for the process
# lifetime.
_AT_FDCWD = -100
_AT_EMPTY_PATH = 0x1000
_linkat_cache: ctypes.CDLL | None = None


def _linkat_libc() -> ctypes.CDLL:
    """Return the cached libc handle exposing linkat()."""
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


def link_inode_no_replace(link_fd: int, final_path: Path) -> None:
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
    there must use the rename fallback (publish_by_rename) instead.

    Args:
        link_fd: A descriptor referencing the inode to publish.
        final_path: The path to create.

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


def publish_no_replace(
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
    falls back to publish_by_rename, which on POSIX creates the final
    entry with an atomic no-replace hard link (os.rename would silently
    replace a destination that appeared after the pre-check) and
    re-opens it no-follow and re-identifies it so the fallback publishes
    the same inode that was verified. On Windows, os.link() by pathname
    is used: the held descriptor (the download's own O_RDWR fd on the
    inode it wrote) prevents the .part pathname from being unlinked or
    replaced while it is held, so linking the pathname cannot publish a
    different inode than the one verified; on volumes without hard-link
    support this also falls back to the no-replace rename.

    Args:
        handle: The held descriptor of the verified file.
        temp_path: The temporary path the handle was opened through.
        final_path: The final name to publish at.

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
            link_inode_no_replace(handle.fileno(), final_path)
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
                return publish_by_rename(handle, temp_path, final_path)
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
        return publish_by_rename(handle, temp_path, final_path)
    return handle


def _reopen_published(
    final_path: Path,
    held_identity: tuple[int, int] | None,
) -> BinaryIO:
    """Re-open a published file and prove it is the verified inode.

    The published entry is opened no-follow and compared against the
    inode that was verified BEFORE publication. If the entry cannot be
    opened, is not a regular file, or refers to a different inode, it
    is removed — but only while it still references the held inode, so
    a replacement installed by another process is left in place.

    Args:
        final_path: The published path.
        held_identity: The (st_dev, st_ino) of the verified inode, or
            None when the caller could not determine it.

    Returns:
        An open file object for the published inode.

    Raises:
        WPSSHBackupError: If the published entry is not the verified
            inode.
    """
    try:
        fd = safe_fs.open_nofollow_regular(final_path, verb="publish")
    except BaseException:
        # The published entry is removed only while it still
        # references the inode this run published. A writer who
        # replaced final_path after the publication installed a
        # different inode; removing it would delete another process's
        # file, so the replacement is left in place.
        safe_fs.unlink_if_same_inode(final_path, held_identity)
        raise
    try:
        safe_fs.assert_nofollow_regular(fd, final_path)
        if held_identity is not None:
            published_stat = os.fstat(fd)
            if (published_stat.st_dev, published_stat.st_ino) != (
                held_identity[0],
                held_identity[1],
            ):
                raise WPSSHBackupError(
                    f"Refusing to publish {final_path}: the temporary "
                    "download was replaced after verification"
                )
        new_handle = os.fdopen(fd, "rb")
    except BaseException:
        # fdopen took ownership only on success; after a failed
        # assertion the descriptor is still ours to close.
        try:
            os.close(fd)
        except OSError:
            pass
        safe_fs.unlink_if_same_inode(final_path, held_identity)
        raise
    return new_handle


def publish_by_rename(
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
    it still references the inode this run published (the held inode,
    captured before publication, never a post-publication lstat that a
    writer could have raced); a replacement installed by another
    process is left in place.

    Args:
        handle: The held descriptor of the verified file.
        temp_path: The temporary path the handle was opened through.
        final_path: The final name to publish at.

    Returns:
        An open file object for the published inode.

    Raises:
        FileExistsError: If final_path already exists.
        WPSSHBackupError: If the published entry is not the verified
            inode.
    """
    # The held inode's identity is captured BEFORE the descriptor is
    # closed: a writer who replaces temp_path in the close-rename
    # interval would otherwise move a replacement inode into the final
    # backup name, and the original inode would be gone.
    try:
        held = os.fstat(handle.fileno())
        held_identity = (held.st_dev, held.st_ino)
    except (OSError, ValueError):
        held_identity = None

    if os.name == "posix":
        # POSIX: os.rename() replaces an existing destination, so the
        # no-replace guarantee is provided by a hard link instead,
        # which fails with FileExistsError if the destination exists.
        # The temporary pathname is kept in place; the caller's cleanup
        # removes it later. The source pathname could have been swapped
        # for a symlink after verification (os.link follows a symlink
        # source on POSIX); the caller's identity re-check rejects that
        # and rolls the final entry back. The source could equally have
        # been swapped for a DIFFERENT REGULAR file: os.link would link
        # the replacement without error, so the published final is
        # compared against the held descriptor's inode (the verified
        # one) below, not merely checked for being a regular file.
        try:
            os.link(temp_path, final_path)
        except FileExistsError as exc:
            raise FileExistsError(
                f"Refusing to overwrite existing backup file: {final_path}"
            ) from exc
        return _reopen_published(final_path, held_identity)

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
    return _reopen_published(final_path, held_identity)


# ---------------------------------------------------------------------------
# Post-publication verification
# ---------------------------------------------------------------------------


def assert_published_inode(handle: BinaryIO, final_path: Path) -> None:
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

    Args:
        handle: The held descriptor of the published inode.
        final_path: The published path.

    Raises:
        WPSSHBackupError: If the published path no longer references
            the verified inode.
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


def verify_published_inode(
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

    Args:
        handle: The held descriptor of the published inode.
        final_path: The published path.
        expected_sha256: The digest the file must still have.

    Raises:
        ChecksumError: If the digest no longer matches.
        WPSSHBackupError: If the published path was replaced.
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
    assert_published_inode(handle, final_path)


def final_all_finals_recheck(
    published: list[tuple[Path, tuple[int, int]]],
    backup_dir: Path,
) -> None:
    """
    Re-check every published final still references its held inode.

    Called under the exclusive publish lock immediately before success
    is reported, so a cooperative concurrent run cannot be mid-
    publication while it runs. Each final path's directory entry is
    compared against the inode this run verified and published: a writer
    who unlinked or replaced ANY final — not just the last one checked
    inside the publication loop — is caught here and the run fails and
    rolls back instead of reporting success with a mismatched
    archive/manifest pair.

    Args:
        published: The published paths and their held identities.
        backup_dir: The directory the finals live in.

    Raises:
        WPSSHBackupError: If any final path no longer references the
            inode this run published.
    """
    for final_path, identity in published:
        try:
            st = os.lstat(final_path)
        except OSError as exc:
            raise WPSSHBackupError(
                f"Refusing to report success: {final_path} was removed "
                f"after publication: {exc}"
            ) from exc
        if (st.st_dev, st.st_ino) != identity:
            raise WPSSHBackupError(
                f"Refusing to report success: {final_path} was replaced "
                "after publication; the final names no longer reference "
                "the verified inodes"
            )


# ---------------------------------------------------------------------------
# The publication transaction
# ---------------------------------------------------------------------------


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
    reported as a successful publication. After the loop every final is
    re-checked against its held inode while an exclusive publication
    lock is held: a writer who replaces an ALREADY-verified final while
    the remaining files publish — not just the last one — is caught
    before success is reported, so the run never reports success with a
    mismatched archive/manifest pair. A cooperative concurrent run
    cannot interleave its publications either: it acquires the same
    lock. If publication fails part-way, the final paths this run
    created are removed so the caller's cleanup can discard the still
    intact temporary downloads (a path that was replaced after
    publication no longer references this run's inode and is left in
    place with a warning). A failed run therefore never leaves a partial
    final-name set in BACKUP_DIR.

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

    # The publication lock is held across the entire operation: the
    # pre-check, every no-replace publication, the final all-finals
    # re-check and the temp cleanup all run while this run exclusively
    # owns the directory for cooperative writers.
    with exclusive_publish_lock(backup_dir):
        _precheck_finals(finals, backup_dir)
        temp_identities = _record_temp_identities(
            finals, temp_paths, downloaded_fds
        )
        published: list[tuple[Path, tuple[int, int]]] = []
        # Handles publish_no_replace() returned for a renamed
        # publication (the fallback used when inode-link publication is
        # unavailable). safe_fs.held_temp_downloads only tracks the
        # original download handles, so these replacement handles are
        # closed here after verification.
        replacement_handles: list[BinaryIO] = []
        try:
            with safe_fs.held_temp_downloads(
                temp_paths, finals, downloaded_fds
            ) as handles:
                for final in finals:
                    final_path = backup_dir / final
                    # Record the held inode before publication: it is
                    # the inode this run verified and intends to
                    # publish, and rollback must recognize it even when
                    # publication linked a replacement instead.
                    fd_stat = os.fstat(handles[final].fileno())
                    identity = (fd_stat.st_dev, fd_stat.st_ino)
                    published_handle = publish_no_replace(
                        handles[final], temp_paths[final], final_path
                    )
                    if published_handle is not handles[final]:
                        replacement_handles.append(published_handle)
                    handles[final] = published_handle
                    published.append((final_path, identity))
                    assert_published_inode(published_handle, final_path)
                    verify_published_inode(
                        published_handle, final_path, digests[final]
                    )
            # After the loop, every final is re-checked against the
            # inode this run verified and published, still under the
            # publication lock: a writer who unlinked or replaced any
            # final — including one published and verified earlier in
            # the loop, while the remaining files published — fails the
            # run here instead of letting it report success with a
            # mismatched archive/manifest pair. The check runs INSIDE
            # this try so a rejection rolls the run back (the finals
            # this run created are removed; a replaced final no longer
            # references this run's inode and is left in place).
            final_all_finals_recheck(published, backup_dir)
        except BaseException:
            # Roll back the final paths this run created. They were
            # made by this run's no-replace publications, so unlinking
            # them can never remove a pre-existing file. A path that
            # was unlinked and replaced after publication no longer
            # references this run's inode; the replacement is left in
            # place with a warning rather than unlinking a file this
            # run did not create. The temporary downloads were not
            # unlinked, so the caller's _discard_temp_downloads()
            # cleanup — which must never touch final paths it did not
            # create — discards them.
            _rollback_published(published)
            raise
        finally:
            # Close the replacement handles the rename fallback
            # returned: without this it leaked one descriptor per
            # artifact.
            for handle in replacement_handles:
                try:
                    handle.close()
                except OSError:
                    pass

        # Publication succeeded: remove the temporary downloads. A
        # leftover temp is only a warning — the finals are complete and
        # verified, so publication is not undone over a cleanup
        # failure. A temp path is removed only while it still
        # references the inode this run created (recorded above); a
        # path replaced by another process is left in place with a
        # warning rather than deleted.
        _remove_temp_downloads(finals, temp_paths, temp_identities)
    return {final: backup_dir / final for final in finals}


def _precheck_finals(finals: list[str], backup_dir: Path) -> None:
    """Refuse to publish over anything that already exists.

    The pre-check makes the common conflict case fail fast with a
    friendly error and no half-done publication. It alone is not the
    guarantee — the no-replace publication is: it fails if a path
    appears between the check and the publication. Symlinks are
    rejected too, including dangling ones: Path.exists() is False for a
    broken link, but publication would silently replace it, breaking the
    preservation promise.

    Args:
        finals: The final names to publish.
        backup_dir: The directory the finals live in.

    Raises:
        FileExistsError: If a final name is already taken.
    """
    for final in finals:
        final_path = backup_dir / final
        if final_path.exists() or final_path.is_symlink():
            raise FileExistsError(
                f"Refusing to overwrite existing backup file: {final_path}"
            )


def _record_temp_identities(
    finals: list[str],
    temp_paths: dict[str, Path],
    downloaded_fds: dict[Path, int],
) -> dict[Path, tuple[int, int]]:
    """Record the inode each temporary download was created with.

    The success-path cleanup removes a temp only while it still
    references that inode. A writer who replaced a .part pathname after
    the download planted a different inode; removing it would delete
    another run's file, so the replacement is left in place with a
    warning.

    Args:
        finals: The final names being published.
        temp_paths: The temporary path of each final name.
        downloaded_fds: The open descriptors of the .part files.

    Returns:
        A mapping of each temporary path to its (st_dev, st_ino).
    """
    identities: dict[Path, tuple[int, int]] = {}
    for final in finals:
        temp_path = temp_paths[final]
        fd = downloaded_fds[temp_path]
        fd_stat = os.fstat(fd)
        identities[temp_path] = (fd_stat.st_dev, fd_stat.st_ino)
    return identities


def _rollback_published(
    published: list[tuple[Path, tuple[int, int]]],
) -> None:
    """Remove the final paths this run created.

    The paths were made by this run's no-replace publications, so
    unlinking them can never remove a pre-existing file. A path that
    was unlinked and replaced after publication no longer references
    this run's inode; the replacement is left in place with a warning
    rather than unlinking a file this run did not create.

    Args:
        published: The published paths and their held identities.
    """
    for final_path, identity in reversed(published):
        safe_fs.unlink_if_same_inode_atomic(
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


def _remove_temp_downloads(
    finals: list[str],
    temp_paths: dict[str, Path],
    temp_identities: dict[Path, tuple[int, int]],
) -> None:
    """Remove the temporary downloads now the finals are published.

    A leftover temp is only a warning — the finals are complete and
    verified, so publication is not undone over a cleanup failure. A
    temp path is removed only while it still references the inode this
    run created; a path replaced by another process is left in place
    with a warning rather than deleted.

    Args:
        finals: The final names that were published.
        temp_paths: The temporary path of each final name.
        temp_identities: Each temporary path's (st_dev, st_ino).
    """
    for final in finals:
        temp_path = temp_paths[final]
        identity = temp_identities[temp_path]
        safe_fs.unlink_if_same_inode_atomic(
            temp_path,
            identity,
            replaced_message=(
                "{what} {path} was replaced during publication; "
                "leaving the replacement in place"
            ),
        )
