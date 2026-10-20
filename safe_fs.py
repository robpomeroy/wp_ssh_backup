"""Safe local-filesystem primitives shared by backup.py and restore.py.

Everything here exists to close a time-of-check/time-of-use window: a
local writer who can modify the backup directory (or the directory a
restore reads from) must not be able to swap a pathname between the
moment a file is inspected and the moment its bytes are used.

The building blocks are:

- :func:`open_nofollow_regular` and :func:`assert_nofollow_regular`:
  open a file through a descriptor that cannot follow a symlink at the
  final path component, and prove the descriptor still refers to that
  leaf.
- :func:`inode_identity`: the ``(st_dev, st_ino)`` pair that identifies
  an inode, used to bind an action to a specific file rather than to a
  pathname.
- :func:`quarantine_name` and :func:`unlink_if_same_inode_atomic`:
  remove a path only while it still refers to the inode the caller
  created, atomically, without ever deleting a file the caller did not
  create.
- :func:`held_local_files` and :func:`held_temp_downloads`: keep
  descriptors open for the whole lifetime of a read-verify-publish
  sequence, so the bytes that are inspected are the bytes that are used.
"""

from __future__ import annotations

import errno
import os
import secrets
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO
from collections.abc import Generator

from common import MissingArtifactError, WPSSHBackupError

__all__ = [
    "assert_nofollow_regular",
    "held_local_files",
    "held_temp_downloads",
    "inode_identity",
    "open_nofollow_regular",
    "quarantine_name",
    "remove_quarantine_reservation",
    "reserve_quarantine_name",
    "unlink_if_same_inode",
    "unlink_if_same_inode_atomic",
]

# How many candidate quarantine names to try before giving up. Each
# attempt uses a fresh 128-bit random suffix, so a collision is
# practically impossible; the loop exists only so a pathological case
# (e.g. a filesystem that keeps failing the create) cannot spin.
_QUARANTINE_RESERVE_ATTEMPTS = 8


# ---------------------------------------------------------------------------
# Descriptors that cannot follow a symlink
# ---------------------------------------------------------------------------


def open_nofollow_regular(
    path: Path,
    *,
    verb: str = "use",
    missing_message: str | None = None,
) -> int:
    """
    Open a local file through a descriptor that cannot follow a symlink
    at the final path component.

    On POSIX, O_NOFOLLOW makes the open fail with ELOOP when the leaf is
    a symlink. Windows has no O_NOFOLLOW, so the descriptor is opened
    and then compared against lstat(): a symlink leaf resolves to a
    different device/inode pair than the link itself, and the mismatch
    is rejected the same way. The descriptor is also required to be a
    regular file, so a directory (openable on some platforms) or any
    other non-regular object is rejected.

    The descriptor is NOT closed on failure: the caller owns it from
    the moment this function returns, and must close it if a later
    check rejects the file. This is a single ownership rule for both
    callers, so a rejected open can never leak a descriptor or close
    one twice.

    Args:
        path: The file to open.
        verb: What the caller is doing with the file, used in the
            error messages (e.g. "publish", "upload").
        missing_message: The message used when the file does not
            exist. Defaults to "Local file missing: {path}".

    Returns:
        The open file descriptor.

    Raises:
        MissingArtifactError: If the path does not exist.
        WPSSHBackupError: If the leaf is a symlink or not a regular
            file.
    """
    if missing_message is None:
        missing_message = f"Local file missing: {path}"
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        # A no-op for regular files, but stops a planted FIFO from
        # blocking the open forever on POSIX; the S_ISREG check in
        # assert_nofollow_regular rejects it.
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
                f"Refusing to {verb} through symlink: {path}"
            ) from exc
        if exc.errno == errno.ENOENT:
            raise MissingArtifactError(missing_message) from exc
        raise WPSSHBackupError(
            f"Refusing to {verb} {path.name}: cannot open local file: {exc}"
        ) from exc


def assert_nofollow_regular(fd: int, path: Path) -> None:
    """Reject a descriptor whose leaf was (or is) a symlink or non-file.

    On platforms without O_NOFOLLOW the open itself cannot detect a
    symlinked leaf, so the descriptor's identity is compared against the
    leaf's lstat(): a symlink resolves to the target's device/inode,
    which differs from the link's own.

    The descriptor is NOT closed here: the caller owns it and must
    close it when this check rejects the file.

    Args:
        fd: The open descriptor to check.
        path: The path the descriptor was opened through.

    Raises:
        WPSSHBackupError: If the descriptor is not a regular file or
            does not refer to the leaf itself.
    """
    fd_stat = os.fstat(fd)
    if not stat.S_ISREG(fd_stat.st_mode):
        raise WPSSHBackupError(
            f"Refusing to use {path.name}: not a regular file"
        )
    if not getattr(os, "O_NOFOLLOW", 0):
        leaf_stat = os.lstat(path)
        if (leaf_stat.st_dev, leaf_stat.st_ino) != (
            fd_stat.st_dev,
            fd_stat.st_ino,
        ):
            raise WPSSHBackupError(
                f"Refusing to use {path.name} through symlink: {path}"
            )


# ---------------------------------------------------------------------------
# Inode identity
# ---------------------------------------------------------------------------


def inode_identity(fd: int) -> tuple[int, int]:
    """Return the (st_dev, st_ino) pair identifying an open file.

    The pair is what binds an action to a specific inode rather than to
    a pathname: a writer who replaces a pathname installs a different
    inode, and the pair no longer matches.

    Args:
        fd: The open descriptor to identify.

    Returns:
        A (st_dev, st_ino) tuple.
    """
    st = os.fstat(fd)
    return (st.st_dev, st.st_ino)


# ---------------------------------------------------------------------------
# Atomic, identity-bound removal
# ---------------------------------------------------------------------------

_quarantine_counter = 0


def quarantine_name(path: Path) -> Path:
    """An unguessable quarantine name in the same directory as path.

    The name is generated in the same directory as path so a rename into
    it is atomic (same filesystem). It carries a 128-bit random suffix:
    the PID and a counter are both predictable, so a concurrent writer
    could otherwise pre-create the name and make the quarantine
    collide with a file of its own.

    The name is only a CANDIDATE: it is not reserved, and the caller
    must claim it with :func:`reserve_quarantine_name` (or create it
    with O_CREAT|O_EXCL) before renaming anything into it.

    Args:
        path: The path the quarantine name is derived from.

    Returns:
        A candidate quarantine path.
    """
    global _quarantine_counter
    _quarantine_counter += 1
    suffix = secrets.token_hex(16)
    return path.with_name(
        f".{path.name}.quarantine-{os.getpid()}-{_quarantine_counter}"
        f"-{suffix}"
    )


def reserve_quarantine_name(path: Path) -> Path:
    """Reserve an unguessable quarantine name and return it.

    The name is created with O_CREAT | O_EXCL, so it is guaranteed not
    to exist beforehand: a file already at that name is never replaced
    and never unlinked. The reservation makes the name unpredictable to
    a concurrent writer, which therefore cannot have pre-created it,
    and it also means the name cannot be a leftover from an earlier run
    that happened to reuse the same PID and counter.

    The reserved entry is an empty regular file created with the
    caller's own permissions. The caller moves the file it wants to
    quarantine over it with os.replace() — which REPLACES the
    destination, and that is safe precisely because the destination is
    this process's own empty reservation. The caller must remove the
    reservation if it does not move anything into it.

    Args:
        path: The path the quarantine name is derived from.

    Returns:
        The reserved quarantine path.

    Raises:
        WPSSHBackupError: If no quarantine name could be reserved.
    """
    for _ in range(_QUARANTINE_RESERVE_ATTEMPTS):
        candidate = quarantine_name(path)
        try:
            fd = os.open(
                candidate,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError:
            # The name is taken (a leftover, or an improbable
            # collision): try another one.
            continue
        except OSError as exc:
            raise WPSSHBackupError(
                f"Could not reserve a quarantine name for {path}: {exc}"
            ) from exc
        os.close(fd)
        return candidate
    raise WPSSHBackupError(
        f"Could not reserve a quarantine name for {path}: "
        f"{_QUARANTINE_RESERVE_ATTEMPTS} names were all taken"
    )


def remove_quarantine_reservation(quarantine: Path) -> None:
    """Remove a quarantine reservation that was never used.

    The reservation is this process's own empty file, created with
    O_CREAT|O_EXCL. When the rename into it did not happen, the
    reservation is still there and must be cleaned up, or the backup
    directory accumulates empty hidden files.

    Args:
        quarantine: The reserved quarantine path.
    """
    try:
        os.unlink(quarantine)
    except OSError:
        # The reservation could not be removed. It is an empty file
        # under a hidden name, so it is harmless: it is never matched
        # by the backup filename pattern and never mistaken for a
        # backup set.
        pass


def _restore_quarantined_entry(
    quarantine: Path, path: Path
) -> tuple[bool, OSError | None]:
    """Put a quarantined entry back at its original pathname.

    The restore uses a NO-REPLACE hard link, never a rename: while the
    entry sat under the quarantine name the original pathname was free,
    and another process may have created a file there. os.rename would
    replace that newcomer (POSIX) and delete another process's file.

    If the pathname has reappeared, the link fails with
    FileExistsError and the quarantined entry is left in place -- it is
    never deleted -- rather than clobbering the newcomer. The quarantine
    name is then a second link to the entry, and removing it is
    best-effort.

    Args:
        quarantine: The quarantine name holding the entry.
        path: The original pathname to restore to.

    Returns:
        A tuple of (the entry was linked to path, the failure that
        stopped it, if any). The failure is the link failure, or the
        failure to remove the now-redundant quarantine name.
    """
    try:
        os.link(quarantine, path)
    except OSError as exc:
        # The pathname was taken while the entry was quarantined, or
        # linking is unsupported on this filesystem. Either way the
        # entry stays under the quarantine name rather than risking a
        # replacement of the original pathname.
        return False, exc
    try:
        os.unlink(quarantine)
    except OSError as exc:
        # The entry is back at path; the quarantine name is now a
        # second link to it and removing it is best-effort.
        return True, exc
    return True, None


def unlink_if_same_inode_atomic(
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

    Every restore of the quarantined entry uses a no-replace hard
    link, never os.rename: the original pathname is free while the
    entry sits under the quarantine name, and another process may
    create a file there. os.rename would replace that newcomer on
    POSIX and delete another process's file, so the quarantined entry
    is instead left in place whenever the pathname has reappeared.

    The quarantine name is RESERVED before the source is renamed into
    it (see :func:`reserve_quarantine_name`). A bare os.rename would
    REPLACE whatever already sat at the quarantine name, deleting an
    unrelated file — a leftover from an earlier run that happened to
    reuse the same PID and counter, or an entry a concurrent writer
    pre-created. Reserving the name first makes the rename safe: the
    only entry it can replace is this process's own empty reservation.

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
    try:
        quarantine = reserve_quarantine_name(path)
    except WPSSHBackupError as exc:
        # No quarantine name could be reserved, so the claim cannot be
        # made and the check-then-unlink is no longer atomic: the file
        # must be left in place. This is a cleanup helper, so it warns
        # rather than raises -- raising here would mask the error the
        # caller is already handling.
        if warn:
            print(
                "WARNING: "
                + check_error_message.format(
                    what=what, path=path, exc=exc
                ),
                file=sys.stderr,
            )
        return
    try:
        # os.replace, not os.rename: the destination is this process's
        # own empty reservation, and os.replace overwrites it on both
        # POSIX and Windows. (os.rename refuses to replace on Windows,
        # and on POSIX it would replace whatever else had appeared at
        # the name — which the reservation makes impossible.)
        os.replace(path, quarantine)
    except FileNotFoundError:
        # Already gone (e.g. published and unlinked); nothing to do.
        # The reservation is this process's own empty file, so it is
        # removed here.
        remove_quarantine_reservation(quarantine)
        return
    except OSError as exc:
        remove_quarantine_reservation(quarantine)
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
            #
            # The restore must NOT replace anything: while the owned
            # inode sat under the quarantine name, the original
            # pathname was free, and another process may have created
            # a file there. os.rename would replace that newcomer
            # (POSIX) and delete another process's file, so the
            # restore uses the same no-replace hard link as the
            # replaced-inode branch below. If the pathname has
            # reappeared, the quarantined entry is left in place
            # rather than clobbering the newcomer.
            # The restore is best-effort and silent: the failure is
            # reported by the warning about the unlink below, which is
            # the actual problem this branch is about.
            _restore_quarantined_entry(quarantine, path)
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
    _restored, exc = _restore_quarantined_entry(quarantine, path)
    if exc is not None:
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


def unlink_if_same_inode(
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

    Args:
        path: The pathname to remove while it still references identity.
        identity: The (st_dev, st_ino) of the inode this run created;
            None means "no identity recorded" and nothing is removed.
    """
    unlink_if_same_inode_atomic(path, identity, warn=False)


# ---------------------------------------------------------------------------
# Held descriptors
# ---------------------------------------------------------------------------


@contextmanager
def held_local_files(
    paths: list[Path],
) -> Generator[dict[Path, BinaryIO], None, None]:
    """
    Open each path once through a no-follow descriptor and hold it open
    for the whole context.

    Everything a restore reads from these paths — member-type
    validation, digest computation and the uploaded bytes — must come
    from the same opened file, so a writer that swaps the pathname for a
    symlink (or replaces the file) after the initial check cannot make
    the restore upload or validate different bytes than the ones it
    already inspected.

    Args:
        paths: The files to open and hold.

    Yields:
        A mapping of each path to its open file object.
    """
    handles: dict[Path, BinaryIO] = {}
    try:
        for path in paths:
            fd = open_nofollow_regular(path, verb="upload")
            try:
                assert_nofollow_regular(fd, path)
                handles[path] = os.fdopen(fd, "rb")
            except BaseException:
                # fdopen took ownership only on success; make sure a
                # failed assertion does not leak the descriptor.
                if path not in handles:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                raise
        yield handles
    finally:
        for handle in handles.values():
            handle.close()


@contextmanager
def held_temp_downloads(
    temp_paths: dict[str, Path],
    finals: list[str],
    downloaded_fds: dict[Path, int],
    *,
    close_on_exit: bool = True,
) -> Generator[dict[str, BinaryIO], None, None]:
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

    Args:
        temp_paths: The temporary path of each final name.
        finals: The final names to open, in order.
        downloaded_fds: The open descriptors of the .part files, keyed
            by their paths.
        close_on_exit: Whether to close the descriptors on exit.

    Yields:
        A mapping of each final name to its open file object.
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
