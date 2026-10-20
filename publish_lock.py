"""The cooperative publication lock that guards a backup directory.

Two concurrent backup runs must not publish into the same directory: each
would link its own final names, and a reader could observe one run's
archive beside another run's manifest. A single lock file in the backup
directory serialises publication between cooperative runs.

The lock is safe against a crashed owner: it records the owning
process's PID, and a lock whose owner is verifiably dead is reclaimed
automatically. A lock whose owner is alive — or whose liveness cannot
be established — is never stolen.

Ownership is recorded ATOMICALLY. The PID is written to a private
temporary file which is then hard-linked into place, so the lock name
never exists without its owner: a contender can never observe an empty
lock and mistake a live creator for a crashed one. On filesystems
without hard links the lock name is created with O_CREAT|O_EXCL
instead, which is a true no-replace primitive but briefly leaves the
lock empty; an empty lock is never reclaimed, so that path fails closed
rather than stealing a live lock.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path
from collections.abc import Generator

import safe_fs
from common import WPSSHBackupError

__all__ = [
    "PUBLISH_LOCK_ATTEMPTS",
    "PUBLISH_LOCK_NAME",
    "PUBLISH_LOCK_RETRY_DELAY",
    "exclusive_publish_lock",
    "pid_alive",
    "steal_stale_lock",
    "try_create_publish_lock",
]

# The publication lock lives in BACKUP_DIR: a cooperative concurrent run
# acquires the same lock, so two runs cannot interleave their
# publications. The file name never matches the backup filename pattern,
# so find_backup_sets() and prune_local_backups() ignore it.
PUBLISH_LOCK_NAME = ".wp-ssh-backup.lock"
PUBLISH_LOCK_ATTEMPTS = 40
PUBLISH_LOCK_RETRY_DELAY = 0.05


def pid_alive(pid: int) -> bool:
    """Best-effort liveness probe for a lock's owning process.

    Returns False ONLY when the PID is verifiably no longer a process.
    Any uncertainty — permissions, platforms without a usable probe,
    a recycled PID belonging to some other live process — returns True,
    so a lock that might still be held is never stolen.

    On POSIX, signal 0 to a process is a pure liveness check (no signal
    is delivered). On Windows, signal 0 is rejected by os.kill, so an
    OpenProcess handle probe is used instead. A NULL handle alone does
    NOT prove the process is gone: OpenProcess also fails with
    ERROR_ACCESS_DENIED for a live process owned by another account (or
    one that is protected). Only ERROR_INVALID_PARAMETER — what
    OpenProcess reports for a PID that names no process — is treated as
    dead; every other failure is uncertain and treated as alive.

    Args:
        pid: The process ID to probe.

    Returns:
        True if the process may still be running.
    """
    if os.name == "nt":
        try:
            import ctypes

            # use_last_error=True so GetLastError() is captured reliably
            # (ctypes may otherwise clobber it between calls).
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            open_process = kernel32.OpenProcess
            open_process.restype = ctypes.c_void_p
            open_process.argtypes = [
                ctypes.c_uint32,  # dwDesiredAccess
                ctypes.c_int,     # bInheritHandle
                ctypes.c_uint32,  # dwProcessId
            ]
            close_handle = kernel32.CloseHandle
            close_handle.restype = ctypes.c_int
            # c_void_p: a 64-bit handle must not be truncated to an int.
            close_handle.argtypes = [ctypes.c_void_p]
            # QUERY_LIMITED_INFORMATION: a no-side-effect probe.
            handle = open_process(0x1000, False, pid)
            if handle:
                close_handle(handle)
                return True
            err = ctypes.get_last_error()
            # ERROR_INVALID_PARAMETER (87): the PID names no process.
            # ERROR_ACCESS_DENIED (5) and anything else: the process may
            # well exist (another account, protected, or a transient
            # failure), so treat it as alive and never steal its lock.
            return err != 87
        except (OSError, AttributeError):
            # Probe unavailable: treat as alive rather than stealing.
            return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists but owned by another account: treat as alive.
        return True
    except OSError:
        # Zombie (ESRCH may surface here on some platforms) or another
        # probe failure: conservative, treat as alive.
        return True


def steal_stale_lock(lock: Path) -> bool:
    """Atomically reclaim a publish lock whose owner is dead.

    Returns True when the lock name has been freed (the caller should
    retry the O_EXCL creation); False when the lock is held by a live
    process or staleness cannot be proven, in which case the caller
    keeps retrying normally.

    The reclaim is inode-bound, not pathname-bound: the lock's inode is
    captured FROM THE SAME DESCRIPTOR the PID is read from, so the
    identity provably describes the entry the PID came from. The lock
    is renamed to a unique name only this process knows, and the renamed
    entry is unlinked ONLY if it is still that same inode. A contender
    that observed the same dead PID cannot steal a lock a second
    contender re-created in between: the second contender's rename moves
    the OLD inode, and if a NEW lock was created at the name before this
    process's rename, the renamed entry is a different inode and is
    restored with a NO-REPLACE hard link (never renaming over a lock
    another contender created) instead of being unlinked — so a live
    lock is never freed. A crash between the rename and the unlink
    leaves a .stale- file but frees the lock name, which is all that
    matters.

    The descriptor is closed before the rename, because Windows refuses
    to rename a file this process holds open. That does not reopen the
    window the descriptor closed: the identity captured from it is
    compared against the renamed entry, so a lock that was replaced
    between the read and the rename is still detected and refused.

    Args:
        lock: The lock file to reclaim.

    Returns:
        True if the lock name is now free.

    Raises:
        WPSSHBackupError: If a quarantined lock cannot be restored and
            the name must not be reused.
    """
    # Open the lock ONCE and read both the identity and the PID from
    # that descriptor. Reading the PID through the pathname and the
    # identity through a separate lstat would leave a window between
    # them: a contender could reclaim the lock and create a new live
    # one in that window, and the identity would then describe the NEW
    # lock while the PID described the old one — the reclaim would
    # free a live lock and let two backups publish concurrently.
    try:
        fd = safe_fs.open_nofollow_regular(
            lock, verb="read the publish lock"
        )
    except (OSError, WPSSHBackupError):
        # The lock cannot be read (gone, unreadable, or a symlink).
        # Nothing can be proven stale; leave it alone.
        return False
    try:
        try:
            safe_fs.assert_nofollow_regular(fd, lock)
            st = os.fstat(fd)
            lock_identity = (st.st_dev, st.st_ino)
            data = b""
            while True:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            return False
    finally:
        # Closed before the rename: Windows refuses to rename a file
        # this process holds open. The identity captured above still
        # describes the entry the PID was read from, and the renamed
        # entry is compared against it below, so a lock that was
        # replaced in between is still detected.
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        pid = int(data.decode("ascii", errors="strict").strip())
    except (UnicodeDecodeError, ValueError):
        # Unparseable. Ownership is recorded atomically (the lock is
        # hard-linked into place only after its PID is written), so a
        # lock created by this tool is never visible without its owner.
        # An unparseable lock is therefore corruption or a foreign file,
        # and it is NEVER reclaimed on age alone: a creator paused
        # between create and write could still be live, and stealing
        # its lock would break exclusivity. The administrator recovery
        # path (delete the lock) covers this case.
        return False
    if pid_alive(pid):
        return False
    # The quarantine name is RESERVED before the lock is moved into
    # it: os.rename REPLACES whatever already sits at the destination,
    # so a leftover entry (e.g. from an earlier run that reused the
    # same PID and counter) would be silently deleted. The reservation
    # is this process's own empty file, so the move can only replace
    # that. os.replace is used rather than os.rename because it also
    # overwrites on Windows, where os.rename refuses to replace.
    try:
        stale = safe_fs.reserve_quarantine_name(lock)
    except WPSSHBackupError:
        # No quarantine name could be reserved, so the lock cannot be
        # reclaimed safely. Report it as not reclaimed: the lock is
        # left untouched and the caller retries the create.
        return False
    try:
        os.replace(lock, stale)
    except FileNotFoundError:
        # Another process stole it first; the name is free, retry
        # create. The reservation is this process's own empty file.
        safe_fs.remove_quarantine_reservation(stale)
        return True
    except OSError:
        safe_fs.remove_quarantine_reservation(stale)
        return False
    try:
        st = os.lstat(stale)
    except OSError:
        # The renamed entry is gone; the name is free, retry create.
        return True
    if (st.st_dev, st.st_ino) != lock_identity:
        # The renamed entry is NOT the stale lock we read: a new lock
        # was created at the name between our read and our rename, and
        # our rename moved that new (possibly live) lock. Restore it
        # with a NO-REPLACE operation: os.rename would replace a lock
        # another contender created at the name in the meantime, making
        # its owner believe it still holds the lock while we publish.
        try:
            os.link(stale, lock)
        except FileExistsError as exc:
            # The name is taken again: the quarantined lock is left in
            # place (never deleted) and the name is NOT freed. This is
            # not a normal retry — the owner of the quarantined lock may
            # still be publishing, so acquisition must fail loudly.
            # The FileExistsError is chained so the original cause is
            # not lost from the traceback.
            raise WPSSHBackupError(
                f"Could not restore the publish lock {lock!s}: another "
                "lock appeared while a newer lock was being quarantined. "
                f"The quarantined lock is at {stale!s}; verify no backup "
                "is running, then remove both files and re-run."
            ) from exc
        except OSError as exc:
            # Linking is unsupported or failed for another reason: the
            # quarantined lock cannot be put back, so the name must not
            # be reused. Fail rather than retrying into a free name.
            raise WPSSHBackupError(
                f"Could not restore the publish lock {lock!s}: {exc}. "
                f"The quarantined lock is at {stale!s}; verify no backup "
                "is running, then remove both files and re-run."
            ) from exc
        try:
            os.unlink(stale)
        except OSError:
            # The lock is restored; the quarantine name is now a second
            # link to it and removing it is best-effort.
            pass
        return False
    try:
        os.unlink(stale)
    except OSError:
        pass
    return True


def try_create_publish_lock(lock: Path) -> tuple[int, int] | None:
    """Create the publish lock with its owner recorded atomically.

    The PID is written to a private temporary file in the same
    directory, which is then hard-linked to the lock name. The link is
    the atomic publication step: the lock name never exists without its
    owner recorded, so a contender can never observe an empty lock and
    mistake a live creator for a crashed one. (Writing the PID after an
    O_EXCL create leaves exactly that window: a creator paused between
    create and write would look stale.)

    On filesystems without hard links, the lock name is created with
    O_CREAT|O_EXCL instead — a true no-replace primitive. os.rename is
    never used: it would replace a live lock on POSIX.

    Args:
        lock: The lock file to create.

    Returns:
        The (st_dev, st_ino) of the created lock, or None when the lock
        name is already taken (the caller retries or reclaims).
    """
    # The staging name is created with O_CREAT|O_EXCL, so it can never
    # replace an existing file. The random suffix also makes it
    # unguessable, so a concurrent writer cannot pre-create it and
    # deny this run the lock.
    tmp = safe_fs.quarantine_name(lock)
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError:
        return None
    try:
        try:
            os.write(fd, f"{os.getpid()}\n".encode())
            st = os.fstat(fd)
            identity = (st.st_dev, st.st_ino)
        finally:
            os.close(fd)
        try:
            # No-replace: fails with FileExistsError if another run
            # already holds the lock.
            os.link(tmp, lock)
        except FileExistsError:
            return None
        except OSError:
            # Hard links unsupported on this filesystem. Fall back to an
            # exclusive create of the lock name itself: O_CREAT|O_EXCL
            # is a true no-replace primitive, whereas os.rename would
            # REPLACE a live lock on POSIX and let two publishers run
            # concurrently. The lock is briefly empty until the PID is
            # written; an empty lock is never reclaimed (see
            # steal_stale_lock), so this fails closed rather than
            # stealing a live lock.
            return _create_lock_exclusive(lock)
        return identity
    finally:
        # The temporary name is only a staging name; the lock itself is
        # a separate link to the same inode.
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _create_lock_exclusive(lock: Path) -> tuple[int, int] | None:
    """Create the lock name with O_CREAT|O_EXCL and record its owner.

    A true no-replace primitive for filesystems without hard links:
    O_EXCL fails when the name already exists, so a live lock is never
    replaced. The PID is written immediately after creation; the lock is
    briefly empty in between, and an empty lock is never reclaimed (it
    fails closed and names the administrator recovery path).

    Args:
        lock: The lock file to create.

    Returns:
        The (st_dev, st_ino) of the created lock, or None when the name
        is already taken or the owner could not be recorded.
    """
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError:
        return None
    st = os.fstat(fd)
    identity = (st.st_dev, st.st_ino)
    try:
        os.write(fd, f"{os.getpid()}\n".encode())
    except OSError:
        os.close(fd)
        # This run created the lock exclusively, so removing it is safe
        # and keeps a half-written lock from blocking later runs.
        safe_fs.unlink_if_same_inode_atomic(lock, identity, warn=False)
        return None
    os.close(fd)
    return identity


@contextmanager
def exclusive_publish_lock(
    backup_dir: Path,
) -> Generator[None, None, None]:
    """Hold an exclusive lock file in backup_dir across publication.

    The lock is created with O_CREAT | O_EXCL: only one run can hold it
    at a time, so a cooperative concurrent backup run cannot publish
    into the directory while this run does. Acquisition retries briefly
    (a run in its final cleanup releases the lock quickly) and then
    fails the run rather than publishing into an actively-written
    directory. The final all-finals re-check runs under this lock, so no
    cooperative writer can be mid-publication when the run reports
    success.

    Stale locks are reclaimed automatically: the lock records the PID
    of its creator, and when creation fails because a lock already
    exists, the recorded PID is probed. A lock whose creator is
    verifiably dead (a crash, SIGKILL or host shutdown) is atomically
    renamed aside and removed, so a later run acquires the lock instead
    of failing. A lock whose PID is alive — including a recycled PID
    owned by an unrelated live process — is never stolen. Ownership is
    recorded ATOMICALLY: the PID is written to a private temporary file
    which is then hard-linked into place, so a lock is never visible
    without its owner. An unparseable lock is therefore corruption or a
    foreign file and is never reclaimed on age alone; the final error
    names the administrator recovery path (delete the lock file).

    The lock is released by atomically removing only the inode this
    process created (identity check via
    safe_fs.unlink_if_same_inode_atomic): a lock created by a later run
    after this process crashed or was killed is never unlinked.

    A local attacker who can write BACKUP_DIR can unlink this lock and
    race the final re-check; that residual window is inherent to a
    writable directory and is the reason publication also never creates
    a final path without a no-replace operation.

    Args:
        backup_dir: The directory whose publication is being guarded.

    Yields:
        None, while the lock is held.
    """
    lock = backup_dir / PUBLISH_LOCK_NAME
    identity: tuple[int, int] | None = None
    for _ in range(PUBLISH_LOCK_ATTEMPTS):
        identity = try_create_publish_lock(lock)
        if identity is not None:
            break
        if steal_stale_lock(lock):
            # The stale lock was reclaimed; retry the create on the
            # next iteration.
            continue
        time.sleep(PUBLISH_LOCK_RETRY_DELAY)
    if identity is None:
        raise WPSSHBackupError(
            f"Another backup appears to be publishing to {backup_dir}. "
            "If no backup process is running, the publish lock may be "
            f"stale: delete {lock!s} (and any .wp-ssh-backup.lock.stale-* "
            "files) and re-run."
        )
    try:
        yield
    finally:
        # Remove only the lock inode this run created; a lock created by
        # a later run after we died must not be unlinked.
        safe_fs.unlink_if_same_inode_atomic(lock, identity, warn=False)
