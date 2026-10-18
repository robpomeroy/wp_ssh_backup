"""Standalone POSIX simulation of _pid_alive + _steal_stale_lock logic."""
import os
import tempfile
import time
from pathlib import Path


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True


_counter = 0


def quarantine_name(path: Path) -> Path:
    global _counter
    _counter += 1
    return path.with_name(
        f".{path.name}.quarantine-{os.getpid()}-{_counter}"
    )


GRACE = 5.0


def steal_stale_lock(lock: Path) -> bool:
    try:
        pid = int(lock.read_text(encoding="ascii", errors="strict").strip())
    except (OSError, ValueError):
        try:
            age = time.time() - lock.stat().st_mtime
        except OSError:
            return False
        if age < GRACE:
            return False
    else:
        if pid_alive(pid):
            return False
    stale = quarantine_name(lock)
    try:
        os.rename(lock, stale)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        os.unlink(stale)
    except OSError:
        pass
    return True


d = tempfile.mkdtemp()
lock = Path(d) / ".wp-ssh-backup.lock"

# Case 1: stale (dead PID) -> stolen
lock.write_text("1073741824\n")  # 2**30
print(
    "stale-pid-stolen:",
    steal_stale_lock(lock) is True,
    "| lock-exists:",
    lock.exists(),
)

# Case 2: live PID (our own) -> not stolen
lock.write_text(f"{os.getpid()}\n")
print("live-pid-not-stolen:", steal_stale_lock(lock) is False)

# Case 3: empty lock, recent mtime -> not stolen (grace)
lock.write_bytes(b"")
print("recent-empty-not-stolen:", steal_stale_lock(lock) is False)

# Case 4: empty lock, old mtime -> stolen
lock.write_bytes(b"")
old = time.time() - 60
os.utime(lock, (old, old))
print(
    "old-empty-stolen:",
    steal_stale_lock(lock) is True,
    "| lock-exists:",
    lock.exists(),
)
