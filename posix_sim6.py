"""POSIX simulation of the updated steal test (os.replace swap)."""
import os
import tempfile
import time
from pathlib import Path

_counter = 0


def quarantine_name(path: Path) -> Path:
    global _counter
    _counter += 1
    return path.with_name(f".{path.name}.quarantine-{os.getpid()}-{_counter}")


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
    try:
        st = os.lstat(lock)
        lock_identity = (st.st_dev, st.st_ino)
    except OSError:
        return False
    stale = quarantine_name(lock)
    try:
        os.rename(lock, stale)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        st = os.lstat(stale)
    except OSError:
        return True
    if (st.st_dev, st.st_ino) != lock_identity:
        try:
            os.rename(stale, lock)
        except OSError:
            pass
        return False
    try:
        os.unlink(stale)
    except OSError:
        pass
    return True


d = Path(tempfile.mkdtemp())
lock = d / ".wp-ssh-backup.lock"
lock.write_text(f"{2**30}\n")
original_rename = os.rename


def rename_new_lock(src, dst):
    if src == lock:
        fresh = d / "fresh-lock"
        fresh.write_text(f"{os.getpid()}\n")
        os.replace(fresh, lock)
    return original_rename(src, dst)


os.rename = rename_new_lock
try:
    result = steal_stale_lock(lock)
finally:
    os.rename = original_rename
print("steal-refused:", result is False)
print("lock-preserved:", lock.exists(), "| pid:", lock.read_text().strip())
