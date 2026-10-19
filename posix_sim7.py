"""POSIX check: does the no-replace restore discriminate from rename?"""
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


def steal(lock: Path, restore_with_link: bool) -> bool:
    try:
        pid = int(lock.read_text(encoding="ascii", errors="strict").strip())
    except (OSError, ValueError):
        return False
    if pid_alive(pid):
        return False
    st = os.lstat(lock)
    lock_identity = (st.st_dev, st.st_ino)
    stale = quarantine_name(lock)
    try:
        os.rename(lock, stale)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    st = os.lstat(stale)
    if (st.st_dev, st.st_ino) != lock_identity:
        if restore_with_link:
            try:
                os.link(stale, lock)
            except OSError:
                return False
            try:
                os.unlink(stale)
            except OSError:
                pass
            return False
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


def run(restore_with_link: bool) -> None:
    d = Path(tempfile.mkdtemp())
    lock = d / ".wp-ssh-backup.lock"
    lock.write_text(f"{2**30}\n")
    original_rename = os.rename
    first_pid = os.getpid()
    second_pid = os.getpid() + 1

    def hook(src, dst):
        if src == lock:
            f1 = d / "c1"
            f1.write_text(f"{first_pid}\n")
            os.replace(f1, lock)
            r = original_rename(src, dst)
            f2 = d / "c2"
            f2.write_text(f"{second_pid}\n")
            os.replace(f2, lock)
            return r
        return original_rename(src, dst)

    os.rename = hook
    try:
        res = steal(lock, restore_with_link)
    finally:
        os.rename = original_rename
    content = lock.read_text().strip()
    label = "link" if restore_with_link else "rename"
    print(
        f"{label}: result={res} content={content} "
        f"second_preserved={content == str(second_pid)}"
    )


run(restore_with_link=False)  # old behaviour
run(restore_with_link=True)   # fixed behaviour
