"""One-off helper: restore the quarantine-move test coverage.

Three things are restored:

1. The 3 failing tests monkeypatch ``os.replace`` again -- that is the
   function the production code uses for the quarantine move. They had
   been reverted to ``os.rename``, so the simulated race never fired.
2. The 7 round-14 tests deleted by 29e93f2 are restored.
3. A shared helper ``intercept_quarantine_move`` is added, so the tests
   patch the function the production code actually calls instead of
   hard-coding a name that can drift again.
"""

import re

PATH = "tests/test_backup.py"

HELPER = '''

def intercept_quarantine_move(
    monkeypatch: pytest.MonkeyPatch,
    module,
    on_move,
) -> None:
    """Patch the function that performs the quarantine move.

    The quarantine move is performed with ``os.replace`` (it must
    overwrite the process's own empty reservation, and ``os.rename``
    refuses to replace on Windows). Tests that need to observe the
    moment of the move must therefore patch ``os.replace`` -- patching
    ``os.rename`` silently does nothing, which makes the simulated race
    never happen and the test vacuous.

    Args:
        monkeypatch: The pytest monkeypatch fixture.
        module: The module whose ``os`` attribute is patched.
        on_move: Called as ``on_move(src, dst)`` after the move.
    """
    original = module.os.replace

    def intercepting(src, dst):
        result = original(src, dst)
        on_move(src, dst)
        return result

    monkeypatch.setattr(module.os, "replace", intercepting)

'''


def patch_module(source, old, new, count=1):
    if old not in source:
        raise SystemExit(f"block not found:\n{old[:400]}")
    return source.replace(old, new, count)


with open(PATH, "rb") as handle:
    raw = handle.read()

text = raw.decode("utf-8")
crlf = "\r\n" in text
source = text.replace("\r\n", "\n")

# --- 1. Restore the three monkeypatches -------------------------------

source = patch_module(
    source,
    """    original_rename = os.rename

    def rename_new_lock(src, dst):
        if src == lock:
            # Simulate the other contender: it already reclaimed the
            # stale lock and created a NEW live lock at the name, so
            # this process's rename moves the NEW lock, not the stale
            # one it read. The new lock must be a genuinely different
            # inode: unlink+recreate can reuse the freed inode number
            # (ext4/tmpfs), and os.rename cannot replace an existing
            # destination on Windows, so the new lock is written to a
            # separate path and moved over the name with os.replace
            # (a distinct function, unaffected by this monkeypatch).
            fresh = tmp_path / "fresh-lock"
            fresh.write_text(f"{os.getpid()}\\n")
            os.replace(fresh, lock)
        return original_rename(src, dst)

    monkeypatch.setattr(publish_lock.os, "rename", rename_new_lock)
""",
    """    original_replace = os.replace

    def replace_new_lock(src, dst):
        if src == lock:
            # Simulate the other contender: it already reclaimed the
            # stale lock and created a NEW live lock at the name, so
            # this process's quarantine move takes the NEW lock, not
            # the stale one it read. The new lock must be a genuinely
            # different inode: unlink+recreate can reuse the freed
            # inode number (ext4/tmpfs), so the new lock is written to
            # a separate path and moved over the name with a
            # hard link + unlink, which does not go through
            # os.replace and is therefore unaffected by this patch.
            fresh = tmp_path / "fresh-lock"
            fresh.write_text(f"{os.getpid()}\\n")
            os.link(fresh, lock)
            os.unlink(fresh)
        return original_replace(src, dst)

    monkeypatch.setattr(publish_lock.os, "replace", replace_new_lock)
""",
)

source = patch_module(
    source,
    """    original_rename = os.rename
    # Distinct contents so the assertion can tell the two contenders
    # apart: the FIRST lock is the one this process's rename moves to
    # the quarantine path; the SECOND is the one that must survive.
    first_pid = os.getpid()
    second_pid = os.getpid() + 1

    def rename_moves_new_lock(src, dst):
        if src == lock:
            # A contender already reclaimed the stale lock and created a
            # NEW lock at the name, so this process's rename moves the
            # NEW lock (a different inode) to the quarantine path.
            first = tmp_path / "contender-lock-1"
            first.write_text(f"{first_pid}\\n")
            os.replace(first, lock)
            result = original_rename(src, dst)
            # Before the restore runs, ANOTHER contender takes the name.
            second = tmp_path / "contender-lock-2"
            second.write_text(f"{second_pid}\\n")
            os.replace(second, lock)
            return result
        return original_rename(src, dst)

    monkeypatch.setattr(publish_lock.os, "rename", rename_moves_new_lock)
""",
    """    original_replace = os.replace
    # Distinct contents so the assertion can tell the two contenders
    # apart: the FIRST lock is the one this process's quarantine move
    # takes to the quarantine path; the SECOND is the one that must
    # survive.
    first_pid = os.getpid()
    second_pid = os.getpid() + 1

    def replace_moves_new_lock(src, dst):
        if src == lock:
            # A contender already reclaimed the stale lock and created a
            # NEW lock at the name, so this process's quarantine move
            # takes the NEW lock (a different inode) to the quarantine
            # path.
            first = tmp_path / "contender-lock-1"
            first.write_text(f"{first_pid}\\n")
            os.link(first, lock)
            os.unlink(first)
            result = original_replace(src, dst)
            # Before the restore runs, ANOTHER contender takes the name.
            second = tmp_path / "contender-lock-2"
            second.write_text(f"{second_pid}\\n")
            os.link(second, lock)
            os.unlink(second)
            return result
        return original_replace(src, dst)

    monkeypatch.setattr(publish_lock.os, "replace", replace_moves_new_lock)
""",
)

source = patch_module(
    source,
    """    original_rename = os.rename

    def renaming(src, dst):
        original_rename(src, dst)
        if Path(src) == path and ".quarantine-" in Path(dst).name:
            # After the path is claimed for quarantine, another process
            # creates a fresh file at the original pathname.
            newcomer = tmp_path / "newcomer.part"
            newcomer.write_bytes(b"newcomer-bytes")
            os.replace(newcomer, path)

    monkeypatch.setattr(os, "rename", renaming)
""",
    """    def on_move(src, dst):
        if Path(src) == path and ".quarantine-" in Path(dst).name:
            # After the path is claimed for quarantine, another process
            # creates a fresh file at the original pathname.
            newcomer = tmp_path / "newcomer.part"
            newcomer.write_bytes(b"newcomer-bytes")
            os.link(newcomer, path)
            os.unlink(newcomer)

    intercept_quarantine_move(monkeypatch, safe_fs, on_move)
""",
)

# --- 2. Restore the deleted round-14 tests ----------------------------

with open("_restored_tests.py", "rb") as handle:
    restored = handle.read().decode("utf-8").replace("\r\n", "\n")

anchor = """
def test_publish_by_rename_publishes_verified_inode(
"""
if anchor not in source:
    raise SystemExit("anchor not found")

source = source.replace(
    anchor, "\n" + restored.strip("\n") + "\n\n" + anchor, 1)

# --- 3. Add the shared helper -----------------------------------------

helper_anchor = """
def test_steal_stale_lock_does_not_steal_new_lock(
"""
if helper_anchor not in source:
    raise SystemExit("helper anchor not found")

source = source.replace(helper_anchor, HELPER + helper_anchor, 1)

if crlf:
    source = source.replace("\n", "\r\n")

with open(PATH, "wb") as handle:
    handle.write(source.encode("utf-8"))

print("done")
