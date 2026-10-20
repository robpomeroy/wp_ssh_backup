"""One-off helper: unify the quarantine-move interception.

The helper hands the callback the ORIGINAL move function, so the
callback controls the ordering (before or after the move) and can
perform its own moves without recursing into the patch. This gives
every test that needs to observe the quarantine move ONE documented
mechanism, so the tests cannot silently go vacuous again if the
function the production code calls changes.
"""

PATH = "tests/test_backup.py"

EDITS = []


def edit(old, new):
    EDITS.append((old, new))


# --- 1. Rewrite the helper ------------------------------------------------

edit(
    '''def intercept_quarantine_move(
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
''',
    '''def intercept_quarantine_move(
    monkeypatch: pytest.MonkeyPatch,
    module,
    on_move,
) -> None:
    """Patch the function that performs the quarantine move.

    The quarantine move is performed with ``os.replace``: it has to
    overwrite the process's own empty reservation, and ``os.rename``
    refuses to replace on Windows. A test that needs to observe the
    move must therefore patch ``os.replace`` -- patching ``os.rename``
    silently does nothing, so the simulated race never happens and the
    test goes vacuous while still passing.

    The callback is given the ORIGINAL move function, so it decides
    whether the race happens before or after the move, and can make its
    own moves without recursing into this patch.

    Args:
        monkeypatch: The pytest monkeypatch fixture.
        module: The module whose ``os`` attribute is patched.
        on_move: Called as ``on_move(src, dst, original)``. It must
            return the result of the move, and must call
            ``original(src, dst)`` to perform it.
    """
    original = module.os.replace

    def intercepting(src, dst):
        return on_move(src, dst, original)

    monkeypatch.setattr(module.os, "replace", intercepting)
''',
)

# --- 2. The first lock test: the swap happens BEFORE the move ------------

edit(
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
            original_replace(fresh, lock)
        return original_replace(src, dst)

    monkeypatch.setattr(publish_lock.os, "replace", replace_new_lock)
""",
    """    def replace_new_lock(src, dst, original):
        if src == lock:
            # Simulate the other contender: it already reclaimed the
            # stale lock and created a NEW live lock at the name, so
            # this process's quarantine move takes the NEW lock, not
            # the stale one it read. The new lock must be a genuinely
            # different inode: unlink+recreate can reuse the freed
            # inode number (ext4/tmpfs), so the new lock is written to
            # a separate path and moved over the name with the
            # ORIGINAL move, which this patch does not intercept.
            fresh = tmp_path / "fresh-lock"
            fresh.write_text(f"{os.getpid()}\\n")
            original(fresh, lock)
        return original(src, dst)

    intercept_quarantine_move(monkeypatch, publish_lock, replace_new_lock)
""",
)

# --- 3. The second lock test: a swap before AND after the move -----------

edit(
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
            original_replace(first, lock)
            result = original_replace(src, dst)
            # Before the restore runs, ANOTHER contender takes the name.
            second = tmp_path / "contender-lock-2"
            second.write_text(f"{second_pid}\\n")
            original_replace(second, lock)
            return result
        return original_replace(src, dst)

    monkeypatch.setattr(publish_lock.os, "replace", replace_moves_new_lock)
""",
    """    # Distinct contents so the assertion can tell the two contenders
    # apart: the FIRST lock is the one this process's quarantine move
    # takes to the quarantine path; the SECOND is the one that must
    # survive.
    first_pid = os.getpid()
    second_pid = os.getpid() + 1

    def replace_moves_new_lock(src, dst, original):
        if src == lock:
            # A contender already reclaimed the stale lock and created a
            # NEW lock at the name, so this process's quarantine move
            # takes the NEW lock (a different inode) to the quarantine
            # path.
            first = tmp_path / "contender-lock-1"
            first.write_text(f"{first_pid}\\n")
            original(first, lock)
            result = original(src, dst)
            # Before the restore runs, ANOTHER contender takes the name.
            second = tmp_path / "contender-lock-2"
            second.write_text(f"{second_pid}\\n")
            original(second, lock)
            return result
        return original(src, dst)

    intercept_quarantine_move(
        monkeypatch, publish_lock, replace_moves_new_lock
    )
""",
)

# --- 4. The restored "never replaces a newcomer" test --------------------

edit(
    """    original_unlink = os.unlink
    original_replace = os.replace

    def unlink(target, *args, **kwargs):
        # Simulate a cleanup failure: the owned inode cannot be
        # removed, so the restore path is taken.
        if ".quarantine-" in Path(target).name:
            raise PermissionError("cleanup denied")
        return original_unlink(target, *args, **kwargs)

    def rename(src, dst):
        result = original_replace(src, dst)
        if Path(src) == path and ".quarantine-" in Path(dst).name:
            # While the owned entry sits under the quarantine name, the
            # original pathname is free and another process takes it.
            newcomer = tmp_path / "newcomer.part"
            newcomer.write_bytes(b"newcomer-bytes")
            os.replace(newcomer, path)
        return result

    monkeypatch.setattr(os, "unlink", unlink)
    monkeypatch.setattr(os, "replace", rename)
""",
    """    original_unlink = os.unlink

    def unlink(target, *args, **kwargs):
        # Simulate a cleanup failure: the owned inode cannot be
        # removed, so the restore path is taken.
        if ".quarantine-" in Path(target).name:
            raise PermissionError("cleanup denied")
        return original_unlink(target, *args, **kwargs)

    def on_move(src, dst, original):
        result = original(src, dst)
        if Path(src) == path and ".quarantine-" in Path(dst).name:
            # While the owned entry sits under the quarantine name, the
            # original pathname is free and another process takes it.
            newcomer = tmp_path / "newcomer.part"
            newcomer.write_bytes(b"newcomer-bytes")
            original(newcomer, path)
        return result

    monkeypatch.setattr(os, "unlink", unlink)
    intercept_quarantine_move(monkeypatch, safe_fs, on_move)
""",
)

# --- 5. The "preserves new file" test: use the original for the newcomer

edit(
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
    """    def on_move(src, dst, original):
        result = original(src, dst)
        if Path(src) == path and ".quarantine-" in Path(dst).name:
            # After the path is claimed for quarantine, another process
            # creates a fresh file at the original pathname.
            newcomer = tmp_path / "newcomer.part"
            newcomer.write_bytes(b"newcomer-bytes")
            original(newcomer, path)
        return result

    intercept_quarantine_move(monkeypatch, safe_fs, on_move)
""",
)

with open(PATH, "rb") as handle:
    raw = handle.read()

text = raw.decode("utf-8")
crlf = "\r\n" in text
source = text.replace("\r\n", "\n")

for old, new in EDITS:
    if old not in source:
        raise SystemExit(f"block not found:\n{old[:300]}")
    source = source.replace(old, new, 1)

if crlf:
    source = source.replace("\n", "\r\n")

with open(PATH, "wb") as handle:
    handle.write(source.encode("utf-8"))

print("done")
