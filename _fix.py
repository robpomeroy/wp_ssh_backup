"""One-off helper: fix the restored lock tests.

Two problems with the restored versions:

1. The swap used ``os.link(fresh, lock)``, which fails when the
   destination already exists (the stale lock is still there). The
   original used ``os.replace``, which replaces it. Using the captured
   ORIGINAL replace avoids the recursion that the original code had
   (and makes the intent obvious).
2. The ``@pytest.mark.skipif(os.name != "posix", ...)`` decorator on
   test_steal_stale_lock_binds_the_pid_to_the_lock_inode was lost
   during extraction. The test unlinks a file this process holds open,
   which Windows refuses.
"""

PATH = "tests/test_backup.py"

EDITS = []


def edit(old, new):
    EDITS.append((old, new))


edit(
    """            fresh = tmp_path / "fresh-lock"
            fresh.write_text(f"{os.getpid()}\\n")
            os.link(fresh, lock)
            os.unlink(fresh)
        return original_replace(src, dst)
""",
    """            fresh = tmp_path / "fresh-lock"
            fresh.write_text(f"{os.getpid()}\\n")
            original_replace(fresh, lock)
        return original_replace(src, dst)
""",
)

edit(
    """            first = tmp_path / "contender-lock-1"
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
""",
    """            first = tmp_path / "contender-lock-1"
            first.write_text(f"{first_pid}\\n")
            original_replace(first, lock)
            result = original_replace(src, dst)
            # Before the restore runs, ANOTHER contender takes the name.
            second = tmp_path / "contender-lock-2"
            second.write_text(f"{second_pid}\\n")
            original_replace(second, lock)
            return result
""",
)

edit(
    """def test_steal_stale_lock_binds_the_pid_to_the_lock_inode(
""",
    """@pytest.mark.skipif(
    os.name != "posix",
    reason="replacing an open lock file is a POSIX-only scenario",
)
def test_steal_stale_lock_binds_the_pid_to_the_lock_inode(
""",
)

with open(PATH, "rb") as handle:
    raw = handle.read()

text = raw.decode("utf-8")
crlf = "\r\n" in text
source = text.replace("\r\n", "\n")

for old, new in EDITS:
    if old not in source:
        raise SystemExit(f"block not found:\n{old}")
    source = source.replace(old, new, 1)

if crlf:
    source = source.replace("\n", "\r\n")

with open(PATH, "wb") as handle:
    handle.write(source.encode("utf-8"))

print("done")
