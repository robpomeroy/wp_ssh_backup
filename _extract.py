"""Extract the 7 deleted round-14 tests from d1cbe25."""

import re
import subprocess

NAMES = [
    "test_quarantine_never_replaces_a_pre_existing_entry",
    "test_reserve_quarantine_name_is_unguessable_and_exclusive",
    "test_failed_quarantine_reservation_leaves_the_file_in_place",
    "test_failed_quarantine_reservation_does_not_raise_in_a_cleanup_path",
    "test_steal_stale_lock_reports_failure_when_no_name_can_be_reserved",
    "test_steal_stale_lock_binds_the_pid_to_the_lock_inode",
    "test_unlink_if_same_inode_atomic_restore_never_replaces_a_newcomer",
]

text = subprocess.run(
    ["git", "show", "d1cbe25:tests/test_backup.py"],
    capture_output=True,
    text=True,
    encoding="utf-8",
    check=True,
).stdout

lines = text.replace("\r\n", "\n").split("\n")

# Find each test's def line and the end of its body (next top-level def
# or decorator at column 0).
starts = []
for i, line in enumerate(lines):
    m = re.match(r"^def (test_\w+)", line)
    if m and m.group(1) in NAMES:
        starts.append((i, m.group(1)))

blocks = {}
for idx, (start, name) in enumerate(starts):
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if re.match(r"^(def |@|class )", lines[j]):
            end = j
            break
    blocks[name] = "\n".join(lines[start:end]).rstrip() + "\n"

with open("_restored_tests.py", "w", encoding="utf-8", newline="\r\n") as fh:
    for name in NAMES:
        if name in blocks:
            fh.write("\n\n")
            fh.write(blocks[name])
        else:
            print(f"MISSING: {name}")

print(f"wrote {len(blocks)} blocks")
