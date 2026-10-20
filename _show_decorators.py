"""Show the decorators preceding each deleted test in d1cbe25."""

import re
import subprocess

text = subprocess.run(
    ["git", "show", "d1cbe25:tests/test_backup.py"],
    capture_output=True,
    text=True,
    encoding="utf-8",
    check=True,
).stdout

lines = text.replace("\r\n", "\n").split("\n")

TARGETS = [
    "test_steal_stale_lock_does_not_steal_new_lock",
    "test_steal_stale_lock_restore_does_not_clobber_newer_lock",
    "test_steal_stale_lock_binds_the_pid_to_the_lock_inode",
    "test_unlink_if_same_inode_atomic_restore_never_replaces_a_newcomer",
    "test_quarantine_never_replaces_a_pre_existing_entry",
    "test_reserve_quarantine_name_is_unguessable_and_exclusive",
    "test_failed_quarantine_reservation_leaves_the_file_in_place",
    "test_failed_quarantine_reservation_does_not_raise_in_a_cleanup_path",
    "test_steal_stale_lock_reports_failure_when_no_name_can_be_reserved",
]

for target in TARGETS:
    for i, line in enumerate(lines):
        if re.match(rf"^def {target}\b", line):
            # Collect the contiguous decorator block above.
            j = i - 1
            decos = []
            while j >= 0 and lines[j].startswith(("@", ")", "    ", '"', "'", "reason=")):
                decos.insert(0, lines[j])
                j -= 1
            # Trim trailing blank lines.
            while decos and decos[0].strip() == "":
                decos.pop(0)
            print(f"--- {target} ---")
            if decos:
                print("\n".join(decos))
            else:
                print("(no decorators)")
            print()
            break
    else:
        print(f"--- {target} --- NOT FOUND\n")
