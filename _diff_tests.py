"""Compare test function names between d1cbe25 and HEAD."""

import re
import subprocess

NAMES = re.compile(r"^def (test_\w+)", re.M)


def names(rev):
    text = subprocess.run(
        ["git", "show", f"{rev}:tests/test_backup.py"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return set(NAMES.findall(text))


old = names("d1cbe25")
new = names("HEAD")

removed = sorted(old - new)
added = sorted(new - old)

print(f"d1cbe25: {len(old)} tests")
print(f"HEAD   : {len(new)} tests")
print()
print(f"REMOVED in 29e93f2 ({len(removed)}):")
for name in removed:
    print(f"  - {name}")
print()
print(f"ADDED in 29e93f2 ({len(added)}):")
for name in added:
    print(f"  + {name}")
