"""POSIX simulation of _publish_by_rename's source-swap rejection."""
import os
import tempfile

d = tempfile.mkdtemp()
temp = os.path.join(d, "a.part")
final = os.path.join(d, "a")

# Verified temp + held fd
with open(temp, "wb") as f:
    f.write(b"verified-payload")
fd = os.open(temp, os.O_RDWR)
held = os.fstat(fd)
held_identity = (held.st_dev, held.st_ino)

# Writer swaps temp for a different regular file (POSIX allows this
# even while the fd is held open).
replacement = os.path.join(d, "replacement.part")
with open(replacement, "wb") as f:
    f.write(b"attacker-bytes")
os.replace(replacement, temp)

# Fallback: hard-link temp -> final
os.link(temp, final)
linked = os.lstat(final)
linked_identity = (linked.st_dev, linked.st_ino)

# Re-open no-follow + compare against held identity
fd2 = os.open(final, os.O_RDONLY)
pub = os.fstat(fd2)
match = (pub.st_dev, pub.st_ino) == held_identity
print("published-matches-held:", match)
print("final-exists:", os.path.exists(final))
# Rollback would remove only if identity matches
os.close(fd2)
os.close(fd)
