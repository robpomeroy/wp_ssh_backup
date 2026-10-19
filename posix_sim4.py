"""POSIX simulation: _publish_by_rename rollback uses held_identity."""
import os
import tempfile

d = tempfile.mkdtemp()
temp = os.path.join(d, "a.part")
final = os.path.join(d, "a")

with open(temp, "wb") as f:
    f.write(b"payload")
fd = os.open(temp, os.O_RDWR)
held = os.fstat(fd)
held_identity = (held.st_dev, held.st_ino)

# Publish: hard-link temp -> final
os.link(temp, final)

# Writer replaces final with a different inode BEFORE reopen fails
replacement = os.path.join(d, "replacement")
with open(replacement, "wb") as f:
    f.write(b"other")
os.replace(replacement, final)

# Rollback with held_identity: final is now the replacement inode, so
# _unlink_if_same_inode must NOT remove it.
# Simulate _unlink_if_same_inode_atomic's identity check:
st = os.lstat(final)
matches = (st.st_dev, st.st_ino) == held_identity
print("replacement-matches-held:", matches)
print("final-preserved:", os.path.exists(final),
      "| bytes:", open(final, "rb").read())

os.close(fd)
