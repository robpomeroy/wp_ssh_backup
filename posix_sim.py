import os
import tempfile

d = tempfile.mkdtemp()
temp = os.path.join(d, "a.part")
final = os.path.join(d, "a")
with open(temp, "wb") as f:
    f.write(b"payload")
fd = os.open(temp, os.O_RDWR)
os.link(temp, final)  # publish as final
# POSIX allows unlinking a final while the temp fd is open
os.unlink(final)
print("unlink-while-open:", not os.path.exists(final))
os.close(fd)
# quarantine simulation
q = os.path.join(d, "quarantine")
os.rename(temp, q)
os.unlink(q)
print("quarantine-unlink:", not os.path.exists(q))
