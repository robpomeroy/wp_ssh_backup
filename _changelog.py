"""One-off helper: record the test repair in the changelog."""

PATH = "CHANGELOG.md"

OLD = """- A quarantine no longer replaces an unrelated entry. The quarantine name
  was built from the process ID and a counter, both of which are
  predictable, and the move into it used `os.rename`, which replaces the
  destination on POSIX. An entry left behind by an earlier run that
  happened to reuse the same process ID and counter — or one a concurrent
  writer pre-created at the predictable name — was therefore silently
  deleted, violating the identity-bound cleanup guarantee. The name now
  carries a 128-bit random suffix and is reserved with `O_CREAT | O_EXCL`
  before the source is moved into it, retrying with a fresh name on
  collision, so the only entry the move can replace is this process's own
  empty reservation. A failed reservation is reported and the file is
  left in place rather than removed unsafely.
"""

NEW = """- A quarantine no longer replaces an unrelated entry. The quarantine name
  was built from the process ID and a counter, both of which are
  predictable, and the move into it used `os.rename`, which replaces the
  destination on POSIX. An entry left behind by an earlier run that
  happened to reuse the same process ID and counter — or one a concurrent
  writer pre-created at the predictable name — was therefore silently
  deleted, violating the identity-bound cleanup guarantee. The name now
  carries a 128-bit random suffix and is reserved with `O_CREAT | O_EXCL`
  before the source is moved into it, retrying with a fresh name on
  collision, so the only entry the move can replace is this process's own
  empty reservation. A failed reservation is reported and the file is
  left in place rather than removed unsafely.
- The tests that exercise the quarantine move are no longer vacuous. They
  intercepted the move by patching `os.rename`, but the move is performed
  with `os.replace` (it has to overwrite the process's own empty
  reservation, and `os.rename` refuses to replace on Windows), so the
  simulated race never happened. The tests now patch the function the
  production code actually calls, through one shared helper, and the
  regression tests for the quarantine reservation are restored.
"""

with open(PATH, "rb") as handle:
    raw = handle.read()

text = raw.decode("utf-8")
crlf = "\r\n" in text
source = text.replace("\r\n", "\n")

if OLD not in source:
    raise SystemExit("block not found")

source = source.replace(OLD, NEW, 1)

if crlf:
    source = source.replace("\n", "\r\n")

with open(PATH, "wb") as handle:
    handle.write(source.encode("utf-8"))

print("done")
