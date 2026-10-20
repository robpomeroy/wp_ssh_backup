"""One-off helper: fix shell.py.

The splitter carried the trailing "@contextmanager" from the Misc
section into shell.py. It belongs with timed() in cli.py, which the
splitter also moved there.
"""

PATH = "shell.py"

OLD = '''    return shquote(f"rm -f {shquote(path)}")


@contextmanager
'''

NEW = '''    return shquote(f"rm -f {shquote(path)}")
'''

with open(PATH, "rb") as handle:
    raw = handle.read()

text = raw.decode("utf-8")
crlf = "\r\n" in text
source = text.replace("\r\n", "\n")

if OLD not in source:
    raise SystemExit("block not found")

source = source.replace(OLD, NEW, 1)

# Two blank lines before the first def, per PEP 8.
source = source.replace(
    "from __future__ import annotations\n\ndef shquote",
    "from __future__ import annotations\n\n\ndef shquote",
    1,
)
# Two blank lines between the two functions.
source = source.replace(
    "\"'\" + path.replace(\"'\", \"'\\\\\\\\''\") + \"'\"\n\ndef trap_rm_action",
    "\"'\" + path.replace(\"'\", \"'\\\\\\\\''\") + \"'\"\n\n\ndef trap_rm_action",
    1,
)

if crlf:
    source = source.replace("\n", "\r\n")

with open(PATH, "wb") as handle:
    handle.write(source.encode("utf-8"))

print("done")
