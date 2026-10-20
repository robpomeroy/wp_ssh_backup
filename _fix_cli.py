"""One-off helper: fix the cli.py append.

Two problems:
1. The ``@contextmanager`` decorator was dropped from ``timed`` (the
   splitter split the decorator off from the function).
2. ``human_size`` and ``timed`` ended up in the wrong order and
   ``human_size`` is missing a blank line.
"""

PATH = "cli.py"

OLD = '''def timed(label: str) -> Generator[None, None, None]:
    """Time a block of work and report how long it took.

    The message is printed only when the block completed successfully.
    The print sits after the yield, so it runs when the `with` block
    exits normally; if the block raises, the exception is thrown in at
    the yield point and the completion message is never printed. A
    failed operation is therefore never reported as having finished.

    Args:
        label: What the block does, e.g. "Files extracted".

    Yields:
        None, while the block runs.
    """
    started = time.monotonic()
    yield
    print(f"{label} ({time.monotonic() - started:.1f}s).")

def human_size(num_bytes: int | float) -> str:
    """
    Convert a size in bytes to a human-readable string with appropriate units.

    Args:
        num_bytes: The size in bytes.

    Returns:
        A human-readable string representing the size.
    """
    size = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"
'''

NEW = '''def human_size(num_bytes: int | float) -> str:
    """
    Convert a size in bytes to a human-readable string with appropriate units.

    Args:
        num_bytes: The size in bytes.

    Returns:
        A human-readable string representing the size.
    """
    size = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


@contextmanager
def timed(label: str) -> Generator[None, None, None]:
    """Time a block of work and report how long it took.

    The message is printed only when the block completed successfully.
    The print sits after the yield, so it runs when the `with` block
    exits normally; if the block raises, the exception is thrown in at
    the yield point and the completion message is never printed. A
    failed operation is therefore never reported as having finished.

    Args:
        label: What the block does, e.g. "Files extracted".

    Yields:
        None, while the block runs.
    """
    started = time.monotonic()
    yield
    print(f"{label} ({time.monotonic() - started:.1f}s).")
'''

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
