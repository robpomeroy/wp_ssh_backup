"""Extract a named section from common.py into a new module.

Sections are delimited by the banner comments:

    # ---------------------------------------------------------------------------
    # Section name
    # ---------------------------------------------------------------------------

The extraction copies the section body verbatim and writes it into a new
module with a header, the module's own imports, and (optionally) a
re-export block.

Usage (from the repo root):
    python _extract_module.py <section> <newmodule>
"""

import re
import sys
from pathlib import Path

COMMON = Path("common.py")
BANNER = re.compile(
    r"^# -{75}\n^# (?P<title>.+)\n^# -{75}\n", re.MULTILINE
)


def sections(text):
    """Return {title: (start, end)} line ranges for each banner."""
    out = {}
    matches = list(BANNER.finditer(text))
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        out[m.group("title")] = (start, end)
    return out


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    title, target = sys.argv[1], sys.argv[2]

    text = COMMON.read_text(encoding="utf-8")
    found = sections(text)
    if title not in found:
        raise SystemExit(
            f"section {title!r} not found; have: {sorted(found)}"
        )
    start, end = found[title]
    body = text[start:end].rstrip() + "\n"
    print(body)
    print(f"--- {len(body.splitlines())} lines in section {title!r} ---")


if __name__ == "__main__":
    main()
