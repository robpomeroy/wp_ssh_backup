"""Report the shape of each MODULES entry."""

import re
import sys

sys.path.insert(0, ".")
import _split_common as sc  # noqa: E402

for name, value in sc.MODULES.items():
    print(f"{name:16} len={len(value)}  {type(value)}")
    if len(value) != 4:
        print("   !!! expected 4 parts")
