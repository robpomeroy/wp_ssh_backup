"""One-off helper: move BACKUP_FILE_RE into naming.py.

The regex encodes the artifact naming scheme, so it belongs with the
other naming constants in naming.py. retention.py imports it from
there, which keeps the dependency one-way (retention -> naming).
"""

# --- naming.py: add the constant next to the other naming patterns ---

NAMING = "naming.py"
RETENTION = "retention.py"

NAMING_OLD = """BACKUP_ID_PATTERN = TS_PATTERN + RUN_SUFFIX_RE
STAGING_PREFIX = "wp-ssh-backup-staging-"
"""

NAMING_NEW = """BACKUP_ID_PATTERN = TS_PATTERN + RUN_SUFFIX_RE
STAGING_PREFIX = "wp-ssh-backup-staging-"

BACKUP_FILE_RE = re.compile(
    r"^wp-(?P<kind>db|files)-(?P<bid>" + BACKUP_ID_PATTERN + r")\\.tar\\.gz"
    r"(\\.sha256)?$"
)
"""

RETENTION_OLD = """from naming import (
    BACKUP_ID_PATTERN,
    backup_id_from_archive_name,
    parse_backup_id,
)
"""

RETENTION_NEW = """from naming import (
    BACKUP_FILE_RE,
    backup_id_from_archive_name,
    parse_backup_id,
)
"""

RETENTION_OLD_RE = '''BACKUP_FILE_RE = re.compile(
    r"^wp-(?P<kind>db|files)-(?P<bid>" + BACKUP_ID_PATTERN + r")\\.tar\\.gz"
    r"(\\.sha256)?$"
)


'''

RETENTION_IMPORT_OLD = """import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
"""

RETENTION_IMPORT_NEW = """from datetime import datetime, timedelta, timezone
from pathlib import Path
"""


def apply(path, old, new):
    with open(path, "rb") as handle:
        raw = handle.read()

    text = raw.decode("utf-8")
    crlf = "\r\n" in text
    source = text.replace("\r\n", "\n")

    if old not in source:
        raise SystemExit(f"block not found in {path}:\n{old!r}")

    source = source.replace(old, new, 1)

    if crlf:
        source = source.replace("\n", "\r\n")

    with open(path, "wb") as handle:
        handle.write(source.encode("utf-8"))

    print(f"edited {path}")


# naming.py needs `re` for the regex.
apply(NAMING, "import posixpath\nimport secrets\n",
      "import posixpath\nimport re\nimport secrets\n")
apply(NAMING, NAMING_OLD, NAMING_NEW)

# retention.py: drop the regex, import it instead.
apply(RETENTION, RETENTION_IMPORT_OLD, RETENTION_IMPORT_NEW)
apply(RETENTION, RETENTION_OLD_RE, "")
apply(RETENTION, RETENTION_OLD, RETENTION_NEW)
