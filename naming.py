"""Timestamps, backup identifiers and artifact file names.

Every artifact name the tool produces is derived here, so the
naming scheme is described in exactly one place.
"""

from __future__ import annotations

import posixpath
import re
import secrets
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Timestamps and file naming
# ---------------------------------------------------------------------------

TS_FORMAT = "%Y%m%dT%H%MZ"
TS_PATTERN = r"\d{8}T\d{4}Z"
RUN_SUFFIX_RE = r"(?:-[0-9a-f]{6})?"
BACKUP_ID_PATTERN = TS_PATTERN + RUN_SUFFIX_RE
STAGING_PREFIX = "wp-ssh-backup-staging-"

BACKUP_FILE_RE = re.compile(
    r"^wp-(?P<kind>db|files)-(?P<bid>" + BACKUP_ID_PATTERN + r")\.tar\.gz"
    r"(\.sha256)?$"
)


def utc_timestamp(now: datetime | None = None) -> str:
    """
    Return a UTC timestamp string such as 20261014T0930Z.

    Args:
        now: The current datetime. If None, the current UTC time is used.

    Returns:
        A string representing the UTC timestamp.
    """
    return (now or datetime.now(timezone.utc)).strftime(TS_FORMAT)

def backup_id(now: datetime | None = None) -> str:


    """
    Return a unique backup identifier: UTC timestamp plus a random suffix.

    The suffix makes concurrent runs in the same minute exclusive: each run
    stages, transfers and names its artifacts independently, so two backups
    can never overwrite or delete one another's files.

    Args:
        now: The current datetime. If None, the current UTC time is used.

    Returns:
        An identifier such as '20261014T0930Z-a1b2c3'.
    """
    return f"{utc_timestamp(now)}-{secrets.token_hex(3)}"



def parse_timestamp(ts: str) -> datetime:
    """
    Parse a timestamp string produced by utc_timestamp().

    Args:
        ts: The timestamp string to parse.

    Returns:
        A datetime object representing the parsed UTC timestamp.


    """
    return datetime.strptime(ts, TS_FORMAT).replace(tzinfo=timezone.utc)

def parse_backup_id(bid: str) -> datetime:
    """
    Parse a backup identifier into its UTC datetime.

    Accepts both plain timestamps ('20261014T0930Z') and identifiers with a
    run suffix ('20261014T0930Z-a1b2c3'), so older backups without suffixes
    remain valid.

    Args:
        bid: The backup identifier to parse.

    Returns:


        A datetime object representing the parsed UTC timestamp.
    """
    ts_part = bid.split("-", 1)[0]
    return parse_timestamp(ts_part)

def staging_dir_for(site_root: str, bid: str) -> str:
    """
    Sibling directory of the site root used to stage remote artifacts.

    A sibling (rather than a directory inside the site root) keeps the staging
    files out of the file tarball and on the same filesystem for fast tars.
    The directory name embeds the backup identifier, making it exclusive to
    one run.

    Args:
        site_root: The root directory of the WordPress site.
        bid: The backup identifier to include in the directory name.



    Returns:
        The path to the staging directory.
    """
    parent = posixpath.dirname(site_root.rstrip("/")) or "/"
    return posixpath.join(parent, STAGING_PREFIX + bid)

def db_archive_name(ts: str) -> str:
    """
    Return the filename for a database backup archive with the given timestamp.



    Args:
        ts: The timestamp string to include in the archive filename.

    Returns:
        The filename for the database backup archive.
    """
    return f"wp-db-{ts}.tar.gz"

def files_archive_name(ts: str) -> str:


    """
    Return the filename for a files backup archive with the given timestamp.

    Args:
        ts: The timestamp string to include in the archive filename.

    Returns:
        The filename for the files backup archive.
    """
    return f"wp-files-{ts}.tar.gz"


def checksum_name(archive_name: str) -> str:
    """
    Return the filename for the checksum file corresponding to the given
    archive.

    Args:
        archive_name: The name of the archive file.

    Returns:
        The name of the checksum file.
    """
    return archive_name + ".sha256"

def backup_id_from_archive_name(name: str) -> str | None:
    """
    Return the backup identifier encoded in an archive filename.

    Args:
        name: The name of the archive file.

    Returns:
        The backup identifier (timestamp plus optional run suffix) if found,
        otherwise None.
    """
    match = BACKUP_FILE_RE.match(name)
    if match and name.endswith(".tar.gz"):
        return match.group("bid")
    return None
