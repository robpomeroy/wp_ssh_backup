"""SHA-256 checksums of local files and of remote manifests.

The manifest parsing is strict: a malformed or duplicated
record is an error rather than something to skip, because a
manifest that silently loses entries cannot be trusted to
describe an archive.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from pathlib import Path

from errors import ChecksumError

# ---------------------------------------------------------------------------
# Checksums
# ---------------------------------------------------------------------------


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    """
    Compute the SHA-256 checksum of a file.

    Args:
        path: The path to the file.
        chunk_size: The size of chunks to read from the file.

    Returns:
        The SHA-256 checksum as a hexadecimal string.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()

def verify_local_checksum(path: str | Path, expected_sha256: str) -> None:


    """
    Verify the SHA-256 checksum of a local file against an expected value.

    Args:
        path: The path to the file.
        expected_sha256: The expected SHA-256 checksum as a hexadecimal string.

    Raises:
        ChecksumError: If the actual checksum does not match the expected
        value.
    """
    actual = sha256_file(path)
    if actual.lower() != expected_sha256.lower():
        raise ChecksumError(
            f"Checksum mismatch for {path}: expected {expected_sha256}, "
            f"got {actual}"
        )


SHA256SUM_LINE_RE = re.compile(r"^([0-9a-fA-F]{64})\s+[ *](.+)$", re.MULTILINE)



def parse_sha256sum_output(text: str) -> dict[str, str]:
    """
    Parse `sha256sum` output into a dictionary mapping filenames to their
    SHA-256 digests.

    Parsing is strict: every nonblank line must be a complete
    `<digest> <name>` record (blank lines are allowed as separators), and
    a filename may appear only once. Lenient parsing would let a manifest
    with a malformed record or duplicate entries collapse into fewer
    entries than it really contains, so callers relying on an exact entry
    count could accept an invalid manifest.

    Args:
        text: The output of the `sha256sum` command as a string.

    Returns:
        A dictionary where the keys are filenames and the values are the
        corresponding SHA-256 digests.

    Raises:
        ChecksumError: If any nonblank line is malformed or a filename is
            duplicated.
    """
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        match = SHA256SUM_LINE_RE.match(line)
        if not match:
            raise ChecksumError(
                f"Malformed checksum line: {line.strip()!r}"
            )
        digest, name = match.group(1), match.group(2)
        name = name.strip()
        if name in result:
            raise ChecksumError(
                f"Duplicate checksum entry for {name!r}"
            )
        result[name] = digest.lower()
    return result

# ---------------------------------------------------------------------------
# Checksum manifests
# ---------------------------------------------------------------------------





def validate_manifest_entries(
    entries: dict[str, str],
    archive_name: str,
    manifest_name: str,
) -> str:
    """
    Check a parsed checksum manifest and return the expected digest.

    A manifest is not trusted blindly: `sha256sum -c` checks whatever
    filename the manifest names, so a manifest pointing at another file
    with a matching digest would pass while the requested archive stays
    corrupt. The manifest must therefore contain exactly one entry, that
    entry must name exactly the requested archive, and no entry may name
    a path (no traversal).

    Args:
        entries: The manifest's parsed entries, keyed by file name.
        archive_name: The archive the manifest must describe.
        manifest_name: The manifest's name, used in the error messages.

    Returns:
        The digest the manifest records for the archive.

    Raises:
        ChecksumError: If the manifest names a path, holds more or fewer
            than one entry, or does not name the requested archive.
    """
    # Reject any path component in ANY entry name before anything
    # else: a manifest may only reference plain filenames, never paths.
    for entry_name in entries:
        if (
            "/" in entry_name
            or "\\" in entry_name
            or posixpath.basename(entry_name) != entry_name
            or entry_name in (".", "..")
        ):
            raise ChecksumError(
                f"{manifest_name} names a path outside the "
                f"staging directory: {entry_name}"
            )
    if len(entries) != 1:
        raise ChecksumError(
            f"{manifest_name} must contain exactly one entry, "
            f"found {len(entries)}"
        )
    if archive_name not in entries:
        raise ChecksumError(
            f"{manifest_name} does not name {archive_name}; the "
            "manifest cannot be trusted for this archive"
        )
    return entries[archive_name]
