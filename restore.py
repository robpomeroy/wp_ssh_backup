"""Restore a WordPress site from a WP SSH Backup set.

Uploads a chosen backup set to the remote host, verifies SHA-256 checksums
remotely, extracts the files tarball into the site root and imports the
database dump.
"""

from __future__ import annotations

import argparse
import posixpath
import shlex
import sys
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

from common import (
    ChecksumError,
    Config,
    MissingArtifactError,
    WPSSHBackupError,
    backup_id,
    backup_id_from_archive_name,
    checksum_name,
    connect,
    db_archive_name,
    detect_wp_cli,
    files_archive_name,
    find_backup_sets,
    load_config,
    mysql_client_config,
    parse_backup_id,
    parse_sha256sum_output,
    read_remote_file,
    read_wp_db_settings,
    remove_remote_file,
    remove_remote_staging,
    run_remote_cmd,
    run_remote_cmd_checked,
    shquote,
    split_db_host,
    staging_dir_for,
    trap_rm_action,
    utc_timestamp,
    write_remote_file,
)


# ---------------------------------------------------------------------------
# Local backup set selection
# ---------------------------------------------------------------------------


def list_backup_sets(backup_dir: Path) -> dict[str, dict[str, Path]]:
    """Return {timestamp: {archive_name: local_path}} for complete sets."""
    sets: dict[str, dict[str, Path]] = {}
    for ts, files in find_backup_sets(backup_dir).items():
        by_name = {path.name: path for path in files}
        sets[ts] = by_name
    return sets


def required_artifacts(
    bid: str, include_files: bool, include_database: bool
) -> list[str]:
    """Archive names a restore of the given kind needs (checksums implied)."""
    required: list[str] = []
    if include_files:
        required.append(files_archive_name(bid))
    if include_database:
        required.append(db_archive_name(bid))
    return required


def set_is_complete(
    set_files: dict[str, Path],
    include_files: bool,
    include_database: bool,
) -> bool:
    """True if the set contains every required archive and its checksum."""
    bid = ts_of(set_files)
    return all(
        name in set_files and checksum_name(name) in set_files
        for name in required_artifacts(bid, include_files, include_database)
    )


def resolve_timestamp(
    sets: dict[str, dict[str, Path]],
    timestamp: str,
) -> str:
    """
    Resolve a --timestamp value to an exact backup id in sets.

    Accepts a full backup id ('20261014T0930Z-a1b2c3') or a bare timestamp
    ('20261014T0930Z'). A bare timestamp resolves only when exactly one set
    matches; if several backups share the minute — including a legacy
    suffix-less set alongside suffixed ones — the error lists their full
    ids so the caller can disambiguate. Raises MissingArtifactError when
    nothing matches.

    Args:
        sets: The available backup sets, keyed by backup id.
        timestamp: The user-supplied value.

    Returns:
        The exact backup id of the requested set.
    """
    if "-" in timestamp:
        # A full id can only match itself; the bare-timestamp path below
        # would also match it, but the exact shortcut is unambiguous.
        if timestamp in sets:
            return timestamp
        available = ", ".join(sorted(sets)) or "(none)"
        raise MissingArtifactError(
            f"No backup set with timestamp {timestamp}. "
            f"Available: {available}"
        )
    matches = [bid for bid in sets if bid.split("-", 1)[0] == timestamp]
    if not matches:
        available = ", ".join(sorted(sets)) or "(none)"
        raise MissingArtifactError(
            f"No backup set with timestamp {timestamp}. "
            f"Available: {available}"
        )
    if len(matches) > 1:
        raise MissingArtifactError(
            f"Several backup sets share the timestamp {timestamp}; "
            "specify a full backup id instead. Available ids: "
            + ", ".join(sorted(matches))
        )
    return matches[0]


def choose_set(
    sets: dict[str, dict[str, Path]],
    timestamp: str | None,
    include_files: bool,
    include_database: bool,
    backup_dir: Path,
) -> dict[str, Path]:
    """
    Pick the backup set to restore, validating required artifacts exist.

    The timestamp argument accepts a full backup id
    ('20261014T0930Z-a1b2c3') or a bare timestamp ('20261014T0930Z'); a
    bare timestamp must match exactly one set. Without an explicit
    timestamp, sets are filtered to those containing the requested
    artifacts before the latest is chosen — the documented schedules can
    produce a database-only set newer than the latest files set, and that
    newer set must not block a files restore. An explicit timestamp is
    strict: it must exist and contain the requested artifacts, with no
    fallback to older sets.
    """
    if not sets:
        raise MissingArtifactError(f"No backup sets found in {backup_dir}.")
    if timestamp:
        chosen = sets[resolve_timestamp(sets, timestamp)]
    else:
        candidates = [
            files
            for files in sets.values()
            if set_is_complete(files, include_files, include_database)
        ]
        if not candidates:
            wanted = ", ".join(
                required_artifacts("*", include_files, include_database)
            )
            raise MissingArtifactError(
                "No backup set contains the requested artifact(s) "
                f"({wanted or 'none'}). "
                f"Searched {len(sets)} set(s) in {backup_dir}."
            )
        chosen = latest_set(candidates, backup_dir)
        print(
            f"No --timestamp given; using latest matching backup set: "
            f"{ts_of(chosen)}"
        )

    bid = ts_of(chosen)
    missing = [
        name
        for name in required_artifacts(bid, include_files, include_database)
        if name not in chosen or checksum_name(name) not in chosen
    ]
    if missing:
        raise MissingArtifactError(
            "Backup set is missing required artifact(s): " + ", ".join(missing)
        )
    return chosen


def ts_of(set_files: dict[str, Path]) -> str:
    """Extract the backup identifier from any archive filename in the set."""
    for name in set_files:
        bid = backup_id_from_archive_name(name)
        if bid:
            return bid
    raise MissingArtifactError("Backup set contains no archive files.")


def latest_set(
    candidates: list[dict[str, Path]],
    backup_dir: Path,
) -> dict[str, Path]:
    """
    Pick the most recent candidate set, rejecting same-minute ambiguity.

    The backup id's timestamp has minute resolution, so two complete sets
    can share it while differing only by their random run suffix. The
    suffix is random, not chronological, so comparing ids (or suffixes)
    cannot tell which run finished last. Rather than silently guessing,
    this raises and asks for an explicit full backup id.

    Args:
        candidates: Complete candidate sets.
        backup_dir: The backup directory, for the error message.

    Returns:
        The single most recent candidate set.

    Raises:
        MissingArtifactError: If two or more candidates share the newest
            timestamp.
    """
    newest = max(parse_backup_id(ts_of(files)) for files in candidates)
    newest_ids = [
        ts_of(files)
        for files in candidates
        if parse_backup_id(ts_of(files)) == newest
    ]
    if len(newest_ids) > 1:
        raise MissingArtifactError(
            f"Several backup sets in {backup_dir} share the newest "
            f"timestamp {utc_timestamp(newest)}; the run suffix is random, "
            "so recency cannot be determined. Specify a full backup id "
            "with --timestamp. Available ids: "
            + ", ".join(sorted(newest_ids))
        )
    return next(files for files in candidates if ts_of(files) == newest_ids[0])


# ---------------------------------------------------------------------------
# Remote restore
# ---------------------------------------------------------------------------


def _require_gnu_tar(client: paramiko.SSHClient) -> None:
    """
    Require GNU tar on the remote host before any restore work.

    Archive validation runs `tar --quoting-style=shell-always`, which
    BusyBox and BSD tar reject as an unknown option; without this check
    every restore involving an archive would fail on such hosts, after
    the upload. `tar --version` prints "tar (GNU tar) ..." on GNU tar
    and fails or prints nothing of the sort elsewhere.

    Raises:
        WPSSHBackupError: If GNU tar is not available.
    """
    code, out, _ = run_remote_cmd(client, "tar --version")
    if code != 0 or "(GNU tar)" not in out:
        raise WPSSHBackupError(
            "GNU tar is required on the remote host for restore "
            "(BusyBox and BSD tar are not supported): "
            f"`tar --version` reported {out.strip() or 'no output'}."
        )


def upload_artifacts(
    sftp: paramiko.SFTPClient,
    set_files: dict[str, Path],
    archive_names: list[str],
    staging: str,
) -> None:
    for name in archive_names:
        sftp_upload_checked(
            sftp, set_files[name], posixpath.join(staging, name)
        )
        sftp_upload_checked(
            sftp,
            set_files[checksum_name(name)],
            posixpath.join(staging, checksum_name(name)),
        )


def sftp_upload_checked(
    sftp: paramiko.SFTPClient, local: Path, remote: str
) -> None:
    if not local.is_file():
        raise MissingArtifactError(f"Local file missing: {local}")
    sftp.put(str(local), remote)


def verify_remote_checksums(
    client: paramiko.SSHClient,
    staging: str,
    archive_names: list[str],
) -> None:
    """
    Verify each uploaded archive against its uploaded .sha256 manifest.

    The manifest is not trusted blindly: `sha256sum -c` checks whatever
    filename the manifest names, so a manifest pointing at another file
    with a matching digest would pass while the requested archive stays
    corrupt. Instead the manifest is read and must contain exactly one
    entry naming exactly the requested archive (no path separators, so no
    traversal), and the archive's bytes are then hashed directly with
    `sha256sum` and compared to the manifest's digest.
    """
    sftp = client.open_sftp()
    try:
        for name in archive_names:
            checksum_remote = posixpath.join(staging, checksum_name(name))
            try:
                text = read_remote_file(sftp, checksum_remote)
            except FileNotFoundError as exc:
                raise ChecksumError(
                    f"Remote checksum file missing: {checksum_remote}"
                ) from exc
            entries = parse_sha256sum_output(text)
            # Reject any path component in ANY entry name before anything
            # else: a manifest may only reference plain filenames inside
            # the staging directory, never paths (no traversal).
            for entry_name in entries:
                if (
                    "/" in entry_name
                    or "\\" in entry_name
                    or posixpath.basename(entry_name) != entry_name
                    or entry_name in (".", "..")
                ):
                    raise ChecksumError(
                        f"{checksum_name(name)} names a path outside the "
                        f"staging directory: {entry_name}"
                    )
            if len(entries) != 1:
                raise ChecksumError(
                    f"{checksum_name(name)} must contain exactly one "
                    f"entry, found {len(entries)}"
                )
            if name not in entries:
                raise ChecksumError(
                    f"{checksum_name(name)} does not name {name}; the "
                    "manifest cannot be trusted for this archive"
                )
            # Hash the archive's bytes directly; the manifest only supplies
            # the expected digest.
            command = (
                f"cd {shquote(staging)} && "
                f"sha256sum {shquote(name)}"
            )
            code, out, err = run_remote_cmd(client, command)
            if code != 0:
                raise ChecksumError(
                    f"Could not hash {name} on the remote host: "
                    f"{err.strip()}"
                )
            actual = parse_sha256sum_output(out)
            if actual.get(name) != entries[name]:
                raise ChecksumError(
                    f"Remote checksum verification failed for {name}: "
                    f"expected {entries[name]}, got "
                    f"{actual.get(name, '(none)')}"
                )
    finally:
        sftp.close()


_ALLOWED_MEMBER_TYPES = frozenset({
    tarfile.REGTYPE,
    tarfile.AREGTYPE,
    tarfile.DIRTYPE,
    tarfile.SYMTYPE,
    tarfile.LNKTYPE,
})


def _validate_local_member_types(archive: Path) -> None:
    """
    Reject a files archive containing any non-allowed member type.

    The remote check relies on tar's verbose listing, whose type letters
    vary between implementations and versions (e.g. a contiguous file may
    be shown as a regular file). The local archive is byte-identical to
    the uploaded one, which remote checksum verification confirms, so its
    raw type flags are authoritative. Only regular files, directories,
    symlinks and hard links are allowed; the links themselves are
    validated by _validate_members() before extraction.

    Raises:
        WPSSHBackupError: If a member type is unsupported or the archive
            cannot be read.
    """
    if not archive.is_file():
        raise MissingArtifactError(f"Local file missing: {archive}")
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if member.type not in _ALLOWED_MEMBER_TYPES:
                    raise WPSSHBackupError(
                        f"Refusing to restore {archive.name}: unsupported "
                        f"member type {member.type!r} for {member.name!r}; "
                        "only regular files, directories and links are "
                        "allowed."
                    )
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise WPSSHBackupError(
            f"Refusing to restore {archive.name}: cannot read archive "
            f"members: {exc}"
        ) from exc


@dataclass(frozen=True)
class _ArchiveWrites:
    """The paths inside the site root that extracting an archive touches.

    member_paths holds every member path the archive writes, relative to
    the site root (POSIX-normalised, leading slashes stripped).
    link_targets holds the paths the archive's symlink members resolve to
    inside the site root: a pre-existing symlink at one of those paths
    would complete an escape chain during extraction.
    """


    member_paths: frozenset[str]
    link_targets: frozenset[str]


def _validate_members(
    archive: str,
    client: paramiko.SSHClient,
) -> _ArchiveWrites:
    """
    Validate a files archive's members before extracting into the site
    root.

    A checksum-matching archive can still carry malicious members: a
    symlink such as 'uploads/link -> ../../private.txt' would be created
    verbatim by tar and, on hosts that serve symlinks, expose files
    outside the site root. Every member name must stay inside the tree
    (no absolute paths or '..' traversal), and every symlink target must
    resolve inside the site root when joined to the link's directory —
    including chains that would escape via another member.
    Only regular files, directories, and validated links are permitted;
    special and unknown member types are rejected before extraction.

    The listing is requested with --quoting-style=shell-always so every
    name and link target is exactly one shell token even when it contains
    spaces or a literal ' -> ' sequence; the tokens are decoded with
    shlex. GNU tar's default -tv format is not machine-readable (a name
    with spaces would be split, and a name containing ' -> ' could be
    mistaken for part of a link target), so any line that cannot be
    decoded unambiguously fails the restore rather than being skipped.

    Args:
        archive: The remote path of the files archive.
        client: An active SSH client connected to the remote host.

    Returns:
        An _ArchiveWrites describing the paths inside the site root the
        archive writes and resolves links to, used by the destination
        tree audit to decide which pre-existing symlinks extraction
        would traverse or replace.

    Raises:
        WPSSHBackupError: If any member name or symlink target escapes
            the restore tree, a member type is unsupported, or the listing
            cannot be decoded.
    """
    # -v is required for link targets; --quoting-style=shell-always makes
    # every field unambiguous. Options must precede the archive operand
    # (GNU tar treats trailing options as positional and ignores them).
    command = (
        f"tar --quoting-style=shell-always -tzf {shquote(archive)}"
    )
    out = run_remote_cmd_checked(client, command, timeout=1800)
    member_paths: set[str] = set()
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            name = shlex.split(line)[0]
        except (ValueError, IndexError) as exc:
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: cannot decode member "
                f"name from tar listing line {line!r}: {exc}"
            ) from exc
        # Normalise the member path relative to the site root. GNU tar
        # strips leading slashes on extraction, so lstrip("/") mirrors
        # what would land on disk.
        normalised = posixpath.normpath(name.lstrip("/"))
        if normalised.startswith("../") or normalised == "..":
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: member {name!r} escapes "
                "the site root."
            )
        member_paths.add(normalised)
    # Symlink targets are only visible in the verbose listing; use the
    # quoted verbose listing to check where links point, following chains
    # through other links in the archive.
    command = (
        f"tar --quoting-style=shell-always -tvzf {shquote(archive)}"
    )
    verbose = run_remote_cmd_checked(client, command, timeout=1800)
    # Regular (non-link) member names, for the hard-link target check.
    regular_members: set[str] = set()
    links: dict[str, str] = {}
    hard_links: list[tuple[str, str]] = []
    for line in verbose.splitlines():
        if not line.strip():
            continue
        # With shell-always quoting every field is one token: permissions
        # owner/group size date time name [-> target | link to target].
        # A symlink line ends with '-> TARGET'; HARD links end with
        # 'link to TARGET' — tar uses that target during extraction, so
        # it must be validated too: pointing at an existing symlink in
        # the destination tree would create a second link to a file
        # outside the site. A hard link is only safe when its target is
        # a REGULAR member of the same archive.
        try:
            fields = shlex.split(line)
        except ValueError as exc:
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: cannot decode tar "
                f"listing line {line!r}: {exc}"
            ) from exc
        if len(fields) < 6:
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: unexpected tar listing "
                f"line {line!r}"
            )
        kind = fields[0][:1]
        if kind not in ("-", "d", "l", "h"):
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: unsupported member type "
                f"{kind!r} in tar listing line {line!r}"
            )
        if kind == "l" and len(fields) >= 8 and fields[-2] == "->":
            links[fields[-3]] = fields[-1]
        elif (
            kind == "h"
            and len(fields) >= 9
            and fields[-3:-1] == ["link", "to"]
        ):
            hard_links.append((fields[-4], fields[-1]))
        elif kind in ("l", "h"):
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: unexpected tar link "
                f"listing line {line!r}"
            )
        elif kind == "-":
            # Only REGULAR members may serve as hard-link targets; a
            # directory (kind 'd') or anything exotic must not.
            regular_members.add(fields[-1].lstrip("/"))

    def _resolve_link(link: str, target: str, seen: set[str]) -> str:
        """Resolve link -> target through the archive's own links."""
        link_dir = posixpath.dirname(posixpath.normpath(link.lstrip("/")))
        resolved = posixpath.normpath(posixpath.join(link_dir, target))
        # A chain: the resolved path may itself be a link in the archive
        # (a -> b, b -> ../../outside).
        if resolved in links and resolved not in seen:
            seen.add(resolved)
            return _resolve_link(resolved, links[resolved], seen)
        return resolved

    link_targets: set[str] = set()
    for link, target in links.items():
        resolved = _resolve_link(link, target, {link})
        if (
            posixpath.isabs(resolved)
            or resolved.startswith("../")
            or resolved == ".."
        ):
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: symlink {link!r} -> "
                f"{target!r} resolves outside the site root ({resolved})."
            )
        # A pre-existing symlink sitting at the resolved path would
        # complete the chain to wherever IT points; the destination tree
        # audit rejects such links.
        link_targets.add(resolved)
    for link, target in hard_links:
        if target.lstrip("/") not in regular_members:
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: hard link {link!r} "
                f"targets {target!r}, which is not a regular member of "
                "the archive; it could chain through an existing "
                "symlink in the destination tree."
            )
    return _ArchiveWrites(frozenset(member_paths), frozenset(link_targets))


def _audit_destination_tree(
    client: paramiko.SSHClient,
    site_root: str,
    writes: _ArchiveWrites,
) -> None:
    """
    Reject pre-existing symlinks in the site tree that extraction would
    traverse or replace.

    _validate_members only sees the archive's contents, but tar extracts into
    the EXISTING site tree: if 'uploads' is already a symlink to a directory
    outside the site root, an archive member 'uploads/file' writes there; if
    an archive link resolves to a path where a pre-existing symlink already
    sits, the chain resolves to wherever that link points. `find <root>
    -type l` lists every symlink already on disk WITHOUT following links (find
    does not traverse symlinked directories by default), so the audit sees the
    real tree.

    Only symlinks that extraction would actually traverse or replace are
    rejected: a symlink is a problem when it sits at the site root itself,
    at a directory the archive writes into (an ancestor of a member path),
    at a member path itself (extraction would replace it), or at a path an
    archive symlink resolves to (it would complete the escape chain). An
    untouched pre-existing symlink elsewhere in the site is not this
    restore's business.

    Args:
        client: An active SSH client connected to the remote host.
        site_root: The directory the archive will be extracted into.
        writes: The member paths and resolved link targets inside the site
            root that extraction touches.

    Raises:
        WPSSHBackupError: If a pre-existing symlink sits at the site root,
            at a member path, in a directory the archive writes into, or
            at a path an archive symlink resolves to.
    """
    if not writes.member_paths and not writes.link_targets:
        return
    # Directories extraction writes through: every ancestor directory of
    # every member path. tar follows a pre-existing symlink sitting at one
    # of these paths when creating the members beneath it.
    ancestors: set[str] = set()
    for member in writes.member_paths:
        parts = member.split("/")
        for i in range(1, len(parts)):
            ancestors.add("/".join(parts[:i]))
    # -print0 / NUL-separated output keeps spaced names intact; the decoder
    # splits on NUL and every name is used verbatim (no shell parsing), so
    # nothing can be smuggled past this check.
    command = (
        f"find {shquote(site_root)} -type l -print0"
    )
    out = run_remote_cmd_checked(client, command, timeout=600)
    for raw in out.split("\0"):
        if not raw:
            continue
        link = raw.rstrip("/")
        rel_link = posixpath.relpath(link, site_root)
        if (
            rel_link == "."
            or rel_link in writes.member_paths
            or rel_link in ancestors
        ):
            # The site root itself is a symlink (every write goes through
            # it), extraction would replace the link with a member, or
            # extraction would follow the link to write a member beneath
            # it.
            raise WPSSHBackupError(
                f"Refusing to extract: {link!r} already exists as a "
                "symlink in the site tree; extraction would follow or "
                "replace it. Remove it and re-run."
            )
        if rel_link in writes.link_targets:
            # An archive symlink resolves to this path; the pre-existing
            # link would complete the chain to wherever it points.
            raise WPSSHBackupError(
                f"Refusing to extract: {link!r} already exists as a "
                "symlink in the site tree; an archive symlink resolves "
                "to it and would follow it. Remove it and re-run."
            )


def extract_files(
    client: paramiko.SSHClient,
    config: Config,
    staging: str,
    ts: str,
) -> None:
    archive = posixpath.join(staging, files_archive_name(ts))
    writes = _validate_members(archive, client)
    _audit_destination_tree(client, config.wp_site_root, writes)
    command = f"tar xzf {shquote(archive)} -C {shquote(config.wp_site_root)}"
    run_remote_cmd_checked(client, command, timeout=3600)


def _validate_db_members(
    archive: str,
    client: paramiko.SSHClient,
    ts: str,
) -> None:
    """
    Require the DB tarball to hold exactly the expected SQL dump member.

    The tarball is checksum-verified, but a checksum only proves the
    bytes match the manifest — a modified archive with a matching local
    manifest could carry a '../' traversal member or a symlink (e.g.
    'my-<id>.cnf' pointing outside staging). Extraction would write
    outside staging, and the later credentials-file write could follow
    such a link and overwrite its target. The backup tool only ever
    packs one regular file (wp-db-<id>.sql), so anything else — links,
    extra names, traversal — is rejected before tar runs.

    The listing is requested with --quoting-style=shell-always and
    decoded with shlex, as for the files archive, so spaced or hostile
    names cannot defeat the check; an undecodable line fails closed.

    Args:
        archive: The remote path of the DB archive.
        client: An active SSH client connected to the remote host.
        ts: The backup identifier the expected dump name is derived from.

    Raises:
        WPSSHBackupError: If the archive does not contain exactly one
            regular member named wp-db-<ts>.sql.
    """
    expected = f"wp-db-{ts}.sql"
    command = (
        f"tar --quoting-style=shell-always -tvzf {shquote(archive)}"
    )
    verbose = run_remote_cmd_checked(client, command, timeout=1800)
    members: list[tuple[str, bool, str | None]] = []
    for line in verbose.splitlines():
        if not line.strip():
            continue
        try:
            fields = shlex.split(line)
        except ValueError as exc:
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: cannot decode tar "
                f"listing line {line!r}: {exc}"
            ) from exc
        if len(fields) < 6:
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: unexpected tar listing "
                f"line {line!r}"
            )
        # The first token is the 10-character mode string; its first
        # character is the member type: '-' regular, 'd' directory,
        # 'l' symlink, 'p' FIFO, 'c' char device, 'b' block device.
        kind = fields[0][0]
        if fields[-2] == "->":
            # Symlink member.
            members.append((fields[-3], True, fields[-1], kind))
        elif fields[-3:-1] == ["link", "to"]:
            # Hard link member: rejected below.
            members.append((fields[-4], True, fields[-1], kind))
        else:
            members.append((fields[-1], False, None, kind))
    if len(members) != 1:
        raise WPSSHBackupError(
            f"Refusing to extract {archive}: expected exactly one member "
            f"({expected!r}), found {len(members)}"
        )
    name, is_link, target, kind = members[0]
    normalised = posixpath.normpath(name.lstrip("/"))
    if (
        is_link
        or kind != "-"
        or normalised != expected
        or normalised.startswith("../")
        or normalised == ".."
    ):
        if is_link:
            detail = f" (symlink to {target!r})"
        else:
            kind_detail = {
                "d": "directory",
                "p": "FIFO",
                "c": "character device",
                "b": "block device",
            }.get(kind, f"type {kind!r}")
            detail = "" if kind == "-" else f" ({kind_detail})"
        raise WPSSHBackupError(
            f"Refusing to extract {archive}: unexpected member "
            f"{name!r}{detail}; expected the regular file {expected!r}"
        )


def import_database(
    client: paramiko.SSHClient,
    config: Config,
    staging: str,
    ts: str,
) -> None:
    """Import the database from the DB tarball in the staging dir."""
    archive = posixpath.join(staging, db_archive_name(ts))
    dump_name = f"wp-db-{ts}.sql"
    dump_path = posixpath.join(staging, dump_name)
    wp_cli = detect_wp_cli(client, config)

    # The tarball is checksum-verified but its members are not trusted:
    # require exactly the expected regular SQL dump before tar runs.
    _validate_db_members(archive, client, ts)

    # Extract the SQL dump from the tarball.
    run_remote_cmd_checked(
        client,
        f"tar xzf {shquote(archive)} -C {shquote(staging)}",
        timeout=1800,
    )

    if wp_cli:
        command = (
            f"cd {shquote(config.wp_site_root)} && "
            f"{shquote(wp_cli)} db import {shquote(dump_path)}"
        )
        run_remote_cmd_checked(client, command, timeout=3600)
        return

    sftp = client.open_sftp()
    try:
        settings = read_wp_db_settings(sftp, config.wp_site_root)
    finally:
        sftp.close()

    host, port, socket_path = split_db_host(settings["DB_HOST"])
    cnf_name = f"my-{ts}.cnf"
    cnf_path = posixpath.join(staging, cnf_name)
    cnf_body = mysql_client_config(
        host=host,
        user=settings["DB_USER"],
        password=settings["DB_PASSWORD"],
        port=port,
        socket=socket_path,
    )

    sftp = client.open_sftp()
    try:
        write_remote_file(sftp, cnf_path, cnf_body, mode=0o600)
    finally:
        sftp.close()

    command = (
        f"cd {shquote(staging)} && "
        f"trap {trap_rm_action(cnf_path)} EXIT && "
        f"mysql --defaults-extra-file={shquote(cnf_path)} "
        f"{shquote(settings['DB_NAME'])} < {shquote(dump_path)}"
    )
    try:
        run_remote_cmd_checked(client, command, timeout=3600)
    finally:
        # Best-effort: if the connection dropped, the removal must not
        # mask the original mysql import failure.
        remove_remote_file(client, cnf_path)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_restore(
    client: paramiko.SSHClient,
    config: Config,
    set_files: dict[str, Path],
    include_files: bool,
    include_database: bool,
    staging_bid: str | None = None,
) -> None:
    """
    Restore the chosen backup set to the remote host.

    Args:
        client: An active SSH client connected to the remote host.
        config: The backup configuration.
        set_files: The local backup set to restore, keyed by filename.
        include_files: Whether to restore the WordPress files.
        include_database: Whether to restore the WordPress database.
        staging_bid: Backup identifier for the staging directory name.
            Defaults to a fresh unique identifier.
    """
    backup_bid = ts_of(set_files)
    staging_ts = staging_bid or backup_id()
    staging = staging_dir_for(config.wp_site_root, staging_ts)
    archive_names: list[str] = []
    if include_files:
        archive_names.append(files_archive_name(backup_bid))
    if include_database:
        archive_names.append(db_archive_name(backup_bid))

    # Bare mkdir (no -p): the staging dir is exclusive to this run, and a
    # collision aborts instead of sharing artifacts with another run.
    # -m 700 creates it owner-only in the mkdir itself, so a permissive
    # umask never leaves it writable by others before the later chmod.
    # The 0700 chmod is issued separately INSIDE the try block below:
    # chained 'mkdir && chmod' would orphan the directory if mkdir
    # succeeded but chmod failed, before the cleanup block was entered.
    code, _, err = run_remote_cmd(
        client,
        f"mkdir -m 700 {shquote(staging)}",
    )
    if code != 0:
        raise WPSSHBackupError(
            f"Could not create staging directory {staging}: "
            f"{err.strip() or 'already exists?'}"
        )
    print(f"Remote staging directory: {staging}")

    try:
        # Mode 0700 keeps other host users out of the directory that will
        # hold the database credentials file. If the chmod fails, the
        # handler below removes the directory this run just created.
        run_remote_cmd_checked(
            client, f"chmod 700 {shquote(staging)}"
        )

        # GNU tar is needed for archive validation; check before any
        # upload so an unsupported host fails fast and cleanly.
        _require_gnu_tar(client)

        with client.open_sftp() as sftp:
            upload_artifacts(sftp, set_files, archive_names, staging)
        verify_remote_checksums(client, staging, archive_names)
        print("Remote checksum verification passed.")

        if include_files:
            # Checked after checksum verification so a corrupt archive is
            # reported as a checksum failure, and before any extraction.
            _validate_local_member_types(
                set_files[files_archive_name(backup_bid)]
            )
            started = _now()
            extract_files(client, config, staging, backup_bid)
            print(f"Files extracted ({_now() - started:.1f}s).")

        if include_database:
            started = _now()
            import_database(client, config, staging, backup_bid)
            print(f"Database imported ({_now() - started:.1f}s).")
    except (
        WPSSHBackupError,
        OSError,
        paramiko.SSHException,
    ):
        # Covers every WPSSHBackupError subclass — including base-class
        # errors such as an invalid WP_CLI_PATH — plus transport failures.
        # Restore always cleans staging: a failed verification means the
        # upload must be repeated.
        remove_remote_staging(client, staging)
        raise

    remove_remote_staging(client, staging)


def _now() -> float:
    return time.monotonic()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Restore a WordPress site from a WP SSH Backup set."
    )
    parser.add_argument(
        "--timestamp",
        help="Backup set to restore: a full backup id (e.g. "
        "20261014T0930Z-a1b2c3) or a bare timestamp (e.g. 20261014T0930Z, "
        "which must match exactly one set). Defaults to the latest "
        "matching set.",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--files",
        action="store_true",
        help="Restore only the WordPress files.",
    )
    group.add_argument(
        "--database",
        action="store_true",
        help="Restore only the WordPress database.",
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="Restore both files and database (the default).",
    )
    args = parser.parse_args(argv)

    neither = not (args.files or args.database)
    include_files = args.files or args.all or neither
    include_database = args.database or args.all or neither

    try:
        config = load_config()
        sets = list_backup_sets(config.backup_dir)
        set_files = choose_set(
            sets,
            args.timestamp,
            include_files,
            include_database,
            config.backup_dir,
        )
        client = connect(config)
    except (WPSSHBackupError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        run_restore(client, config, set_files, include_files, include_database)
    except (WPSSHBackupError, OSError, paramiko.SSHException) as exc:
        # run_restore cleans up staging and re-raises transport/SFTP
        # failures; report them here rather than letting them escape as a
        # traceback.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()

    print("Restore complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
