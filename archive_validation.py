"""Validating archives before they are extracted into the site root.

A checksum-matching archive can still be hostile: it may carry a
symlink that points outside the site root, a member whose name
traverses upward, a duplicate name that hides an escaping link under a
later safe duplicate, or a hard link to a path that is a symlink in the
destination tree. Every one of those is rejected here, BEFORE tar runs.

The consumption of the archive is bound to the digest that was
verified: the digest is re-checked inside the SAME remote command that
extracts, so a same-user process that replaces the staging archive
after the earlier checksum verification cannot make tar extract bytes
that were never covered by the verified digest.
"""

from __future__ import annotations

import hashlib
import posixpath
import shlex
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import paramiko

from common import (
    WPSSHBackupError,
    run_remote_cmd,
    run_remote_cmd_checked,
    shquote,
)

__all__ = [
    "ArchiveWrites",
    "audit_destination_tree",
    "extract_verified_archive",
    "require_gnu_tar",
    "validate_db_members",
    "validate_local_member_types",
    "validate_members",
]


# ---------------------------------------------------------------------------
# Host prerequisites
# ---------------------------------------------------------------------------


def require_gnu_tar(client: paramiko.SSHClient) -> None:
    """
    Require GNU tar on the remote host before any restore work.

    Archive validation runs `tar --quoting-style=shell-always`, which
    BusyBox and BSD tar reject as an unknown option; without this check
    every restore involving an archive would fail on such hosts, after
    the upload. `tar --version` prints "tar (GNU tar) ..." on GNU tar
    and fails or prints nothing of the sort elsewhere.

    Args:
        client: An active SSH client connected to the remote host.

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


# ---------------------------------------------------------------------------
# Local member types
# ---------------------------------------------------------------------------

_ALLOWED_MEMBER_TYPES = frozenset({
    tarfile.REGTYPE,
    tarfile.AREGTYPE,
    tarfile.DIRTYPE,
    tarfile.SYMTYPE,
    tarfile.LNKTYPE,
})


class _HashingReader:
    """A file-like wrapper that hashes every byte read through it."""

    def __init__(self, handle: BinaryIO) -> None:
        self._handle = handle
        self._digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self._handle.read(size)
        self._digest.update(data)
        return data

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def validate_local_member_types(
    archive: Path,
    handle: BinaryIO,
) -> str:
    """
    Reject a files archive containing any non-allowed member type, and
    return the archive's SHA-256 digest.

    The remote check ran against the uploaded bytes; this local check
    must therefore bind its verdict to those same bytes. The digest is
    computed over the exact bytes this call inspected, in the same pass,
    so the caller can require it to equal the digest the remote host
    computed for the uploaded archive: re-reading the pathname later
    could validate different bytes than the ones uploaded and extracted.

    The archive is read from the caller's held, no-follow file object —
    the same descriptor the upload will use — so a pathname swapped for
    a symlink or a different file after the initial open cannot change
    which bytes are validated or uploaded.

    The remote check relies on tar's verbose listing, whose type letters
    vary between implementations and versions (e.g. a contiguous file may
    be shown as a regular file). The local archive is byte-identical to
    the uploaded one, which remote checksum verification confirms, so its
    raw type flags are authoritative. Only regular files, directories,
    symlinks and hard links are allowed; the links themselves are
    validated by validate_members() before extraction.

    Args:
        archive: The local archive, used for the error messages.
        handle: The held, no-follow file object to read the archive from.

    Returns:
        The SHA-256 digest of the archive's bytes.

    Raises:
        WPSSHBackupError: If a member type is unsupported or the archive
            cannot be read.
    """
    try:
        # The upload may already have read this handle to EOF; restart
        # from the beginning so validation and the digest cover the
        # whole held file.
        handle.seek(0)
        # A hashing reader between the file and tarfile's streaming
        # mode hashes exactly the bytes tarfile inspects, in one
        # pass; the trailing drain covers bytes gzip buffers past
        # the last member.
        reader = _HashingReader(handle)
        with tarfile.open(fileobj=reader, mode="r|gz") as tar:
            for member in tar:
                if member.type not in _ALLOWED_MEMBER_TYPES:
                    raise WPSSHBackupError(
                        f"Refusing to restore {archive.name}: unsupported "
                        f"member type {member.type!r} for {member.name!r}; "
                        "only regular files, directories and links are "
                        "allowed."
                    )
        while reader.read(1024 * 1024):
            pass
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise WPSSHBackupError(
            f"Refusing to restore {archive.name}: cannot read archive "
            f"members: {exc}"
        ) from exc
    return reader.hexdigest()


# ---------------------------------------------------------------------------
# Member validation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArchiveWrites:
    """The paths inside the site root that extracting an archive touches.

    member_paths holds every member path the archive writes, relative to
    the site root (POSIX-normalised, leading slashes stripped).
    link_targets holds the paths the archive's symlink members resolve to
    inside the site root: a pre-existing symlink at one of those paths
    would complete an escape chain during extraction.
    """

    member_paths: frozenset[str]
    link_targets: frozenset[str]


def _parse_name_listing(archive: str, out: str) -> set[str]:
    """Parse the plain member listing into normalised member paths.

    Args:
        archive: The remote archive path, for the error messages.
        out: The output of `tar -tzf`.

    Returns:
        The normalised member paths.

    Raises:
        WPSSHBackupError: If a name is absolute, escapes the site root,
            is duplicated, or cannot be decoded.
    """
    member_paths: set[str] = set()
    seen: set[str] = set()
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
        # Reject an absolute member name outright. GNU tar strips the
        # leading '/' on extraction, but accepting it would make the
        # accepted archive format depend on tar's path-stripping
        # behaviour; the validator's policy is that every member is
        # relative to the site root.
        if posixpath.isabs(name):
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: member {name!r} is an "
                "absolute path."
            )
        # Normalise the member path relative to the site root.
        normalised = posixpath.normpath(name.lstrip("/"))
        if normalised.startswith("../") or normalised == "..":
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: member {name!r} escapes "
                "the site root."
            )
        if normalised in seen:
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: duplicate member "
                f"{normalised!r}"
            )
        seen.add(normalised)
        member_paths.add(normalised)
    return member_paths


def _parse_verbose_listing(
    archive: str, verbose: str
) -> tuple[set[str], dict[str, str], list[tuple[str, str]]]:
    """Parse the verbose member listing into its three kinds of member.

    Args:
        archive: The remote archive path, for the error messages.
        verbose: The output of `tar -tvzf`.

    Returns:
        A tuple of (regular member names, symlink name -> target,
        hard link (name, target) pairs).

    Raises:
        WPSSHBackupError: If a line cannot be decoded, a member type is
            unsupported, or a name is duplicated.
    """
    # Regular (non-link) member names, for the hard-link target check.
    regular_members: set[str] = set()
    links: dict[str, str] = {}
    hard_links: list[tuple[str, str]] = []
    seen_names: set[str] = set()
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
            normalised = posixpath.normpath(fields[-3].lstrip("/"))
            if normalised in seen_names:
                raise WPSSHBackupError(
                    f"Refusing to extract {archive}: duplicate member "
                    f"{normalised!r}"
                )
            seen_names.add(normalised)
            # Store the link name in the same normalised form resolution
            # uses: the raw tar spelling (e.g. './uploads/a') must not
            # create a chain keyed differently from the lookups, or an
            # escape through a second link would pass validation.
            links[normalised] = fields[-1]
        elif (
            kind == "h"
            and len(fields) >= 9
            and fields[-3:-1] == ["link", "to"]
        ):
            normalised = posixpath.normpath(fields[-4].lstrip("/"))
            if normalised in seen_names:
                raise WPSSHBackupError(
                    f"Refusing to extract {archive}: duplicate member "
                    f"{normalised!r}"
                )
            seen_names.add(normalised)
            hard_links.append((fields[-4], fields[-1]))
        elif kind in ("l", "h"):
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: unexpected tar link "
                f"listing line {line!r}"
            )
        elif kind == "-":
            normalised = posixpath.normpath(fields[-1].lstrip("/"))
            if normalised in seen_names:
                raise WPSSHBackupError(
                    f"Refusing to extract {archive}: duplicate member "
                    f"{normalised!r}"
                )
            seen_names.add(normalised)
            # Only REGULAR members may serve as hard-link targets; a
            # directory (kind 'd') or anything exotic must not.
            regular_members.add(normalised)
        elif kind == "d":
            normalised = posixpath.normpath(fields[-1].lstrip("/"))
            if normalised in seen_names:
                raise WPSSHBackupError(
                    f"Refusing to extract {archive}: duplicate member "
                    f"{normalised!r}"
                )
            seen_names.add(normalised)
    return regular_members, links, hard_links


def _resolve_link_chain(
    archive: str,
    links: dict[str, str],
    link: str,
    target: str,
    seen: set[str],
) -> str:
    """Resolve link -> target through the archive's own links.

    Args:
        archive: The remote archive path, for the error messages.
        links: The archive's symlinks, keyed by normalised name.
        link: The link being resolved.
        target: The link's target as tar spelled it.
        seen: The links already followed, for cycle detection.

    Returns:
        The resolved path, relative to the site root.

    Raises:
        WPSSHBackupError: If the links form a cycle.
    """
    link_dir = posixpath.dirname(posixpath.normpath(link.lstrip("/")))
    resolved = posixpath.normpath(posixpath.join(link_dir, target))
    # A chain: the resolved path may itself be a link in the archive
    # (a -> b, b -> ../../outside).
    if resolved in links:
        if resolved in seen:
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: symlink cycle involving "
                f"{link!r}"
            )
        seen.add(resolved)
        return _resolve_link_chain(archive, links, resolved, links[resolved], seen)
    return resolved


def validate_members(
    archive: str,
    client: paramiko.SSHClient,
) -> ArchiveWrites:
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
    Every member name must also be unique after normalisation: duplicate
    names let a crafted archive hide an escaping symlink under a later
    safe duplicate (a dict keyed by name would only validate the last
    occurrence) or make extraction write the same path twice with
    different types. The backup tool never writes duplicate members, so
    any duplicate is rejected.

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
        An ArchiveWrites describing the paths inside the site root the
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
    member_paths = _parse_name_listing(archive, out)
    # Symlink targets are only visible in the verbose listing; use the
    # quoted verbose listing to check where links point, following chains
    # through other links in the archive.
    command = (
        f"tar --quoting-style=shell-always -tvzf {shquote(archive)}"
    )
    verbose = run_remote_cmd_checked(client, command, timeout=1800)
    regular_members, links, hard_links = _parse_verbose_listing(
        archive, verbose
    )

    link_targets: set[str] = set()
    for link, target in links.items():
        resolved = _resolve_link_chain(archive, links, link, target, {link})
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
        # Normalise the target exactly like member names: GNU tar emits
        # targets as raw spellings (e.g. './original' when the site is
        # tarred with '.' as the member), while regular_members holds
        # the normalised forms. Comparing the raw target would reject
        # every hard link of a normal backup.
        if posixpath.normpath(target.lstrip("/")) not in regular_members:
            raise WPSSHBackupError(
                f"Refusing to extract {archive}: hard link {link!r} "
                f"targets {target!r}, which is not a regular member of "
                "the archive; it could chain through an existing "
                "symlink in the destination tree."
            )
    return ArchiveWrites(frozenset(member_paths), frozenset(link_targets))


# ---------------------------------------------------------------------------
# Destination tree audit
# ---------------------------------------------------------------------------


def _ancestors_of(paths: frozenset[str] | set[str]) -> set[str]:
    """Return every ancestor directory of every path.

    Args:
        paths: The paths whose ancestors are wanted.

    Returns:
        The set of ancestor directory paths, relative to the site root.
    """
    ancestors: set[str] = set()
    for path in paths:
        parts = path.split("/")
        for i in range(1, len(parts)):
            ancestors.add("/".join(parts[:i]))
    return ancestors


def _find_remote_paths(
    client: paramiko.SSHClient,
    site_root: str,
    expression: str,
) -> list[tuple[str, str]]:
    """Run a find(1) expression over the site tree and return its hits.

    -print0 / NUL-separated output keeps spaced names intact; the
    decoder splits on NUL and every name is used verbatim (no shell
    parsing), so nothing can be smuggled past the check.

    Args:
        client: An active SSH client connected to the remote host.
        site_root: The directory to search.
        expression: The find(1) expression, e.g. "-type l".

    Returns:
        A list of (absolute path, path relative to the site root) pairs.
    """
    command = (
        f"find {shquote(site_root)} {expression} -print0"
    )
    out = run_remote_cmd_checked(client, command, timeout=600)
    paths: list[tuple[str, str]] = []
    for raw in out.split("\0"):
        if not raw:
            continue
        path = raw.rstrip("/")
        paths.append((path, posixpath.relpath(path, site_root)))
    return paths


def audit_destination_tree(
    client: paramiko.SSHClient,
    site_root: str,
    writes: ArchiveWrites,
) -> None:
    """
    Reject pre-existing symlinks and hard links in the site tree that
    extraction would traverse or replace.

    validate_members only sees the archive's contents, but tar extracts
    into the EXISTING site tree: if 'uploads' is already a symlink to a
    directory outside the site root, an archive member 'uploads/file'
    writes there; if an archive link resolves to a path where a
    pre-existing symlink already sits, the chain resolves to wherever
    that link points. `find <root> -type l` lists every symlink already
    on disk WITHOUT following links (find does not traverse symlinked
    directories by default), so the audit sees the real tree.

    A pre-existing HARD link at a member path is an escape too: the inode
    is shared with another name (possibly outside the site root, e.g. a
    hard-linked wp-config.php and authorized_keys). Extracting a regular
    member over it truncates the shared inode, so the linked file outside
    the site is overwritten with the archive's bytes. GNU tar's default
    extraction unlinks the destination first (leaving the outside link
    intact), but that is an implementation detail — `--overwrite` and
    other tar implementations truncate in place — so the audit rejects
    hard-linked write targets instead of relying on it. `find <root>
    -type f -links +1` lists files whose link count is greater than one
    (i.e. hard-linked).

    Only links that extraction would actually traverse or replace are
    rejected: a symlink is a problem when it sits at the site root itself,
    at a directory the archive writes into (an ancestor of a member path),
    at a member path itself (extraction would replace it), at a directory
    in the path an archive symlink resolves to (a later write through the
    resolved target would follow it), or at a path an archive symlink
    resolves to (it would complete the escape chain); a hard link is a
    problem when it sits at a member path itself (extraction would write
    over the shared inode). An untouched pre-existing link elsewhere in
    the site is not this restore's business.

    Args:
        client: An active SSH client connected to the remote host.
        site_root: The directory the archive will be extracted into.
        writes: The member paths and resolved link targets inside the
            site root that extraction touches.

    Raises:
        WPSSHBackupError: If a pre-existing symlink sits at the site
            root, at a member path, in a directory the archive writes
            into, or at a path an archive symlink resolves to; or if a
            pre-existing hard link sits at a member path.
    """
    if not writes.member_paths and not writes.link_targets:
        return
    # Directories extraction writes through: every ancestor directory of
    # every member path, and of every path an archive symlink resolves
    # to. tar follows a pre-existing symlink sitting at one of these
    # paths when creating the members beneath it — and a symlink member
    # is created as a link, but a later member (or a later process)
    # traversing into the link's resolved target would follow a
    # pre-existing symlink in one of the target's directory components,
    # so those directories must be audited too.
    ancestors = _ancestors_of(writes.member_paths)
    ancestors |= _ancestors_of(writes.link_targets)

    for link, rel_link in _find_remote_paths(client, site_root, "-type l"):
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
    # Pre-existing hard links at member paths: extracting a regular member
    # over a hard-linked file truncates the shared inode, overwriting the
    # linked file outside the site root. find -links +1 lists files whose
    # link count is greater than one; only member paths matter (directories
    # cannot be hard-linked, so ancestors are not a concern).
    for hard, rel_hard in _find_remote_paths(
        client, site_root, "-type f -links +1"
    ):
        if rel_hard in writes.member_paths:
            # Extraction would write a regular member over this path,
            # truncating the inode it shares with another name (possibly
            # outside the site root).
            raise WPSSHBackupError(
                f"Refusing to extract: {hard!r} already exists as a "
                "hard link in the site tree; extraction would overwrite "
                "the shared inode. Remove it and re-run."
            )


# ---------------------------------------------------------------------------
# Verified extraction
# ---------------------------------------------------------------------------


def extract_verified_archive(
    client: paramiko.SSHClient,
    staging: str,
    name: str,
    expected_digest: str,
    dest: str,
) -> None:
    """Revalidate the archive's digest and extract it in one command.

    The revalidation and the extraction are delivered to the host as a
    single shell command, so there is no round-trip between the check and
    the consumption in which a same-user process could swap the archive
    (the residual window is the microseconds inside one shell, the
    smallest achievable without holding a remote descriptor).

    Args:
        client: An active SSH client connected to the remote host.
        staging: The remote staging directory holding the archive.
        name: The archive's filename.
        expected_digest: The digest the archive must still have.
        dest: The directory to extract into.

    Raises:
        RemoteCommandError: If the digest no longer matches (the archive
            was replaced after verification) or tar fails.
    """
    command = (
        f"cd {shquote(staging)} && "
        f"sha256sum {shquote(name)} | cut -d' ' -f1 | "
        f"grep -qx {shquote(expected_digest.lower())} && "
        f"tar xzf {shquote(name)} -C {shquote(dest)}"
    )
    run_remote_cmd_checked(client, command, timeout=3600)


# ---------------------------------------------------------------------------
# Database archive members
# ---------------------------------------------------------------------------


def validate_db_members(
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
    members: list[tuple[str, bool, str | None, str]] = []
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
    # Reject an absolute member name before stripping the leading '/':
    # '/wp-db-<ts>.sql' must not pass the regular-file/name policy as if
    # it were the relative member the backup tool writes.
    if posixpath.isabs(name):
        raise WPSSHBackupError(
            f"Refusing to extract {archive}: member {name!r} is an "
            "absolute path."
        )
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
