# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- A failed operation is no longer reported as having completed. The timing
  helper printed its completion message from a `finally` block, so an
  exception inside the measured block still produced messages such as
  `Files extracted (12.3s).` The message now follows the yield and is
  printed only when the block exits normally.
- The stale publish lock is no longer reclaimed by mistake. The dead PID
  was read through the lock's pathname and the lock's identity was
  captured through a separate `lstat`, leaving a window between them. A
  contender that replaced the lock in that window could have its new,
  live lock renamed aside and unlinked — freeing a live publication lock
  and letting two backups publish concurrently. The PID and the identity
  are now read from a single descriptor, so the identity provably
  describes the entry the PID came from.
- Cleanup no longer replaces an unrelated file. When an owned file could
  not be unlinked, the quarantined entry was restored with
  `os.rename(quarantine, path)`, which replaces the destination on POSIX:
  a file another process created at the original pathname while the entry
  sat under the quarantine name was silently deleted. The restore now uses
  a no-replace hard link, so a newcomer is preserved and the quarantined
  entry is left in place.

## [0.1.0] - 2026-10-20

First release. The tool backs up and restores a WordPress site over SSH
using a temporary local backup set, and hardens every step of the transfer
against tampering from another process on the same host.

### Added

- `backup.py` — creates a database dump and/or a site-root tarball on the
  remote host, downloads them with SFTP, verifies SHA-256 checksums locally
  and publishes them under their final names only once verified.
- `restore.py` — selects a local backup set, uploads it to the remote host,
  verifies the uploaded bytes and extracts the files and database back into
  place.
- `authorize_host.py` — fetches a host's public SSH key, shows its SHA-256
  fingerprint for out-of-band verification and records it in a known_hosts
  file.
- `-v` / `--version` on all three entry points, reporting the version from
  the single source of truth in `version.py`.
- `CHANGELOG.md` and a `## Changelog` section in the README.

### Security

- Backup files are published through a no-replace operation, never an
  overwrite: a file that appears at a final name after the pre-check can
  never be silently replaced.
- The archive bytes that are published are the bytes that were verified.
  The download descriptors are held open across verification and
  publication, and the published link is created from the held descriptor's
  inode rather than from a re-opened pathname.
- The published file is re-verified through the held descriptor after
  linking, and every final is re-checked against its held inode before
  success is reported, so a replaced final fails the run instead of
  producing a mismatched archive/manifest pair.
- A cooperative publication lock prevents two concurrent backup runs from
  publishing into the same directory. The lock records its owner's PID
  atomically, is reclaimed only when that PID is verifiably dead, and a
  live lock is never stolen.
- Restore validates every archive member before extraction: absolute paths,
  traversal, duplicate names, symlinks that resolve outside the site root,
  hard links to non-regular members and unsupported member types are all
  rejected. The destination tree is audited for pre-existing symlinks and
  hard links that extraction would follow or overwrite.
- Archive consumption is bound to the verified digest: the digest is
  re-checked inside the same remote command that extracts, so a same-user
  process that replaces a staging archive cannot make tar extract bytes
  that were never verified.
- Database credentials are never passed on a remote command line. They are
  written to a temporary owner-only option file that is removed as soon as
  the command finishes.
- Unknown SSH host keys are always rejected; a host must be authorised
  explicitly before first use.

### Documentation

- README covering installation, configuration, host key verification,
  usage, restoring, scheduling, development and security notes.
