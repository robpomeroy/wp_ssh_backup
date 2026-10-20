# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `common.py` is no longer a single 1651-line module. It was split into
  focused modules, each with one responsibility: `errors.py` (the
  exception types), `config.py` (configuration), `remote.py` (the SSH
  and SFTP transport), `remote_ops.py` (remote operations both flows
  share), `wp_config.py` (parsing `wp-config.php`), `db_config.py`
  (the MySQL option file), `naming.py` (timestamps, identifiers and
  file names), `checksums.py` (checksums and manifests), `retention.py`
  (local backup sets and retention), `shell.py` (shell quoting) and
  `host_keys.py` (fingerprints and `known_hosts` entries). `common.py`
  remains as a re-export facade, so `from common import ...` keeps
  working; new code should import from the module that owns the name.
- The `common.py` facade re-exports every public name the old module
  had, including `strip_php_comments` and the ten public constants
  (`REQUIRED_KEYS`, `TS_FORMAT`, `TS_PATTERN`, `RUN_SUFFIX_RE`,
  `BACKUP_ID_PATTERN`, `BACKUP_FILE_RE`, `STAGING_PREFIX`,
  `SHA256SUM_LINE_RE`, `WP_DB_KEYS` and `WP_DEFINE_RE`). The old
  module had no `__all__`, so every module-level name was importable;
  the facade now carries the same public surface, and a test pins it.
- The backup and restore flows no longer name the set of failures that
  mean "the run could not complete" twice. The set now lives in
  `errors.py` as `REMOTE_FAILURES`, so the two flows cannot drift into
  cleaning up different failures.
- The stale-lock reclaim and the quarantined-entry restore are split
  into named helpers, so each has one job. The control flow and the
  warnings are unchanged.

### Added

- `ruff` and `pyflakes` are development dependencies, and CI runs both
  as a lint step. `ruff` is configured in `pyproject.toml` with the
  `E4`, `E7`, `E9`, `F`, `UP` and `B` rule sets.

### Fixed

- The `@contextmanager` helpers are annotated as `Generator` rather
  than `Iterator`. Annotating a context manager's return type as
  `Iterator` is deprecated; the decorator itself is not.

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
- A quarantine no longer replaces an unrelated entry. The quarantine name
  was built from the process ID and a counter, both of which are
  predictable, and the move into it used `os.rename`, which replaces the
  destination on POSIX. An entry left behind by an earlier run that
  happened to reuse the same process ID and counter — or one a concurrent
  writer pre-created at the predictable name — was therefore silently
  deleted, violating the identity-bound cleanup guarantee. The name now
  carries a 128-bit random suffix and is reserved with `O_CREAT | O_EXCL`
  before the source is moved into it, retrying with a fresh name on
  collision, so the only entry the move can replace is this process's own
  empty reservation. A failed reservation is reported and the file is
  left in place rather than removed unsafely.
- The tests that exercise the quarantine move are no longer vacuous. They
  intercepted the move by patching `os.rename`, but the move is performed
  with `os.replace` (it has to overwrite the process's own empty
  reservation, and `os.rename` refuses to replace on Windows), so the
  simulated race never happened. The tests now patch the function the
  production code actually calls, through one shared helper, and the
  regression tests for the quarantine reservation are restored.

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
