# WP SSH Backup

WP SSH Backup is a tool for taking backups of WordPress websites over SSH. This
is most suitable for users who have SSH access to their WordPress hosting
server.

## Features

- Backup WordPress files over SSH
- Backup WordPress database over SSH
- SHA-256 checksums generated on the server and verified after download
- Automatic cleanup of temporary files on the server
- Local backup retention (prune old backup sets automatically)
- Restore files and/or database from a backup set

## Requirements

- Python 3.10 or later. Check your version with:
  ```bash
  python --version
  ```
- SSH access to your WordPress hosting server (key-based authentication is
  recommended).
- On the server: GNU tar, `gzip` and `sha256sum` (present on virtually all
  Linux hosts). For database backups, either [WP-CLI](https://wp-cli.org/) or
  `mysqldump` must be available. Restore requires GNU tar specifically: it
  validates archive members with `tar --quoting-style=shell-always`, which
  BusyBox and BSD tar reject. The restore CLI checks for GNU tar before
  uploading anything and reports a clear error if it is missing.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/robpomeroy/wp_ssh_backup.git
   ```
2. Navigate to the project directory:
   ```bash
   cd wp_ssh_backup
   ```
3. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   ```
   On Windows (PowerShell):
   ```powershell
   .venv\Scripts\Activate.ps1
   ```
   On Linux/macOS:
   ```bash
   source .venv/bin/activate
   ```
4. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Copy .env.example to .env:
   ```bash
   cp .env.example .env
   ```
6. Edit the `.env` file to configure your SSH and WordPress settings.

## Configuration

The following settings are read from the `.env` file:

| Setting | Description |
| --- | --- |
| `SSH_HOST` | Hostname or IP address of the hosting server. |
| `SSH_PORT` | SSH port (usually 22). |
| `SSH_USER` | SSH user to log in as. |
| `SSH_KEY_PATH` | Path to a private key file. Leave empty to use your SSH agent. |
| `SSH_PASSWORD` | Optional password authentication. Prefer keys where possible. |
| `SSH_KNOWN_HOSTS` | Optional path to a known_hosts file with trusted server keys. Leave empty to use `~/.ssh/known_hosts`. |
| `WP_SITE_ROOT` | Absolute path to the WordPress root directory on the server. |
| `WP_CLI_PATH` | Optional explicit path to `wp` if it is not on the server PATH. |
| `BACKUP_DIR` | Local directory where backups are stored. |
| `RETENTION_DAYS` | Delete local backup sets older than this many days (0 disables pruning). |

## Host key verification

WP SSH Backup **rejects servers whose host key is not already trusted** — it
never silently accepts a new key. This protects your backups and database
credentials from man-in-the-middle attacks.

Before connecting to a server for the first time, authorise its host key:

```bash
python authorize_host.py
```

This connects to the bare SSH transport (no username, password or key file is
sent — the server learns nothing about you beyond your IP), fetches the
server's public host key and displays its SHA-256 fingerprint:

```
The fingerprint of example.com:22 is:
    SHA256:7f9tLuJMScst0ObcMi3DVb+Rjy/S/lR+gSSHeZq7Pds
```

Compare this fingerprint against a trusted source — your hosting control panel,
or the output of `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` run on the
server itself — and type `y` to save it. The key is recorded in
`~/.ssh/known_hosts` (or the file named by `SSH_KNOWN_HOSTS`), where the OpenSSH
client and WP SSH Backup will both trust it.

For scripted provisioning, pin the expected fingerprint instead of
confirming interactively:

```bash
python authorize_host.py --fingerprint SHA256:7f9tLuJMScst0ObcMi3DVb+Rjy/S/lR+gSSHeZq7Pds
```

To display the fingerprint without saving anything:

```bash
python authorize_host.py --show
```

`--show` and `--fingerprint` are mutually exclusive. Combining them is an
argument error (exit status 2), rejected before configuration is loaded or a
connection is made.

If you have already connected to the server with the `ssh` command, its key is
already in your `~/.ssh/known_hosts` and no authorisation step is needed.

If a connection later fails with a host key mismatch, the server's key has
changed — either it was rebuilt, or something is impersonating it. Verify the
new fingerprint out-of-band before re-authorising.

## Usage

To create a backup, run:
```bash
python backup.py [--files] [--database] [--all]
```

You can use the following options:
- `--files`: Backup only WordPress files.
- `--database`: Backup only the WordPress database.
- `--all`: Backup both WordPress files and database (the default).

Depending on the rate of change on your WordPress site, you may wish to use
different schedules for file and database backups. For example, you might want
to back up your database more frequently than your files if your content changes
often but you rarely upload new files.

### How a backup works

1. A staging directory (`wp-ssh-backup-staging-<backup-id>`) is created as a
   **sibling** of the WordPress site root on the server. The directory is
   created with a bare `mkdir`, so it is exclusive to this run: concurrent
   runs never share or overwrite one another's staging files.
2. The database is dumped with WP-CLI (`wp db export`) if it is installed;
   otherwise the database credentials are read from `wp-config.php` and
   `mysqldump` is used. In the fallback path, credentials are passed via a
   temporary option file (`--defaults-extra-file`) rather than the command line,
   so the password is never visible in the process list; the file is removed as
   soon as the dump completes (or fails).
3. The site root is packed into a gzip tarball, excluding the staging directory
   and `wp-content/cache`.
4. SHA-256 checksums are generated on the server.
5. The tarballs and checksum files are downloaded over SFTP into `BACKUP_DIR`
   under temporary names (a `.part` suffix), so a failed transfer can never be
   mistaken for a backup set.
6. Checksums are re-verified locally. Only then are the files published
   under their final names, using an atomic no-replace operation (a hard
   link, or a no-replace rename on filesystems without hard-link
   support) created from the verified file's own open descriptor: the
   descriptor each download wrote through is handed over and held open,
   so verification hashes and publication links the very inode the
   transfer created — never a re-opened `.part` pathname. A writer who
   can modify `BACKUP_DIR` cannot substitute a self-consistent
   (archive, manifest) pair after the download (the replacement is a
   different inode), and a symlink planted at a `.part` path cannot
   divert verification or publication to unverified bytes. The
   published link is confirmed to reference the verified inode, whose
   digest is re-checked after linking before the final directory entry
   is confirmed once more. On Linux the hard link is created from the
   held descriptor itself (`linkat` with `AT_EMPTY_PATH`); on macOS/BSD
   and on filesystems or kernels that reject that flag, publication
      falls back to a hard link from the verified `.part` pathname (which
      is atomic and refuses to replace an existing destination), and on
      Windows to a no-replace rename of the verified file; in both
      fallbacks the published file is re-opened no-follow and
      re-identified so the same verified inode is published. The fallback
      cleanup removes a final entry only while it still references the
      inode this run published, so a replacement installed by another
      process is never deleted. Each checksum manifest must contain exactly
      one entry naming the archive it accompanies (matching the restore
      verifier), so a manifest with extra entries is refused rather than
      published as a complete set that restore would later reject.
      A file that appears at a
   final name after the pre-check —
   from another backup process or a local attacker who can write
   `BACKUP_DIR` — can never be silently overwritten. If publication
   fails part-way, the final files this run created are removed and the
   temporary downloads are cleaned up. If verification fails, the
   partial downloads are deleted and the remote staging directory is
   **kept** so the transfer can be retried; otherwise the staging
   directory is deleted. Failed-run cleanup removes only temporary
   files created by that run: each `.part` path is unlinked only while
   it still refers to the inode this run created, so a path replaced by
   another process is left in place (with a warning) rather than
   deleted. Cleanup failures are reported as warnings without hiding
   the original error.
7. Local backup sets older than `RETENTION_DAYS` are pruned.

If local pruning or the final size calculation fails after a verified download,
the CLI reports that the backup was downloaded and verified, includes the local
filesystem error, and exits with status 1 rather than reporting full success.

Backups are named `wp-db-<backup-id>.tar.gz` and `wp-files-<backup-id>.tar.gz`,
where `<backup-id>` is a UTC timestamp plus a random run suffix, in the form
`20261014T0930Z-a1b2c3`. The suffix makes each run's artifacts unique, so two
backups started in the same minute cannot overwrite one another. A backup
*set* is all the files sharing one backup id. Older backups created before
this scheme (plain timestamps, no suffix) remain valid for restore and
retention.

## Restoring

To restore from a backup set, run:
```bash
python restore.py [--timestamp <ts>] [--files] [--database] [--all]
```

- Without `--timestamp`, the most recent backup set **containing the
  requested artifacts** is used — so a newer database-only set does not block
  restoring files from an older set (the split schedules below can produce
  this). If two complete sets share the newest timestamp (same-minute runs
  with different random suffixes), the run fails and lists their full ids:
  the suffix is random, so recency cannot be inferred — pass an explicit
  full backup id instead.
- `--files` / `--database` / `--all` select what to restore (default: both).
- `--timestamp` accepts either a full backup id (`20261014T0930Z-a1b2c3`)
  or a bare timestamp (`20261014T0930Z`). A bare timestamp is accepted only
  when it matches exactly one set; if several backups share the minute,
  the run fails and lists the full ids so you can pick one.
- An explicit `--timestamp` is strict: the set must exist and contain the
  requested artifacts; there is no fallback to older sets.
- `-v` / `--version` prints the version and exits.

If the local backup directory cannot be listed, restore reports an `ERROR:`
message and exits with status 2 before opening an SSH connection.

The restore process uploads the chosen tarballs to the server, verifies their
checksums there, extracts the files into `WP_SITE_ROOT` and imports the database
(via WP-CLI or `mysql`).

Before extracting site files, restore permits only regular files, directories,
and validated symbolic and hard links. Special members (including FIFOs,
devices and contiguous files) and unknown member types are rejected before any
site file is replaced. After checksum verification, the type flags are read
directly from the local archive, so the check does not depend on how the
server's `tar` labels member types; the server-side listing is checked as
well. The type check also hashes the exact bytes it inspected and requires
that digest to match the one the server computed for the uploaded archive,
so a local pathname replaced between upload and validation cannot approve a
different archive than the one that will be extracted. Local artifacts are
opened once through no-follow file descriptors and held open until they
have been validated and uploaded, so a symlink planted at an artifact path
(or a file swapped in after the initial open) cannot change which bytes
are uploaded or validated.

Before extraction, the existing site tree is audited for links that
extraction would traverse or replace: a pre-existing symlink at the site
root, at a member path, in a directory the archive writes into, or at a
path an archive symlink resolves to is rejected (it would divert writes
outside the site or complete an escape chain), and a pre-existing hard
link at a member path is rejected too — extracting a regular member over
it truncates the shared inode, overwriting the linked file (which may
live outside the site root, e.g. a hard-linked `wp-config.php` and
`authorized_keys`). Links elsewhere in the site that the archive never
touches are left alone.

**Warning:** restoring overwrites the current site contents and database. Take a
fresh backup immediately beforehand if you may need to roll back:

```bash
python backup.py --all
```

## Scheduling

### Linux (cron)

Edit your crontab with `crontab -e` and add lines such as:

```cron
# Daily database backup at 03:30, files weekly on Sunday at 04:00
30 3 * * * cd /path/to/wp_ssh_backup && .venv/bin/python backup.py --database >> backup.log 2>&1
0 4 * * 0 cd /path/to/wp_ssh_backup && .venv/bin/python backup.py --files >> backup.log 2>&1
```

### Windows (Task Scheduler via PowerShell)

Run the following in PowerShell to create a daily 03:30 backup task:

```powershell
$venvPython = "C:\path\to\wp_ssh_backup\.venv\Scripts\python.exe"
$projectDir = "C:\path\to\wp_ssh_backup"

$action = New-ScheduledTaskAction -Execute $venvPython `
    -Argument "backup.py --all" `
    -WorkingDirectory $projectDir
$trigger = New-ScheduledTaskTrigger -Daily -At 3:30am
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

Register-ScheduledTask -TaskName "WP SSH Backup" `
    -Action $action -Trigger $trigger -Settings $settings
```

To remove the task later:

```powershell
Unregister-ScheduledTask -TaskName "WP SSH Backup" -Confirm:$false
```

## Development

Install the development dependencies and run the tests:

```bash
pip install -r requirements-dev.txt
pytest
```

Unit and orchestration tests run entirely offline against a simulated SSH
server. Live integration tests (which use your real `.env` and a real host) are
opt-in:

```bash
WP_SSH_BACKUP_LIVE_TEST=1 pytest tests/test_live.py
```

### Linting

Two linters are configured, and CI runs both:

```bash
ruff check .     # style and correctness rules (see pyproject.toml)
pyflakes .       # undefined names, unused imports
```

`ruff` is the stricter of the two and covers pyflakes' `F` rules, so it is
the one to run while working; `pyflakes` is a quick, zero-configuration check.

### Continuous integration

A GitHub Actions workflow (`.github/workflows/tests.yml`) lints and runs the
offline test suite on every push and pull request, against Python 3.10 (the
minimum supported version) and 3.14 on Ubuntu. Live tests are excluded from
CI, as no host or credentials are available there.

### Project layout

The three entry points are thin: they parse arguments and orchestrate. The
work lives in focused modules.

### Entry points

| File | Responsibility |
| --- | --- |
| `backup.py` | Backup orchestration: create the remote artifacts, download, verify and publish them. |
| `restore.py` | Restore orchestration: select a set, upload it, verify it and extract it. |
| `authorize_host.py` | Fetch and record a host key. |
| `cli.py` | Shared command-line helpers (`--version`, the scope flags). |
| `version.py` | The single source of truth for the version number. |

### Low-level layer

| File | Responsibility |
| --- | --- |
| `errors.py` | The exception types, and the set of failures that mean "the run could not complete". |
| `config.py` | Loading and validating the configuration. |
| `remote.py` | The SSH and SFTP transport. |
| `remote_ops.py` | Remote operations both flows share: staging directories, the wp CLI, remote cleanup. |
| `wp_config.py` | Parsing `wp-config.php` on the remote host. |
| `db_config.py` | The MySQL option file that carries the database credentials. |
| `naming.py` | Timestamps, backup identifiers and artifact file names. |
| `checksums.py` | SHA-256 checksums of local files and of remote manifests. |
| `retention.py` | The backup sets held locally, and the retention policy. |
| `shell.py` | Quoting for remote shell commands. |
| `host_keys.py` | Host key fingerprints and `known_hosts` entries. |
| `safe_fs.py` | Local-filesystem primitives: no-follow opens, inode identity, atomic identity-bound removal, held descriptors. |
| `publish.py` | Publishing verified downloads under their final names, without replacing anything. |
| `publish_lock.py` | The cooperative publication lock and its stale-owner recovery. |
| `archive_validation.py` | Archive member validation, the destination-tree audit and verified extraction. |
| `selection.py` | Choosing which local backup set to restore. |

`common.py` re-exports the low-level layer, so `from common import ...` keeps
working; new code should import from the module that owns the name.

Every module can be imported and tested on its own; the test suite mirrors
this layout.

## Security notes

- Prefer SSH key authentication over passwords.
- Unknown SSH host keys are always rejected; authorise a server explicitly with
  `authorize_host.py` before first use (see *Host key verification*).
- Database credentials are never passed on remote command lines; they are
  supplied through a temporary option file that is deleted immediately after
  use. The option file is created owner-only (0600) on the server before any
  credentials are written to it.
- The `.env` file contains secrets — keep it out of version control.

## Changelog

All notable changes are recorded in [CHANGELOG.md](CHANGELOG.md), which follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The current version
is reported by every program:

```bash
python backup.py --version
```

## Licence

The project is licensed under the GNU General Public License 3 (GPLv3). See
the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and
submit a pull request. Ensure that your code follows the existing style and
includes appropriate tests.

Rob
