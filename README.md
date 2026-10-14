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
- On the server: `tar`, `gzip` and `sha256sum` (present on virtually all Linux
  hosts). For database backups, either [WP-CLI](https://wp-cli.org/) or
  `mysqldump` must be available.

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
| `WP_SITE_ROOT` | Absolute path to the WordPress root directory on the server. |
| `WP_CLI_PATH` | Optional explicit path to `wp` if it is not on the server PATH. |
| `BACKUP_DIR` | Local directory where backups are stored. |
| `RETENTION_DAYS` | Delete local backup sets older than this many days (0 disables pruning). |

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

1. A staging directory (`wp-ssh-backup-staging-<timestamp>`) is created as a
   **sibling** of the WordPress site root on the server.
2. The database is dumped with WP-CLI (`wp db export`) if it is installed;
   otherwise the database credentials are read from `wp-config.php` and
   `mysqldump` is used. In the fallback path, credentials are passed via a
   temporary option file (`--defaults-extra-file`) rather than the command line,
   so the password is never visible in the process list; the file is removed as
   soon as the dump completes (or fails).
3. The site root is packed into a gzip tarball, excluding the staging directory
   and `wp-content/cache`.
4. SHA-256 checksums are generated on the server.
5. The tarballs and checksum files are downloaded over SFTP into `BACKUP_DIR`.
6. Checksums are re-verified locally. If verification fails, the remote staging
   directory is **kept** so the transfer can be retried; otherwise it is
   deleted.
7. Local backup sets older than `RETENTION_DAYS` are pruned.

Backups are named `wp-db-<timestamp>.tar.gz` and `wp-files-<timestamp>.tar.gz`,
where `<timestamp>` is in UTC in the form `20261014T0930Z`. A backup *set* is
all the files sharing one timestamp.

## Restoring

To restore from a backup set, run:
```bash
python restore.py [--timestamp <ts>] [--files] [--database] [--all]
```

- Without `--timestamp`, the most recent backup set is used.
- `--files` / `--database` / `--all` select what to restore (default: both).

The restore process uploads the chosen tarballs to the server, verifies their
checksums there, extracts the files into `WP_SITE_ROOT` and imports the database
(via WP-CLI or `mysql`).

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

### Continuous integration

A GitHub Actions workflow (`.github/workflows/tests.yml`) runs the offline test
suite on every push and pull request, against Python 3.10 (the minimum
supported version) and 3.14 on Ubuntu. Live tests are excluded from CI, as no
host or credentials are available there.

## Security notes

- Prefer SSH key authentication over passwords.
- Database credentials are never passed on remote command lines; they are
  supplied through a temporary option file that is deleted immediately after
  use.
- The `.env` file contains secrets — keep it out of version control.

## Licence

The project is licensed under the GNU General Public License 3 (GPLv3). See
the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and
submit a pull request. Ensure that your code follows the existing style and
includes appropriate tests.

Rob
