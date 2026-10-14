"""Shared helpers for WP SSH Backup.

Contains configuration loading, SSH/SFTP plumbing, checksum utilities,
timestamp/naming helpers and wp-config.php parsing used by both backup.py and
restore.py.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import re
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import paramiko
from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class WPSSHBackupError(Exception):
    """Base class for all WP SSH Backup errors."""


class ConfigError(WPSSHBackupError):
    """Raised when .env configuration is missing or invalid."""


class RemoteCommandError(WPSSHBackupError):
    """Raised when a remote command exits with a non-zero status."""

    def __init__(self, command: str, exit_code: int, stderr: str) -> None:
        self.command = command
        self.exit_code = exit_code
        self.stderr = stderr
        super().__init__(
            f"Remote command failed (exit {exit_code}): {command}\n"
            f"stderr: {stderr.strip() or '(empty)'}"
        )


class ChecksumError(WPSSHBackupError):
    """Raised when an artifact fails SHA-256 verification."""


class MissingArtifactError(WPSSHBackupError):
    """Raised when an expected file (local or remote) cannot be found."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REQUIRED_KEYS = ("SSH_HOST", "SSH_USER", "WP_SITE_ROOT", "BACKUP_DIR")


@dataclass(frozen=True)
class Config:
    ssh_host: str
    ssh_port: int
    ssh_user: str
    ssh_key_path: str | None
    ssh_password: str | None
    wp_site_root: str
    wp_cli_path: str | None
    backup_dir: Path
    retention_days: int


def _get_int(name: str, default: int, minimum: int = 1) -> int:
    """
    Retrieve an integer environment variable with validation.

    Args:
        name: The name of the environment variable.
        default: The default value to use if the environment variable is not
            set.
        minimum: The minimum acceptable value (inclusive).

    Returns:
        The integer value of the environment variable, or the default if not
        set.

    Raises:
        ConfigError: If the environment variable is not a valid integer or is
        below the minimum.
    """
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _find_env_file() -> Path:
    cwd_env = Path.cwd() / ".env"
    if cwd_env.is_file():
        return cwd_env
    return Path(__file__).resolve().parent / ".env"


def load_config(env_file: str | os.PathLike | None = None) -> Config:
    """
    Load and validate configuration from a .env file.

    Real environment variables take precedence over .env values (standard
    python-dotenv behaviour).

    Args:
        env_file: Path to the .env file. If None, the function will attempt to
            locate a .env file in the current working directory or the script's
            directory.

    Returns:
        A Config object populated with the validated configuration.

    Raises:
        ConfigError: If required settings are missing or invalid.
    """
    if env_file is not None:
        env_path = Path(env_file)
        if not env_path.is_file():
            raise ConfigError(f"Config file not found: {env_path}")
    else:
        env_path = _find_env_file()
        if not env_path.is_file():
            raise ConfigError(
                "No .env file found. Copy .env.example to .env and fill in "
                "your SSH and WordPress settings."
            )
    load_dotenv(env_path)

    missing = [key for key in REQUIRED_KEYS if not os.getenv(key, "").strip()]
    if missing:
        raise ConfigError(
            "Missing required setting(s) in .env: " + ", ".join(missing)
        )

    site_root = os.getenv("WP_SITE_ROOT", "").strip()
    if not site_root.startswith("/"):
        raise ConfigError(
            "WP_SITE_ROOT must be an absolute remote path "
            f"(starting with '/'), got {site_root!r}"
        )

    return Config(
        ssh_host=os.getenv("SSH_HOST", "").strip(),
        ssh_port=_get_int("SSH_PORT", 22),
        ssh_user=os.getenv("SSH_USER", "").strip(),
        ssh_key_path=os.getenv("SSH_KEY_PATH", "").strip() or None,
        ssh_password=os.getenv("SSH_PASSWORD", "") or None,
        wp_site_root=site_root.rstrip("/") or "/",
        wp_cli_path=os.getenv("WP_CLI_PATH", "").strip() or None,
        backup_dir=Path(os.getenv("BACKUP_DIR", "").strip()).expanduser(),
        retention_days=_get_int("RETENTION_DAYS", 30, minimum=0),
    )


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------


def connect(config: Config) -> paramiko.SSHClient:
    """
    Open an SSH connection using the configured credentials.

    Args:
        config: The configuration object containing SSH connection details.

    Returns:
        An active paramiko.SSHClient connected to the remote host.

    Raises:
        WPSSHBackupError: If the SSH connection or authentication fails.
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    kwargs: dict[str, object] = {
        "hostname": config.ssh_host,
        "port": config.ssh_port,
        "username": config.ssh_user,
        "timeout": 30,
        "allow_agent": True,
        "look_for_keys": True,
    }
    if config.ssh_key_path:
        kwargs["key_filename"] = str(Path(config.ssh_key_path).expanduser())
        kwargs["allow_agent"] = False
        kwargs["look_for_keys"] = False
    if config.ssh_password:
        kwargs["password"] = config.ssh_password

    try:
        client.connect(**kwargs)
    except paramiko.AuthenticationException as exc:
        client.close()
        raise WPSSHBackupError(
            "SSH authentication failed. Check SSH_USER, SSH_KEY_PATH and "
            "SSH_PASSWORD in .env."
        ) from exc
    except paramiko.SSHException as exc:
        client.close()
        raise WPSSHBackupError(
            f"SSH connection to {config.ssh_host} failed: {exc}"
        ) from exc
    except OSError as exc:
        client.close()
        raise WPSSHBackupError(
            f"Could not reach {config.ssh_host}:{config.ssh_port}: {exc}"
        ) from exc
    return client


def run_remote_cmd(
    client: paramiko.SSHClient,
    command: str,
    timeout: float | None = None,
) -> tuple[int, str, str]:
    """
    Execute a command remotely, returning (exit_code, stdout, stderr).

    stderr is drained on a background thread so that a chatty stderr stream
    cannot deadlock the stdout read.

    Args:
        client: An active SSH client connected to the remote host.
        command: The command to execute on the remote host.
        timeout: Optional timeout for the command execution.

    Returns:
        A tuple containing the exit code, stdout, and stderr as strings.
    """
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    stderr_chunks: list[bytes] = []

    def _drain_stderr() -> None:
        stderr_chunks.append(stderr.read())

    reader = threading.Thread(target=_drain_stderr, daemon=True)
    reader.start()
    out = stdout.read()
    exit_code = stdout.channel.recv_exit_status()
    reader.join(timeout=10)
    err = b"".join(stderr_chunks)
    return (
        exit_code,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
    )


def run_remote_cmd_checked(
    client: paramiko.SSHClient,
    command: str,
    timeout: float | None = None,
) -> str:
    """
    Run a command, raising RemoteCommandError on a non-zero exit.

    Args:
        client: An active SSH client connected to the remote host.
        command: The command to execute on the remote host.
        timeout: Optional timeout for the command execution.

    Returns:
        The stdout output of the command as a string.

    Raises:
        RemoteCommandError: If the command exits with a non-zero status.
    """
    code, out, err = run_remote_cmd(client, command, timeout=timeout)
    if code != 0:
        raise RemoteCommandError(command, code, err)
    return out


# ---------------------------------------------------------------------------
# SFTP
# ---------------------------------------------------------------------------


def sftp_download(
    sftp: paramiko.SFTPClient, remote_path: str, local_path: str | Path
) -> Path:
    """
    Download a file from the remote host via SFTP.

    Args:
        sftp: An active SFTP client connected to the remote host.
        remote_path: The path to the file on the remote host.
        local_path: The local path where the file should be saved.

    Returns:
        The local path to the downloaded file as a Path object.
    """
    local = Path(local_path)
    local.parent.mkdir(parents=True, exist_ok=True)
    sftp.get(remote_path, str(local))
    return local


def sftp_upload(
    sftp: paramiko.SFTPClient, local_path: str | Path, remote_path: str
) -> str:
    """
    Upload a file to the remote host via SFTP.

    Args:
        sftp: An active SFTP client connected to the remote host.
        local_path: The local path to the file to be uploaded.
        remote_path: The path on the remote host where the file should be
            saved.

    Returns:
        The remote path to the uploaded file as a string.
    """
    sftp.put(str(local_path), remote_path)
    return remote_path


def remote_path_exists(sftp: paramiko.SFTPClient, remote_path: str) -> bool:
    """
    Check if a remote path exists on the remote host via SFTP.

    Args:
        sftp: An active SFTP client connected to the remote host.
        remote_path: The path on the remote host to check.

    Returns:
        True if the remote path exists, False otherwise.
    """
    try:
        sftp.stat(remote_path)
        return True
    except OSError:
        return False


def write_remote_file(
    sftp: paramiko.SFTPClient,
    remote_path: str,
    content: str | bytes,
    mode: int = 0o600,
) -> None:
    """
    Write content to a remote file via SFTP, creating or overwriting it.

    Args:
        sftp: An active SFTP client connected to the remote host.
        remote_path: The path on the remote host where the file should be
            written.
        content: The content to write to the file, as a string or bytes.
        mode: The file permissions to set on the remote file (default: 0o600).

    Returns:
        None.
    """
    data = content.encode("utf-8") if isinstance(content, str) else content
    with sftp.open(remote_path, "wb") as handle:
        handle.write(data)
    sftp.chmod(remote_path, mode)


def read_remote_file(sftp: paramiko.SFTPClient, remote_path: str) -> str:
    """
    Read the content of a remote file via SFTP.

    Args:
        sftp: An active SFTP client connected to the remote host.
        remote_path: The path on the remote host to the file to be read.

    Returns:
        The content of the remote file as a string, decoded using UTF-8.
    """
    with sftp.open(remote_path, "rb") as handle:
        return handle.read().decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# wp-config.php parsing
# ---------------------------------------------------------------------------

WP_DB_KEYS = ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST")

WP_DEFINE_RE = re.compile(
    r"define\s*\(\s*['\"](?P<name>DB_[A-Za-z_]+)['\"]\s*,\s*"
    r"(?P<q>['\"])(?P<value>(?:\\.|(?!(?P=q)).)*)(?P=q)\s*\)\s*;",
    re.DOTALL,
)


def _unescape_php(value: str) -> str:
    """
    Unescape PHP string literals by converting escaped characters to their
    literal form.

    Args:
        value: The PHP string literal to unescape.

    Returns:
        The unescaped string.
    """
    return re.sub(r"\\(.)", r"\1", value)


def parse_wp_config(text: str) -> dict[str, str]:
    """
    Extract WordPress DB connection settings from wp-config.php source.

    Note:
        Only literal string values are recognised; wp-config files that build
        values dynamically (e.g. from getenv) will yield missing keys, which
        callers report as a clear error.

    Args:
        text: The content of the wp-config.php file as a string.

    Returns:
        A dictionary containing the WordPress DB connection settings, with keys
        being the setting names (e.g., "DB_NAME") and values being the
        corresponding values from the wp-config.php file.
    """
    found: dict[str, str] = {}
    for match in WP_DEFINE_RE.finditer(text):
        name = match.group("name").upper()
        if name in WP_DB_KEYS and name not in found:
            found[name] = _unescape_php(match.group("value"))
    return found


def read_wp_db_settings(
    sftp: paramiko.SFTPClient, site_root: str
) -> dict[str, str]:
    """
    Read wp-config.php over SFTP and validate the required DB keys.

    Args:
        sftp: An active Paramiko SFTP client connected to the remote host.
        site_root: The root directory of the WordPress site on the remote host.

    Returns:
        A dictionary containing the WordPress DB connection settings, with keys
        being the setting names (e.g., "DB_NAME") and values being the
        corresponding values from the wp-config.php file.
    """
    wp_config_path = posixpath.join(site_root, "wp-config.php")
    if not remote_path_exists(sftp, wp_config_path):
        raise MissingArtifactError(
            f"{wp_config_path} not found on the remote host; cannot determine "
            "database credentials."
        )
    settings = parse_wp_config(read_remote_file(sftp, wp_config_path))
    missing = [key for key in WP_DB_KEYS if key not in settings]
    if missing:
        raise MissingArtifactError(
            "wp-config.php is missing database setting(s): "
            + ", ".join(missing)
        )
    return settings


# ---------------------------------------------------------------------------
# MySQL option file (credential hardening)
# ---------------------------------------------------------------------------


def split_db_host(db_host: str) -> tuple[str, str | None, str | None]:
    """
    Split a wp-config DB_HOST value into (host, port, socket path).

    Args:
        db_host: The DB_HOST value from wp-config.php.

    Returns:
        A tuple of (host, port, socket path), where port and socket path may be
        None.
    """
    if ":" not in db_host:
        return db_host, None, None
    host, _, rest = db_host.partition(":")
    if rest.isdigit():
        return host or "localhost", rest, None
    return host or "localhost", None, rest


def mysql_client_config(
    host: str,
    user: str,
    password: str,
    port: str | None = None,
    socket: str | None = None,
) -> str:
    """
    Build a [client] option-file body.

    Credentials are supplied to mysqldump/mysql via --defaults-extra-file so
    they never appear on a command line, where they would be visible to other
    users through the process list.

    Args:
        host: The MySQL server host.
        user: The MySQL username.
        password: The MySQL password.
        port: The MySQL server port, if specified.
        socket: The MySQL socket path, if specified.

    Returns:
        A string containing the [client] option-file body.
    """

    def escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    lines = ["[client]"]
    if socket:
        lines.append(f'socket="{escape(socket)}"')
    else:
        lines.append(f'host="{escape(host)}"')
        if port:
            lines.append(f'port="{escape(port)}"')
    lines.append(f'user="{escape(user)}"')
    lines.append(f'password="{escape(password)}"')
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Timestamps and file naming
# ---------------------------------------------------------------------------

TS_FORMAT = "%Y%m%dT%H%MZ"
TS_PATTERN = r"\d{8}T\d{4}Z"
STAGING_PREFIX = "wp-ssh-backup-staging-"


def utc_timestamp(now: datetime | None = None) -> str:
    """
    Return a UTC timestamp string such as 20261014T0930Z.

    Args:
        now: The current datetime. If None, the current UTC time is used.

    Returns:
        A string representing the UTC timestamp.
    """
    return (now or datetime.now(timezone.utc)).strftime(TS_FORMAT)


def parse_timestamp(ts: str) -> datetime:
    """
    Parse a timestamp string produced by utc_timestamp().

    Args:
        ts: The timestamp string to parse.

    Returns:
        A datetime object representing the parsed UTC timestamp.
    """
    return datetime.strptime(ts, TS_FORMAT).replace(tzinfo=timezone.utc)


def staging_dir_for(site_root: str, ts: str) -> str:
    """
    Sibling directory of the site root used to stage remote artifacts.

    A sibling (rather than a directory inside the site root) keeps the staging
    files out of the file tarball and on the same filesystem for fast tars.

    Args:
        site_root: The root directory of the WordPress site.
        ts: The timestamp string to include in the staging directory name.

    Returns:
        The path to the staging directory.
    """
    parent = posixpath.dirname(site_root.rstrip("/")) or "/"
    return posixpath.join(parent, STAGING_PREFIX + ts)


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


def timestamp_from_archive_name(name: str) -> str | None:
    """
    Return the backup timestamp encoded in an archive filename.

    Args:
        name: The name of the archive file.

    Returns:
        The timestamp string if found, otherwise None.
    """
    match = BACKUP_FILE_RE.match(name)
    if match and name.endswith(".tar.gz"):
        return match.group("ts")
    return None


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

    Args:
        text: The output of the `sha256sum` command as a string.

    Returns:
        A dictionary where the keys are filenames and the values are the
        corresponding SHA-256 digests.
    """
    result: dict[str, str] = {}
    for digest, name in SHA256SUM_LINE_RE.findall(text):
        result[name.strip()] = digest.lower()
    return result


# ---------------------------------------------------------------------------
# Local backup sets and retention
# ---------------------------------------------------------------------------

BACKUP_FILE_RE = re.compile(
    r"^wp-(?P<kind>db|files)-(?P<ts>" + TS_PATTERN + r")\.tar\.gz(\.sha256)?$"
)


def find_backup_sets(backup_dir: Path) -> dict[str, list[Path]]:
    """
    Map each backup timestamp to the local files belonging to that set.

    Args:
        backup_dir: The directory containing the backup files.

    Returns:
        A dictionary where the keys are backup timestamps and the values are
        lists of Paths to the corresponding backup files.
    """
    sets: dict[str, list[Path]] = {}
    if not backup_dir.is_dir():
        return sets
    for path in sorted(backup_dir.iterdir()):
        if not path.is_file():
            continue
        match = BACKUP_FILE_RE.match(path.name)
        if match:
            sets.setdefault(match.group("ts"), []).append(path)
    return sets


def prune_local_backups(
    backup_dir: Path,
    retention_days: int,
    now: datetime | None = None,
) -> list[str]:
    """
    Delete whole backup sets older than retention_days.

    Args:
        backup_dir: The directory containing the backup files.
        retention_days: The number of days to retain backups.
        now: The current datetime for comparison (defaults to UTC now).

    Returns:
        The timestamps of the removed sets. A retention_days of 0
        disables pruning.
    """
    if retention_days <= 0:
        return []
    now_dt = now or datetime.now(timezone.utc)
    cutoff = now_dt - timedelta(days=retention_days)
    removed: list[str] = []
    for ts, files in find_backup_sets(backup_dir).items():
        try:
            ts_dt = parse_timestamp(ts)
        except ValueError:
            continue
        if ts_dt < cutoff:
            for path in files:
                path.unlink(missing_ok=True)
            removed.append(ts)
    return removed


# ---------------------------------------------------------------------------
# Higher-level remote helpers shared by backup and restore
# ---------------------------------------------------------------------------


def detect_wp_cli(client: paramiko.SSHClient, config: Config) -> str | None:
    """
    Detect the path to the wp CLI binary on the remote host.

    Args:
        client: An active Paramiko SSHClient connected to the remote host.
        config: The configuration object containing potential wp_cli_path.

    Returns:
        The path to the wp CLI binary, or None if it is not available on the
        remote host.
    """
    if config.wp_cli_path:
        test_cmd = f"test -x {shquote(config.wp_cli_path)}"
        code, _, _ = run_remote_cmd(client, test_cmd)
        if code != 0:
            raise WPSSHBackupError(
                f"WP_CLI_PATH is set to {config.wp_cli_path} but it is not "
                "executable on the remote host."
            )
        return config.wp_cli_path
    code, out, _ = run_remote_cmd(client, "command -v wp")
    if code == 0:
        lines = out.strip().splitlines()
        if lines:
            return lines[0]
    return None


def remove_remote_staging(client: paramiko.SSHClient, staging: str) -> None:
    """
    Best-effort removal of the remote staging directory.

    Args:
        client: An active Paramiko SSHClient connected to the remote host.
        staging: The path to the remote staging directory.
    """
    try:
        run_remote_cmd_checked(client, f"rm -rf {shquote(staging)}")
    except WPSSHBackupError as exc:
        print(
            "WARNING: could not remove remote staging directory "
            f"{staging}: {exc}",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


def shquote(path: str) -> str:
    """
    Single-quote a path for safe use in a remote shell command.

    Args:
        path: The path to be quoted.

    Returns:
        The single-quoted path as a string.
    """
    return "'" + path.replace("'", "'\\''") + "'"


def human_size(num_bytes: int | float) -> str:
    """
    Convert a size in bytes to a human-readable string with appropriate units.

    Args:
        num_bytes: The size in bytes.

    Returns:
        A human-readable string representing the size.
    """
    size = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"
