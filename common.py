"""Shared helpers for WP SSH Backup.

Contains configuration loading, SSH/SFTP plumbing, checksum utilities,
timestamp/naming helpers and wp-config.php parsing used by both backup.py and
restore.py.
"""

from __future__ import annotations

import base64
import hashlib
import os
import posixpath
import re
import secrets
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


class UnknownHostKeyError(WPSSHBackupError):
    """Raised when the server presents a host key that is not trusted."""


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
    ssh_known_hosts: str | None
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
    if site_root.rstrip("/") == "":
        # The staging dir is a sibling of the site root; for '/' it would
        # be '/wp-ssh-backup-staging-...' — INSIDE the '.' being archived,
        # so the backup would capture its own staging directory (including
        # the database dump and the growing files archive).
        raise ConfigError(
            "WP_SITE_ROOT must not be '/': the staging directory would "
            "sit inside the archived tree and the backup would capture "
            "itself. Point WP_SITE_ROOT at the WordPress directory "
            "(e.g. /home/user/public_html)."
        )

    return Config(
        ssh_host=os.getenv("SSH_HOST", "").strip(),
        ssh_port=_get_int("SSH_PORT", 22),
        ssh_user=os.getenv("SSH_USER", "").strip(),
        ssh_key_path=os.getenv("SSH_KEY_PATH", "").strip() or None,
        ssh_password=os.getenv("SSH_PASSWORD", "") or None,
        ssh_known_hosts=os.getenv("SSH_KNOWN_HOSTS", "").strip() or None,
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

    The server's host key must already be trusted: it is looked up in the
    file named by SSH_KNOWN_HOSTS (if set) and in the user's system
    known_hosts file. Unknown keys are rejected — see authorize_host.py for
    provisioning the trust before the first connection.

    Args:
        config: The configuration object containing SSH connection details.

    Returns:
        An active paramiko.SSHClient connected to the remote host.

    Raises:
        WPSSHBackupError: If the SSH connection or authentication fails, or
            the server's host key is not trusted.
    """
    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()
    except (OSError, UnicodeDecodeError, paramiko.SSHException) as exc:
        # A malformed default known_hosts file (e.g. undecodable bytes)
        # would otherwise escape as a traceback before connect() is
        # reached.
        client.close()
        raise WPSSHBackupError(
            f"Could not load the system known_hosts file: {exc}"
        ) from exc
    if config.ssh_known_hosts:
        known_hosts_path = Path(config.ssh_known_hosts).expanduser()
        if not known_hosts_path.is_file():
            raise WPSSHBackupError(
                f"SSH_KNOWN_HOSTS file not found: {known_hosts_path}. "
                "Run authorize_host.py to create it."
            )
        try:
            client.load_host_keys(str(known_hosts_path))
        except (
            OSError,
            UnicodeDecodeError,
            paramiko.SSHException,
        ) as exc:
            # An unreadable or malformed known_hosts file raises before the
            # guarded connect() below; convert it so the CLIs report a
            # clear configuration error instead of a traceback.
            client.close()
            raise WPSSHBackupError(
                f"Could not load SSH_KNOWN_HOSTS file "
                f"{known_hosts_path}: {exc}"
            ) from exc
    # Unknown host keys are always rejected; there is no auto-add.
    client.set_missing_host_key_policy(paramiko.RejectPolicy())

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
    except paramiko.BadHostKeyException as exc:
        client.close()
        raise WPSSHBackupError(
            f"HOST KEY MISMATCH for {exc.hostname}: the server presented a "
            "different key than the trusted one. This can indicate a "
            "man-in-the-middle attack, or a legitimate server rebuild. "
            "Verify the new fingerprint out-of-band, then update the entry "
            "with authorize_host.py."
        ) from exc
    except paramiko.SSHException as exc:
        client.close()
        message = str(exc)
        rejected = "key was rejected" in message
        not_found = "not found in known_hosts" in message
        if rejected or not_found:
            raise UnknownHostKeyError(
                "The server's host key is not trusted. Run "
                "'python authorize_host.py' to review and authorise it "
                f"before connecting. ({message})"
            ) from exc
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

    Note:
        The process umask is tightened to 077 for the duration of the
        write so the SFTP server creates the file already restricted to
        the requesting user (SFTP servers apply their umask at creation
        time). Relying on a post-write chmod alone would leave the secret
        readable to other host users during the write window. The
        previous umask is restored afterwards.
    """
    data = content.encode("utf-8") if isinstance(content, str) else content
    old_umask = os.umask(0o077)
    try:
        with sftp.open(remote_path, "wb") as handle:
            handle.write(data)
    finally:
        os.umask(old_umask)
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

# Escape sequences PHP recognises, per string delimiter. Anything else
# keeps its backslash, matching PHP's behaviour.
_SINGLE_ESCAPES = {"'", "\\"}

_DOUBLE_ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "f": "\f",
    "e": "\x1b",
    "\\": "\\",
    '"': '"',
    "$": "$",
}

WP_DEFINE_RE = re.compile(
    r"\bdefine\s*\(\s*['\"](?P<name>DB_[A-Za-z_]+)['\"]\s*,\s*"
    r"(?P<q>['\"])(?P<value>(?:\\.|(?!(?P=q)).)*)(?P=q)\s*\)\s*;",
    re.DOTALL,
)


def strip_php_comments(source: str) -> tuple[str, list[bool]]:
    """
    Remove PHP comments from source while preserving string literals.

    A single pass tracks whether the scanner is inside a single- or
    double-quoted string (honouring backslash escapes) or inside a line
    ('//' or '#') or block ('/* ... */') comment. Comment openers are only
    recognised in code, so comment-like text inside string literals — for
    example a password containing '//' or '/*' — is preserved verbatim.
    Each comment is replaced by a single space, mirroring the PHP
    tokenizer, which treats comments as whitespace.

    Args:
        source: The PHP source text.

    Returns:
        A tuple of (stripped, in_string): stripped is the source with
        comments removed, and in_string[i] is True when stripped[i] lies
        inside a string literal. Heredocs and the '?>' HTML mode are not
        tracked; wp-config.php does not use them.
    """
    out: list[str] = []
    in_string: list[bool] = []
    i = 0
    n = len(source)
    state = "code"
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "'":
                state = "single"
                out.append(ch)
                in_string.append(False)
                i += 1
            elif ch == '"':
                state = "double"
                out.append(ch)
                in_string.append(False)
                i += 1
            elif ch == "/" and nxt == "/":
                state = "line"
                out.append(" ")
                in_string.append(False)
                i += 2
            elif ch == "#":
                state = "line"
                out.append(" ")
                in_string.append(False)
                i += 1
            elif ch == "/" and nxt == "*":
                state = "block"
                out.append(" ")
                in_string.append(False)
                i += 2
            else:
                out.append(ch)
                in_string.append(False)
                i += 1
        elif state == "single" or state == "double":
            quote = "'" if state == "single" else '"'
            if ch == "\\" and nxt:
                out.append(ch)
                in_string.append(True)
                out.append(nxt)
                in_string.append(True)
                i += 2
            else:
                if ch == quote:
                    state = "code"
                out.append(ch)
                in_string.append(ch != quote)
                i += 1
        elif state == "line":
            if ch == "\n":
                state = "code"
                out.append(ch)
                in_string.append(False)
            i += 1
        else:  # block comment
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
            else:
                i += 1
    return "".join(out), in_string


def _unescape_php(value: str, quote: str) -> str:
    r"""
    Decode PHP escape sequences in the raw text of a string literal.

    PHP retains the backslash for escape sequences it does not recognise,
    so 'p\q' denotes p\q rather than pq; only sequences PHP recognises
    are decoded here. Single-quoted strings recognise only \' and \\;
    double-quoted strings additionally recognise \n, \r, \t, \v, \f,
    \e, \$, octal, hex and \u{...} sequences.

    Args:
        value: The raw text between the string delimiters.
        quote: The delimiter the literal was written with (' or ").

    Returns:
        The decoded string value.
    """
    out: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = value[i + 1]
        if quote == "'":
            if nxt in _SINGLE_ESCAPES:
                out.append(nxt)
            else:
                out.append(ch + nxt)
            i += 2
            continue
        simple = _DOUBLE_ESCAPES.get(nxt)
        if simple is not None:
            out.append(simple)
            i += 2
            continue
        if nxt == "x":
            hexa = re.match(r"[0-9A-Fa-f]{1,2}", value[i+2:])
            if hexa:
                out.append(chr(int(hexa.group(0), 16)))
                i += 2 + len(hexa.group(0))
                continue
        elif nxt == "u":
            uni = re.match(r"\{[0-9A-Fa-f]+\}", value[i+2:])
            if uni:
                out.append(chr(int(uni.group(0)[1:-1], 16)))
                i += 2 + len(uni.group(0))
                continue
        elif nxt in "01234567":
            octal = re.match(r"[0-7]{1,2}", value[i+2:])
            digits = 1 + (len(octal.group(0)) if octal else 0)
            octal_value = int(value[i+1:i+1+digits], 8) % 256
            out.append(chr(octal_value))
            # Advance past the backslash and every consumed octal digit;
            # forgetting this leaves i unchanged and loops forever.
            i += 1 + digits
            continue
        # Unrecognised escape: PHP keeps the backslash.
        out.append(ch + nxt)
        i += 2
    return "".join(out)


def parse_wp_config(text: str) -> dict[str, str]:
    """
    Extract WordPress DB connection settings from wp-config.php source.

    PHP comments are removed before definitions are selected, so a
    commented-out define can no longer shadow the real one; comment-like
    text inside string literals is preserved, so values containing '//' or
    '/*' survive intact. A define appearing inside a string literal is not
    treated as code.

    Note:
        Only literal string values are recognised; wp-config files that build
        values dynamically (e.g. from getenv) will yield missing keys, which
        callers report as a clear error. Heredoc strings and the '?>' HTML
        mode are not tracked. Escape sequences are decoded per PHP rules;
        unrecognised escapes keep their backslash.

    Args:
        text: The content of the wp-config.php file as a string.

    Returns:
        A dictionary containing the WordPress DB connection settings, with keys
        being the setting names (e.g., "DB_NAME") and values being the
        corresponding values from the wp-config.php file.
    """
    stripped, in_string = strip_php_comments(text)
    found: dict[str, str] = {}
    for match in WP_DEFINE_RE.finditer(stripped):
        if in_string[match.start()]:
            continue
        name = match.group("name").upper()
        if name in WP_DB_KEYS and name not in found:
            found[name] = _unescape_php(
                match.group("value"), match.group("q")
            )
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

    IPv6 literals are handled per MySQL conventions: an unbracketed
    address such as '::1' is returned whole (it contains no port or
    socket suffix), while a bracketed address such as '[::1]:3306' is
    unwrapped before the port or socket path after the closing bracket is
    parsed.

    Args:
        db_host: The DB_HOST value from wp-config.php.

    Returns:
        A tuple of (host, port, socket path), where port and socket path may be
        None.
    """
    # Bracketed IPv6 literal, optionally with :port or :/socket/path.
    if db_host.startswith("["):
        closing = db_host.find("]")
        if closing != -1:
            host = db_host[1:closing]
            rest = db_host[closing + 1:]
            if rest.startswith(":"):
                rest = rest[1:]
                if rest.isdigit():
                    return host, rest, None
                if rest:
                    return host, None, rest
            return host, None, None
    # Unbracketed IPv6 literal ('::1', '2001:db8::1'): more than one
    # colon means it cannot be a host:port or host:socket form.
    if db_host.count(":") > 1:
        return db_host, None, None
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
RUN_SUFFIX_RE = r"(?:-[0-9a-f]{6})?"
BACKUP_ID_PATTERN = TS_PATTERN + RUN_SUFFIX_RE
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
# Local backup sets and retention
# ---------------------------------------------------------------------------

BACKUP_FILE_RE = re.compile(
    r"^wp-(?P<kind>db|files)-(?P<bid>" + BACKUP_ID_PATTERN + r")\.tar\.gz"
    r"(\.sha256)?$"
)


def find_backup_sets(backup_dir: Path) -> dict[str, list[Path]]:
    """
    Map each backup timestamp to the local files belonging to that set.

    Groups that contain no archive (e.g. an orphaned .sha256 file left
    behind after its tarball was deleted) are omitted: such a group has
    no backup id extractable from an archive name, and including it would
    make set selection fail on a group that can never be restored.

    Groups whose backup id parses to an invalid date (e.g. month 13 in
    '20261301T0000Z' — the filename regex only checks the shape) are also
    omitted, so an unparseable id can never reach date-based selection
    logic and crash it.

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
            sets.setdefault(match.group("bid"), []).append(path)
    result: dict[str, list[Path]] = {}
    for bid, files in sets.items():
        if not any(
            backup_id_from_archive_name(path.name) for path in files
        ):
            continue
        try:
            parse_backup_id(bid)
        except ValueError:
            continue
        result[bid] = files
    return result


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
    for bid, files in find_backup_sets(backup_dir).items():
        try:
            bid_dt = parse_backup_id(bid)
        except ValueError:
            continue
        if bid_dt < cutoff:
            for path in files:
                path.unlink(missing_ok=True)
            removed.append(bid)
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

    Transport failures (a dropped SSH connection raises OSError or
    paramiko.SSHException) are caught as well as command failures, so a
    cleanup problem can never replace the original error that triggered
    the cleanup; it is reported as a warning instead.

    Args:
        client: An active Paramiko SSHClient connected to the remote host.
        staging: The path to the remote staging directory.
    """
    try:
        run_remote_cmd_checked(client, f"rm -rf {shquote(staging)}")
    except (WPSSHBackupError, OSError, paramiko.SSHException) as exc:
        print(
            "WARNING: could not remove remote staging directory "
            f"{staging}: {exc}",
            file=sys.stderr,
        )


def remove_remote_file(client: paramiko.SSHClient, path: str) -> None:
    """
    Best-effort removal of a single remote file.

    Used for credential files (e.g. the temporary MySQL cnf) that must be
    cleaned up even when the command that used them failed. Like
    remove_remote_staging, transport failures and command failures are
    caught and reported as a warning, so cleanup can never mask the
    original error that triggered it.

    Args:
        client: An active Paramiko SSHClient connected to the remote host.
        path: The path to the remote file.
    """
    try:
        run_remote_cmd_checked(client, f"rm -f {shquote(path)}")
    except (WPSSHBackupError, OSError, paramiko.SSHException) as exc:
        print(
            f"WARNING: could not remove remote file {path}: {exc}",
            file=sys.stderr,
        )


def allocate_remote_dir(
    client: paramiko.SSHClient,
    site_root: str,
    prefix: str,
    attempts: int = 5,
) -> str:
    """
    Create an exclusive remote directory as a sibling of site_root.

    The directory name is the prefix plus a fresh backup id, and it is
    created with a bare mkdir so an existing directory is a collision
    rather than shared use; on collision the allocation retries with a new
    id. Callers must recursively delete only the returned path, never a
    fixed name, so unrelated remote data cannot be destroyed.

    Args:
        client: An active Paramiko SSHClient connected to the remote host.
        site_root: The directory the new directory is created alongside.
        prefix: Name prefix for the directory; must not contain '/'.
        attempts: How many distinct ids to try before giving up.

    Returns:
        The allocated directory path.

    Raises:
        WPSSHBackupError: If no exclusive directory could be created, or
            the prefix contains '/'.
    """
    if "/" in prefix:
        raise WPSSHBackupError(
            f"Directory prefix must not contain '/': {prefix!r}"
        )
    parent = posixpath.dirname(site_root.rstrip("/")) or "/"
    last_error = ""
    for _ in range(max(1, attempts)):
        candidate = posixpath.join(parent, prefix + backup_id())
        code, _, err = run_remote_cmd(
            client, f"mkdir {shquote(candidate)}"
        )
        if code == 0:
            return candidate
        last_error = err.strip()
    raise WPSSHBackupError(
        f"Could not allocate an exclusive remote directory under {parent} "
        f"with prefix {prefix!r}: {last_error or 'target already exists'}"
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


def trap_rm_action(path: str) -> str:
    """
    Build a trap action that removes a file, quoted as one shell argument.

    The path is single-quoted inside the action, and the complete action is
    single-quoted again, so the shell hands trap exactly one argument and
    re-evaluates it safely when the signal fires. Nesting the quotes the
    other way round (quoting the action but letting the path's quotes
    terminate it) splits the action into several arguments: trap then
    rejects the bogus signal name, the cleanup never runs, and shell
    metacharacters in the path would be re-evaluated.

    Args:
        path: The path of the file the trap should remove.

    Returns:
        A fully-quoted trap action, ready for 'trap <action> EXIT'.
    """
    return shquote(f"rm -f {shquote(path)}")


def fingerprint(key: paramiko.PKey) -> str:
    """
    Return the OpenSSH-style SHA-256 fingerprint of a host key.

    Args:
        key: The paramiko host key object.

    Returns:
        A fingerprint string such as
        'SHA256:7f9tLuJMScst0ObcMi3DVb+Rjy/S/lR+gSSHeZq7Pds'.
    """
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def known_hosts_entry(hostname: str, port: int, key: paramiko.PKey) -> str:
    """
    Build a known_hosts line for the given host and key.

    Non-standard ports use the OpenSSH [host]:port form, matching how
    paramiko looks up keys for them.

    Args:
        hostname: The host name or IP address.
        port: The SSH port.
        key: The host key object.

    Returns:
        A single known_hosts line ending with a newline.
    """
    name = hostname if port == 22 else f"[{hostname}]:{port}"
    return f"{name} {key.get_name()} {key.get_base64()}\n"


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
