"""Loading and validation of the tool's configuration.

The configuration is read from a .env file and the process
environment, validated, and frozen into a :class:`Config` value
object. Nothing else in the tool reads the environment directly.
"""

from __future__ import annotations

import os
import posixpath
import sys
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from errors import ConfigError

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


def _is_frozen() -> bool:
    """Return whether the program is running as a bundled executable.

    PyInstaller sets sys.frozen in the bundle it unpacks, so it is
    true for a frozen binary and absent when the script is run from a
    checkout.

    Returns:
        True if the program is a frozen executable, False otherwise.
    """
    return bool(getattr(sys, "frozen", False))


def _find_env_file() -> Path:
    """Locate the .env file to read.

    The current directory is searched first, so running the tool from
    the directory holding the configuration always works.

    A frozen build (PyInstaller) is different: the bundle unpacks into
    a temporary directory, so the module's own __file__ points into
    that temporary directory and never at the user's files. The
    directory holding the executable is searched instead, so a copy of
    the program placed next to its .env finds it.

    Args:
        None.

    Returns:
        The path of the .env file to read. The path is not guaranteed
        to exist; the caller reports the error, and the error names
        the path that was searched so the user knows where to put the
        file.
    """
    cwd_env = Path.cwd() / ".env"
    if cwd_env.is_file():
        return cwd_env
    if _is_frozen():
        # sys.executable is the executable the user ran, so its
        # directory is where the program was placed.
        exe_env = Path(sys.executable).resolve().parent / ".env"
        if exe_env.is_file():
            return exe_env
        # Nothing found: report the path next to the executable, since
        # that is where the user would put it.
        return exe_env
    return Path(__file__).resolve().parent / ".env"


def load_config(env_file: str | os.PathLike | None = None) -> Config:
    """
    Load and validate configuration from a .env file.

    Real environment variables take precedence over .env values (standard
    python-dotenv behaviour).

    Args:
        env_file: Path to the .env file. If None, the function will attempt to
            locate an .env file in the current working directory, then next to
            the program (the script's directory when run from source, the
            executable's directory when run as a frozen binary).

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
            if _is_frozen():
                # A frozen binary is a single file the user
                # downloaded, so the .env belongs beside it. Saying
                # only "no .env file found" would leave the user
                # hunting for the place the file is expected.
                raise ConfigError(
                    "No .env file found. A standalone executable reads "
                    "its configuration from a .env file beside the "
                    f"executable: {env_path}\n"
                    "Copy .env.example to that location and fill in your "
                    "SSH and WordPress settings."
                )
            raise ConfigError(
                f"No .env file found at {env_path}. Copy .env.example to "
                "that location and fill in your SSH and WordPress "
                "settings."
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
    # Normalise "." and ".." components (e.g. /home/user/public_html/.
    # or /home/user/../user/public_html) BEFORE the root check and before
    # storing the value: staging_dir_for() places the staging directory
    # next to the *string* passed here, so an unnormalised path such as
    # '/x/.' yields /staging-dir — the PARENT of the real site root —
    # or, for '/x/./.', staging inside the real root, where a files
    # backup would archive its own growing tarball and the staged
    # database dump.
    site_root = posixpath.normpath(site_root)
    # POSIX leaves exactly two leading slashes ('//') untouched; treat
    # the result as root if nothing remains after stripping them.
    if site_root.rstrip("/") == "":
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
        wp_site_root=site_root,
        wp_cli_path=os.getenv("WP_CLI_PATH", "").strip() or None,
        backup_dir=Path(os.getenv("BACKUP_DIR", "").strip()).expanduser(),
        retention_days=_get_int("RETENTION_DAYS", 30, minimum=0),
    )
