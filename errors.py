"""Exception types raised by WP SSH Backup.

Every error the tool raises derives from :class:`WPSSHBackupError`,
so a caller can catch the whole family with one except clause and
still distinguish the individual failure modes when it needs to.
"""

from __future__ import annotations

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
