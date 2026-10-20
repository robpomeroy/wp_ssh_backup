"""Remote operations that the backup and restore flows share.

These build on the transport layer: they create and remove
remote directories, locate the wp CLI, and clean up after a
run whether it succeeded or failed.
"""

from __future__ import annotations

import posixpath
import sys

import paramiko

from config import Config
from errors import WPSSHBackupError
from naming import backup_id, staging_dir_for
from remote import run_remote_cmd, run_remote_cmd_checked
from shell import shquote

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

def _best_effort_rm(


    client: paramiko.SSHClient,
    path: str,
    command: str,
    description: str,
) -> None:
    """Remove a remote path, reporting a failure as a warning.

    Transport failures (a dropped SSH connection raises OSError or
    paramiko.SSHException) are caught as well as command failures, so a
    cleanup problem can never replace the original error that triggered
    the cleanup; it is reported as a warning instead.

    Args:
        client: An active Paramiko SSHClient connected to the remote host.
        path: The path being removed.
        command: The shell command that performs the removal.
        description: How the path is described in the warning message.
    """
    try:
        run_remote_cmd_checked(client, command)
    except (WPSSHBackupError, OSError, paramiko.SSHException) as exc:
        print(
            f"WARNING: could not remove remote {description} {path}: {exc}",
            file=sys.stderr,
        )



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
    _best_effort_rm(
        client, staging, f"rm -rf {shquote(staging)}", "staging directory"
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
    _best_effort_rm(client, path, f"rm -f {shquote(path)}", "file")


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
        # -m 700 creates the directory with owner-only permissions in the
        # mkdir itself: under a permissive umask (e.g. 0002) a bare mkdir
        # would leave it group/world-writable until any later chmod, and
        # another account could plant files inside it.
        code, _, err = run_remote_cmd(
            client, f"mkdir -m 700 {shquote(candidate)}"
        )
        if code == 0:
            return candidate


        last_error = err.strip()
    raise WPSSHBackupError(
        f"Could not allocate an exclusive remote directory under {parent} "
        f"with prefix {prefix!r}: {last_error or 'target already exists'}"
    )

def create_staging_dir(
    client: paramiko.SSHClient,
    site_root: str,
    bid: str,
) -> str:
    """
    Create this run's exclusive remote staging directory.

    Uses a bare mkdir (no -p) so the command fails if the directory
    already exists: two concurrent runs in the same minute have
    different backup ids and therefore different directories, and a
    collision (astronomically unlikely) aborts instead of sharing
    artifacts.

    The directory is created with -m 700 so a permissive umask (e.g. a
    shared-group 0002) never leaves it writable by other accounts between
    creation and the later 0700 chmod.

    The 0700 chmod is issued separately by the caller (inside its
    cleanup scope): mkdir and chmod chained with && would leave an
    orphaned directory on the host if mkdir succeeded but chmod failed,
    before the caller's cleanup block was entered.

    Args:
        client: An active SSH client connected to the remote host.
        site_root: The WordPress site root the staging directory is a
            sibling of.
        bid: This run's backup identifier.

    Returns:
        The staging directory path.

    Raises:
        WPSSHBackupError: If the staging directory already exists.
    """
    staging = staging_dir_for(site_root, bid)
    code, _, err = run_remote_cmd(
        client, f"mkdir -m 700 {shquote(staging)}"
    )
    if code != 0:
        raise WPSSHBackupError(
            f"Could not create staging directory {staging}: "
            f"{err.strip() or 'already exists?'}"
        )
    return staging
