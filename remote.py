"""SSH and SFTP transport.

The transport layer: opening a connection to a trusted host,
running a command, and moving files over SFTP. Everything here
is concerned with the wire, not with what the commands mean.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import paramiko

from config import Config
from errors import (
    RemoteCommandError,
    UnknownHostKeyError,
    WPSSHBackupError,
)
from shell import shquote

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
    sftp: paramiko.SFTPClient, remote_path: str, local_path: str | Path,
    *,
    created_paths: list[tuple[Path, tuple[int, int]]] | None = None,
    downloaded_fds: dict[Path, int] | None = None,
) -> Path:
    """
    Download a file from the remote host via SFTP into local_path.

    The destination is created with O_EXCL semantics and mode 0600 before
    the transfer starts: sftp.get() writes with the process's default
    permissions, so under a permissive umask (e.g. 022) in a traversable
    BACKUP_DIR other local users could read database archives and site
    configuration while (and after) the file is downloaded. A pre-existing
    file or symlink at the destination is never followed or truncated —
    the call raises instead, so an attacker-planted link cannot redirect
    the download.

    On success the caller is handed the very descriptor this call wrote
    through, opened read/write on the inode it created, so verification
    and publication can hash and link that inode without ever re-opening
    the pathname. A writer who can modify BACKUP_DIR cannot substitute a
    self-consistent (archive, manifest) pair after the transfer: the
    replacement is a different inode, and hashing/linking the held
    descriptor (not the path) keeps the checksum and the publication
    bound to the downloaded bytes. The caller owns the returned
    descriptor and must close it (the descriptor is also recorded in
    downloaded_fds for cleanup).

    Args:
        sftp: An active SFTP client connected to the remote host.
        remote_path: The path to the file on the remote host.
        local_path: The local path where the file should be saved.
        created_paths: If supplied, records (path, (st_dev, st_ino)) of
            the destination immediately after exclusive creation,
            including when the subsequent transfer fails. Cleanup can
            then remove the path only while it still refers to the inode
            this call created, never a replacement another run planted.
        downloaded_fds: If supplied, records the open descriptor of the
            destination after a successful transfer, keyed by the local
            Path. The caller takes ownership of the descriptor and must
            close it.

    Returns:
        The local path to the downloaded file as a Path object.

    Raises:
        FileExistsError: If a file or symlink already exists at
            local_path.
    """
    local = Path(local_path)
    local.parent.mkdir(parents=True, exist_ok=True)
    # O_CREAT | O_EXCL | O_RDWR, 0600: fails if anything (including a
    # symlink, which os.open with O_EXCL never follows to its target)
    # already exists at the path, then streams into a private file. The
    # descriptor is opened read/write so the same inode can be hashed
    # and linked later without re-opening the (possibly swapped) path.
    fd = os.open(local, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if created_paths is not None:
            st = os.fstat(fd)
            created_paths.append((local, (st.st_dev, st.st_ino)))
        stream = os.fdopen(fd, "wb", closefd=False)
        try:
            sftp.getfo(remote_path, stream)
        finally:
            # Flush and detach the wrapper WITHOUT closing the raw fd;
            # closing the wrapper alone would leave the fd dangling
            # until GC, which pytest reports as an unraisable exception.
            stream.flush()
            stream.detach()
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    if downloaded_fds is not None:
        downloaded_fds[local] = fd
    else:
        os.close(fd)
    return local

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
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    remote_path: str,
    content: str | bytes,
    mode: int = 0o600,
) -> None:
    """
    Write content to a remote file via SFTP, creating or overwriting it.

    Args:
        client: An active SSH client connected to the remote host.
        sftp: An active SFTP client connected to the remote host.
        remote_path: The path on the remote host where the file should be
            written.
        content: The content to write to the file, as a string or bytes.
        mode: The file permissions to set on the remote file (default: 0o600).

    Returns:
        None.

    Note:
        paramiko's SFTP open sends an empty attribute block, so the server
        creates the file with its own default mode (typically
        0666 & ~umask, i.e. group/other readable) and a client-side umask
        cannot influence a remote server. The path is therefore recreated
        through a server-side shell command running under umask 077
        BEFORE any content is uploaded: an existing file or symlink at
        the path is removed (so the creation cannot truncate through a
        link) and a fresh owner-only regular file takes its place, so the
        secret is never readable by other host users at any point. A
        final chmod enforces the requested mode.
    """
    data = content.encode("utf-8") if isinstance(content, str) else content
    # Recreate the path server-side under umask 077 before any content
    # exists: rm -f clears a pre-existing file or symlink, and the `: >`
    # redirection then creates a fresh regular file 0600 at the instant
    # of creation. Neither a creation mode nor a client-side umask can
    # reach the server through paramiko's SFTP open.
    run_remote_cmd_checked(
        client,
        f"rm -f {shquote(remote_path)} && umask 077"
        f" && : > {shquote(remote_path)}",
    )
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
