"""Authorise a WordPress host's SSH key before using WP SSH Backup.

Fetches the server's public host key (no credentials are sent), displays its
SHA-256 fingerprint for out-of-band verification, and — after explicit
confirmation — appends it to a known_hosts file that backup.py and restore.py
will trust.

Usage:
    python authorize_host.py                 # interactive
    python authorize_host.py --fingerprint SHA256:...   # non-interactive pin
    python authorize_host.py --show          # display fingerprint only
"""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

import paramiko

from common import (
    Config,
    WPSSHBackupError,
    fingerprint,
    known_hosts_entry,
    load_config,
)


def fetch_host_key(config: Config) -> paramiko.PKey:
    """
    Connect to the bare SSH transport and return the server's host key.

    No username, password or key file is supplied: the handshake completes
    before authentication would begin, so nothing secret is transmitted and
    the server cannot learn anything about the caller beyond its IP.

    The TCP connection itself is opened with an explicit socket timeout:
    constructing Transport from an address would connect without one and
    could block for the OS socket timeout before the handshake timer even
    starts.

    Args:
        config: The configuration object with SSH host/port details.

    Returns:
        The server's public host key.

    Raises:
        WPSSHBackupError: If the transport cannot be established.
    """
    sock: socket.socket | None = None
    transport: paramiko.Transport | None = None
    try:
        # Bound the TCP connect explicitly; Transport(addr) would connect
        # with no timeout and could hang for the OS default.
        sock = socket.create_connection(
            (config.ssh_host, config.ssh_port), timeout=30
        )
        sock.settimeout(None)
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=30)
            return transport.get_remote_server_key()
        finally:
            transport.close()
    except (paramiko.SSHException, OSError) as exc:
        raise WPSSHBackupError(
            f"Could not reach {config.ssh_host}:{config.ssh_port} to fetch "
            f"its host key: {exc}"
        ) from exc
    finally:
        if transport is not None:
            transport.close()
        if sock is not None:
            sock.close()


def is_host_trusted(
    known_hosts_path: Path,
    hostname: str,
    port: int,
    key: paramiko.PKey,
) -> bool:
    """
    True if known_hosts already trusts this host/port with this key.

    The fingerprint alone is not enough: the same key may be recorded
    under a different host name or port, and skipping the append in that
    case would leave the configured host untrusted (connect() would then
    reject it). Both the host/port entry and the key must match.

    Args:
        known_hosts_path: Path to the known_hosts file (may not exist).
        hostname: The host name or IP address.
        port: The SSH port.
        key: The server's host key.

    Returns:
        True if an entry for this host/port exists whose key matches.
    """
    if not known_hosts_path.is_file():
        return False
    # Reuse known_hosts_entry's naming ([host]:port for non-standard
    # ports) so the lookup key cannot drift from what we write.
    name = known_hosts_entry(hostname, port, key).split(" ", 1)[0]
    # HostKeys.lookup resolves OpenSSH hashed hostnames ('|1|...' entries)
    # as well as plaintext ones, so an already-trusted hashed entry is
    # recognised instead of being duplicated as a new plaintext line that
    # would expose the host name the user chose to hash.
    host_keys = paramiko.HostKeys(str(known_hosts_path))
    matching = host_keys.lookup(name)
    if not matching:
        return False
    return any(
        fingerprint(pkey) == fingerprint(key) for pkey in matching.values()
    )


def append_to_known_hosts(
    known_hosts_path: Path, hostname: str, port: int, key: paramiko.PKey
) -> None:
    """
    Append a host key entry to a known_hosts file, creating it if needed.

    Args:
        known_hosts_path: Path to the known_hosts file.
        hostname: The host name or IP address.
        port: The SSH port.
        key: The server's host key.
    """
    known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
    with open(known_hosts_path, "a", encoding="utf-8") as handle:
        handle.write(known_hosts_entry(hostname, port, key))


def confirm_interactive(fp: str, hostname: str, port: int) -> bool:
    """
    Ask the user to confirm a fingerprint interactively.

    Args:
        fp: The fingerprint string to display.
        hostname: The host name being authorised.
        port: The SSH port.

    Returns:
        True if the user typed an affirmative answer.
    """
    print()
    print(f"The fingerprint of {hostname}:{port} is:")
    print(f"    {fp}")
    print()
    print(
        "Verify this against a trusted source — e.g. your hosting control "
        "panel, or the output of this command run on the server itself:"
    )
    print("    ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")
    print()
    answer = input("Trust this host key? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Authorise a WordPress host's SSH key for WP SSH Backup. "
            "Fetches the host key (no credentials sent), shows its "
            "fingerprint and records it in a known_hosts file."
        )
    )
    parser.add_argument(
        "--fingerprint",
        help=(
            "Expected fingerprint (SHA256:...). When given, no interactive "
            "prompt is shown and the fetched key must match exactly."
        ),
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Display the fingerprint and exit without saving.",
    )
    args = parser.parse_args(argv)

    try:
        config = load_config()
    except WPSSHBackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    known_hosts_path = (
        Path(config.ssh_known_hosts).expanduser()
        if config.ssh_known_hosts
        else Path.home() / ".ssh" / "known_hosts"
    )

    try:
        key = fetch_host_key(config)
    except WPSSHBackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    fp = fingerprint(key)

    if args.show:
        print(f"{config.ssh_host}:{config.ssh_port} {key.get_name()} {fp}")
        return 0

    if args.fingerprint:
        if args.fingerprint != fp:
            print(
                f"ERROR: fingerprint mismatch for {config.ssh_host}:"
                f"{config.ssh_port}.\n"
                f"  expected: {args.fingerprint}\n"
                f"  actual:   {fp}\n"
                "The host key does not match. Do NOT proceed; investigate "
                "before trusting this host.",
                file=sys.stderr,
            )
            return 1
        print(f"Fingerprint matches: {fp}")
    else:
        if not confirm_interactive(fp, config.ssh_host, config.ssh_port):
            print("Aborted; nothing was saved.")
            return 1

    if is_host_trusted(
        known_hosts_path, config.ssh_host, config.ssh_port, key
    ):
        print(f"Already trusted in {known_hosts_path}; nothing to do.")
        return 0

    append_to_known_hosts(
        known_hosts_path, config.ssh_host, config.ssh_port, key
    )
    print(f"Host key saved to {known_hosts_path}.")
    print("backup.py and restore.py will now trust this host.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
