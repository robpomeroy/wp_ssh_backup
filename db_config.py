"""The MySQL option file that carries the database credentials.

The password never appears on a command line: it is written to
an owner-only option file that mysqldump and mysql read through
--defaults-extra-file.
"""

from __future__ import annotations

import posixpath

import paramiko

from errors import ConfigError
from remote import write_remote_file
from wp_config import read_wp_db_settings

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

    Raises:
        ConfigError: If any option value contains a line break or other
            control character, which would corrupt the option file.
    """

    def escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def check(value: str, option: str) -> str:
        if any(ord(ch) < 0x20 or ch == "\x7f" for ch in value):
            raise ConfigError(
                f"wp-config.php DB_{option} contains a line break or "
                "control character; it cannot be written to a MySQL "
                "option file."
            )
        return value

    check(host, "HOST")
    check(user, "USER")
    check(password, "PASSWORD")
    if port:
        check(port, "PORT")
    if socket:
        check(socket, "HOST")
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
# Database credentials on the remote host
# ---------------------------------------------------------------------------



def read_db_settings(
    client: paramiko.SSHClient,
    site_root: str,
) -> dict[str, str]:
    """Read the database settings from the site's wp-config.php.

    Args:
        client: An active SSH client connected to the remote host.
        site_root: The WordPress site root.

    Returns:
        The DB_HOST, DB_USER, DB_PASSWORD and DB_NAME values.
    """
    sftp = client.open_sftp()
    try:
        return read_wp_db_settings(sftp, site_root)
    finally:
        sftp.close()

def write_mysql_client_config(
    client: paramiko.SSHClient,
    site_root: str,
    staging: str,
    ts: str,
) -> tuple[str, str]:
    """Write a temporary MySQL option file into the staging directory.

    The credentials never appear on a remote command line: they are
    written to an owner-only option file that both mysqldump and mysql
    read through --defaults-extra-file. The file is created under
    umask 077, so it is never readable by another host user even
    briefly.

    The caller is responsible for removing the file (see
    :func:`remove_remote_file`); the returned path is the one to remove.

    Args:
        client: An active SSH client connected to the remote host.
        site_root: The WordPress site root, read for the settings.
        staging: The remote staging directory to write the file into.
        ts: The backup identifier the file name is derived from.

    Returns:
        A tuple of (the option file's path, the database name).
    """
    settings = read_db_settings(client, site_root)
    host, port, socket_path = split_db_host(settings["DB_HOST"])
    cnf_name = f"my-{ts}.cnf"
    cnf_path = posixpath.join(staging, cnf_name)
    cnf_body = mysql_client_config(
        host=host,
        user=settings["DB_USER"],
        password=settings["DB_PASSWORD"],
        port=port,
        socket=socket_path,
    )
    sftp = client.open_sftp()
    try:
        write_remote_file(client, sftp, cnf_path, cnf_body, mode=0o600)
    finally:
        sftp.close()
    return cnf_path, settings["DB_NAME"]
