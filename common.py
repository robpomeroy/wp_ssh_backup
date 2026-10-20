"""Shared helpers for WP SSH Backup.

The implementations live in focused modules:

- :mod:`errors` -- the exception types
- :mod:`config` -- loading and validating the configuration
- :mod:`remote` -- the SSH and SFTP transport
- :mod:`remote_ops` -- remote operations shared by both flows
- :mod:`wp_config` -- parsing wp-config.php
- :mod:`db_config` -- the MySQL option file
- :mod:`naming` -- timestamps, identifiers and file names
- :mod:`checksums` -- SHA-256 checksums and manifests
- :mod:`retention` -- local backup sets and retention
- :mod:`shell` -- quoting for remote shell commands
- :mod:`host_keys` -- fingerprints and known_hosts entries

This module re-exports them, so existing imports keep working.
"""

from __future__ import annotations

from errors import (
    REMOTE_FAILURES,
    ChecksumError,
    ConfigError,
    MissingArtifactError,
    RemoteCommandError,
    UnknownHostKeyError,
    WPSSHBackupError,
)
from config import (
    Config,
    load_config,
)
from remote import (
    connect,
    read_remote_file,
    remote_path_exists,
    run_remote_cmd,
    run_remote_cmd_checked,
    sftp_download,
    write_remote_file,
)
from remote_ops import (
    allocate_remote_dir,
    create_staging_dir,
    detect_wp_cli,
    remove_remote_file,
    remove_remote_staging,
)
from wp_config import (
    parse_wp_config,
    read_wp_db_settings,
)
from db_config import (
    mysql_client_config,
    read_db_settings,
    split_db_host,
    write_mysql_client_config,
)
from naming import (
    backup_id,
    backup_id_from_archive_name,
    checksum_name,
    db_archive_name,
    files_archive_name,
    parse_backup_id,
    parse_timestamp,
    staging_dir_for,
    utc_timestamp,
)
from checksums import (
    parse_sha256sum_output,
    sha256_file,
    validate_manifest_entries,
    verify_local_checksum,
)
from retention import (
    find_backup_sets,
    prune_local_backups,
)
from shell import (
    shquote,
    trap_rm_action,
)
from host_keys import (
    fingerprint,
    known_hosts_entry,
)
from cli import (
    human_size,
    timed,
)

__all__ = [
    "REMOTE_FAILURES",
    "ChecksumError",
    "ConfigError",
    "MissingArtifactError",
    "RemoteCommandError",
    "UnknownHostKeyError",
    "WPSSHBackupError",
    "Config",
    "load_config",
    "connect",
    "read_remote_file",
    "remote_path_exists",
    "run_remote_cmd",
    "run_remote_cmd_checked",
    "sftp_download",
    "write_remote_file",
    "allocate_remote_dir",
    "create_staging_dir",
    "detect_wp_cli",
    "remove_remote_file",
    "remove_remote_staging",
    "parse_wp_config",
    "read_wp_db_settings",
    "mysql_client_config",
    "read_db_settings",
    "split_db_host",
    "write_mysql_client_config",
    "backup_id",
    "backup_id_from_archive_name",
    "checksum_name",
    "db_archive_name",
    "files_archive_name",
    "parse_backup_id",
    "parse_timestamp",
    "staging_dir_for",
    "utc_timestamp",
    "parse_sha256sum_output",
    "sha256_file",
    "validate_manifest_entries",
    "verify_local_checksum",
    "find_backup_sets",
    "prune_local_backups",
    "shquote",
    "trap_rm_action",
    "fingerprint",
    "known_hosts_entry",
    "human_size",
    "timed",
]
