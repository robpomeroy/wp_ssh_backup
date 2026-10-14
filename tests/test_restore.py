"""Orchestration tests for restore.py using the fake SSH/SFTP layer."""

from __future__ import annotations

import hashlib
import posixpath
from pathlib import Path

import pytest

import restore
from common import (
    ChecksumError,
    Config,
    MissingArtifactError,
    checksum_name,
    db_archive_name,
    files_archive_name,
    staging_dir_for,
    write_remote_file,
)
from tests.fakes import FakeSSHClient

TS = "20261014T0930Z"
SITE_ROOT = "/home/user/public_html"


def make_config(tmp_path: Path, **overrides: str) -> Config:
    values = {
        "ssh_host": "example.com",
        "ssh_port": 22,
        "ssh_user": "user",
        "ssh_key_path": None,
        "ssh_password": None,
        "wp_site_root": SITE_ROOT,
        "wp_cli_path": None,
        "backup_dir": tmp_path / "backups",
        "retention_days": 30,
    }
    values.update(overrides)
    return Config(**values)


def make_local_set(
    backup_dir: Path, ts: str, wp_cli: bool = True
) -> dict[str, Path]:
    """Create a complete local backup set with valid checksums."""
    import io
    import tarfile

    backup_dir.mkdir(parents=True, exist_ok=True)
    set_files: dict[str, Path] = {}
    payloads: dict[str, bytes] = {}

    def tarball(members: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    if wp_cli:
        payloads[files_archive_name(ts)] = tarball(
            {"wp-config.php": b"<?php // site\n", "index.php": b"<?php\n"}
        )
        payloads[db_archive_name(ts)] = tarball(
            {f"wp-db-{ts}.sql": b"-- SQL dump\n"}
        )
    else:
        payloads[files_archive_name(ts)] = tarball(
            {"wp-config.php": b"<?php // site\n"}
        )
    for name, payload in payloads.items():
        path = backup_dir / name
        path.write_bytes(payload)
        (backup_dir / checksum_name(name)).write_text(
            f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
        )
        set_files[name] = path
        set_files[checksum_name(name)] = backup_dir / checksum_name(name)
    return set_files


# ---------------------------------------------------------------------------
# Set selection
# ---------------------------------------------------------------------------


def test_choose_set_latest_when_no_timestamp(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261013T0000Z")
    make_local_set(backup_dir, "20261014T0000Z")
    sets = restore.list_backup_sets(backup_dir)

    chosen = restore.choose_set(sets, None, True, True, backup_dir)

    assert restore.ts_of(chosen) == "20261014T0000Z"


def test_choose_set_explicit_timestamp(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261013T0000Z")
    make_local_set(backup_dir, "20261014T0000Z")
    sets = restore.list_backup_sets(backup_dir)

    chosen = restore.choose_set(sets, "20261013T0000Z", True, True, backup_dir)

    assert restore.ts_of(chosen) == "20261013T0000Z"


def test_choose_set_unknown_timestamp(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0000Z")
    sets = restore.list_backup_sets(backup_dir)

    with pytest.raises(MissingArtifactError, match="No backup set"):
        restore.choose_set(sets, "20200101T0000Z", True, True, backup_dir)


def test_choose_set_no_sets(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    with pytest.raises(MissingArtifactError, match="No backup sets"):
        restore.choose_set({}, None, True, True, backup_dir)


def test_choose_set_missing_db_artifact(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0000Z", wp_cli=False)
    sets = restore.list_backup_sets(backup_dir)

    with pytest.raises(MissingArtifactError, match="missing required"):
        restore.choose_set(sets, None, True, True, backup_dir)


# ---------------------------------------------------------------------------
# Full restore flow
# ---------------------------------------------------------------------------


def test_run_restore_files_round_trip(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, "20261014T1000Z")

    restore.run_restore(
        client, config, set_files, True, False, ts="20261014T1000Z"
    )

    # The files tarball's contents were extracted into the site root.
    assert (
        client.remote_fs[posixpath.join(SITE_ROOT, "wp-config.php")]
        == b"<?php // site\n"
    )
    assert (
        client.remote_fs[posixpath.join(SITE_ROOT, "index.php")]
        == b"<?php\n"
    )
    # Staging cleaned up after success.
    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_run_restore_database_round_trip(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    restore.run_restore(
        client, config, set_files, False, True, ts="20261014T1000Z"
    )

    import_commands = [c for c in client.commands if "db import" in c]
    assert len(import_commands) == 1


def test_run_restore_mysqldump_fallback_uses_cnf(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli=None)
    config = make_config(tmp_path)
    client.remote_fs[posixpath.join(SITE_ROOT, "wp-config.php")] = (
        "define( 'DB_NAME', 'wpdb' );\n"
        "define( 'DB_USER', 'u' );\n"
        "define( 'DB_PASSWORD', 'p' );\n"
        "define( 'DB_HOST', 'localhost' );\n"
    ).encode()

    restore.run_restore(
        client, config, set_files, False, True, ts="20261014T1000Z"
    )

    mysql_commands = [c for c in client.commands if "mysql " in c]
    assert len(mysql_commands) == 1
    assert "--defaults-extra-file" in mysql_commands[0]
    assert "-pp" not in mysql_commands[0]
    # Credentials file removed afterwards (staging ts differs from backup ts).
    cnf_path = posixpath.join(
        staging_dir_for(SITE_ROOT, "20261014T1000Z"), f"my-{TS}.cnf"
    )
    assert cnf_path not in client.remote_fs


def test_run_restore_checksum_failure_removes_staging(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    # Corrupt the local archive so the remote check fails.
    archive_path = set_files[files_archive_name(TS)]
    archive_path.write_bytes(b"corrupted")
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    with pytest.raises(ChecksumError):
        restore.run_restore(
            client, config, set_files, True, False, ts="20261014T1000Z"
        )

    staging = staging_dir_for(SITE_ROOT, "20261014T1000Z")
    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_write_remote_file_sets_mode_600(tmp_path: Path) -> None:
    client = FakeSSHClient(SITE_ROOT)
    write_remote_file(client.sftp, "/tmp/secret.cnf", "[client]\n", mode=0o600)
    assert client.sftp.modes["/tmp/secret.cnf"] == 0o600
