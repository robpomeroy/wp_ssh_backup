"""Orchestration tests for backup.py using the fake SSH/SFTP layer."""

from __future__ import annotations

import posixpath
from pathlib import Path

import pytest

import backup
from common import (
    ChecksumError,
    Config,
    RemoteCommandError,
    checksum_name,
    db_archive_name,
    files_archive_name,
    parse_sha256sum_output,
    staging_dir_for,
    utc_timestamp,
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


@pytest.fixture()
def backup_dir(tmp_path: Path) -> Path:
    path = tmp_path / "backups"
    path.mkdir()
    return path


# ---------------------------------------------------------------------------
# Database dump creation
# ---------------------------------------------------------------------------


def test_create_db_dump_with_wp_cli_tars_the_dump(
    tmp_path: Path, backup_dir: Path
) -> None:
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/local/bin/wp")
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    archive = backup.create_db_dump(client, config, staging, TS)

    assert archive == db_archive_name(TS)
    assert posixpath.join(staging, archive) in client.remote_fs
    # The SQL dump must be inside the tarball, not left loose.
    loose_dump = posixpath.join(staging, f"wp-db-{TS}.sql")
    import io
    import tarfile

    with tarfile.open(
        fileobj=io.BytesIO(client.remote_fs[posixpath.join(staging, archive)]),
        mode="r:gz",
    ) as tar:
        assert tar.getmembers()[0].name == f"wp-db-{TS}.sql"
    del loose_dump


def test_create_db_dump_mysqldump_fallback_uses_cnf(
    tmp_path: Path, backup_dir: Path
) -> None:
    client = FakeSSHClient(SITE_ROOT, wp_cli=None)
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    # Provide wp-config.php with DB credentials via SFTP.
    client.remote_fs[posixpath.join(SITE_ROOT, "wp-config.php")] = (
        "define( 'DB_NAME', 'wpdb' );\n"
        "define( 'DB_USER', 'dbuser' );\n"
        "define( 'DB_PASSWORD', 'dbpass' );\n"
        "define( 'DB_HOST', 'localhost' );\n"
    ).encode()

    archive = backup.create_db_dump(client, config, staging, TS)

    assert archive == db_archive_name(TS)
    # The credentials file must have been removed after the dump.
    cnf_path = posixpath.join(staging, f"my-{TS}.cnf")
    assert cnf_path not in client.remote_fs
    # The dump command used --defaults-extra-file, never -p<password>.
    dump_commands = [c for c in client.commands if "mysqldump" in c]
    assert len(dump_commands) == 1
    assert "--defaults-extra-file" in dump_commands[0]
    assert "-pdbpass" not in dump_commands[0]
    assert "-p dbpass" not in dump_commands[0]


def test_create_db_dump_mysqldump_failure_removes_cnf(
    tmp_path: Path, backup_dir: Path
) -> None:
    client = FakeSSHClient(SITE_ROOT, wp_cli=None)
    client.fail_on["mysqldump"] = 1
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)
    client.remote_fs[posixpath.join(SITE_ROOT, "wp-config.php")] = (
        "define( 'DB_NAME', 'wpdb' );\n"
        "define( 'DB_USER', 'u' );\n"
        "define( 'DB_PASSWORD', 'p' );\n"
        "define( 'DB_HOST', 'localhost' );\n"
    ).encode()

    with pytest.raises(RemoteCommandError):
        backup.create_db_dump(client, config, staging, TS)

    cnf_path = posixpath.join(staging, f"my-{TS}.cnf")
    assert cnf_path not in client.remote_fs


# ---------------------------------------------------------------------------
# Files archive creation
# ---------------------------------------------------------------------------


def test_create_files_archive_excludes_cache(
    tmp_path: Path, backup_dir: Path
) -> None:
    client = FakeSSHClient(SITE_ROOT)
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    archive = backup.create_files_archive(client, config, staging, TS)

    assert archive == files_archive_name(TS)
    tar_command = next(c for c in client.commands if c.startswith("tar czf"))
    assert "--exclude=./wp-content/cache" in tar_command


# ---------------------------------------------------------------------------
# Full backup flow
# ---------------------------------------------------------------------------


def test_run_backup_files_only_round_trip(
    tmp_path: Path, backup_dir: Path
) -> None:
    client = FakeSSHClient(SITE_ROOT)
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    local_paths = backup.run_backup(
        client, config, include_files=True, include_database=False, ts=TS
    )

    archive = files_archive_name(TS)
    local_archive = backup_dir / archive
    local_checksum = backup_dir / checksum_name(archive)
    assert local_archive.is_file()
    assert local_checksum.is_file()
    # The downloaded checksum file describes the downloaded archive.
    digest = parse_sha256sum_output(local_checksum.read_text())[archive]
    from common import sha256_file

    assert sha256_file(local_archive) == digest
    # Staging dir removed after success.
    assert not any(path.startswith(staging) for path in client.remote_fs)
    assert local_paths[archive] == local_archive


def test_run_backup_database_only_round_trip(
    tmp_path: Path, backup_dir: Path
) -> None:
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    local_paths = backup.run_backup(
        client, config, include_files=False, include_database=True, ts=TS
    )

    archive = db_archive_name(TS)
    assert (backup_dir / archive).is_file()
    assert (backup_dir / checksum_name(archive)).is_file()
    assert local_paths[archive] == backup_dir / archive


def test_run_backup_all_creates_both_archives(
    tmp_path: Path, backup_dir: Path
) -> None:
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    local_paths = backup.run_backup(
        client, config, include_files=True, include_database=True, ts=TS
    )

    assert files_archive_name(TS) in local_paths
    assert db_archive_name(TS) in local_paths


def test_run_backup_checksum_mismatch_keeps_staging(
    tmp_path: Path, backup_dir: Path
) -> None:
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    # Corrupt the tarball after checksum generation but before download.
    original_get = client.sftp.get

    def corrupting_get(remote_path: str, local_path: str) -> None:
        original_get(remote_path, local_path)
        if remote_path.endswith(".tar.gz"):
            Path(local_path).write_bytes(b"corrupted")

    client.sftp.get = corrupting_get  # type: ignore[method-assign]
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    with pytest.raises(ChecksumError):
        backup.run_backup(
            client, config, include_files=True, include_database=False, ts=TS
        )

    # Remote staging must be kept for retry.
    assert any(path.startswith(staging) for path in client.remote_fs)


def test_run_backup_remote_failure_removes_staging(
    tmp_path: Path, backup_dir: Path
) -> None:
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    client.fail_on["tar czf"] = 1
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    with pytest.raises(RemoteCommandError):
        backup.run_backup(
            client, config, include_files=True, include_database=False, ts=TS
        )

    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_run_backup_uses_provided_timestamp(
    tmp_path: Path, backup_dir: Path
) -> None:
    client = FakeSSHClient(SITE_ROOT)
    config = make_config(tmp_path)
    ts = utc_timestamp()
    backup.run_backup(client, config, True, False, ts)
    assert files_archive_name(ts) in [p.name for p in backup_dir.iterdir()]
