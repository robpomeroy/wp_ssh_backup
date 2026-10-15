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
    backup_id,
    checksum_name,
    db_archive_name,
    files_archive_name,
    parse_sha256sum_output,
    staging_dir_for,
    WPSSHBackupError,
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
        "ssh_known_hosts": None,
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


def test_create_db_dump_site_path_with_spaces(
    tmp_path: Path, backup_dir: Path
) -> None:
    """Regression: a spaced site path must not break the trap action."""
    spaced_root = "/home/user/my site/public_html"
    client = FakeSSHClient(spaced_root, wp_cli=None)
    config = make_config(tmp_path, wp_site_root=spaced_root)
    staging = staging_dir_for(spaced_root, TS)
    client.remote_fs[posixpath.join(spaced_root, "wp-config.php")] = (
        "define( 'DB_NAME', 'wpdb' );\n"
        "define( 'DB_USER', 'u' );\n"
        "define( 'DB_PASSWORD', 'p' );\n"
        "define( 'DB_HOST', 'localhost' );\n"
    ).encode()

    archive = backup.create_db_dump(client, config, staging, TS)

    # The dump was produced and tarred despite the space in the path.
    assert archive == db_archive_name(TS)
    assert posixpath.join(staging, archive) in client.remote_fs
    # The trap action reached the shell as ONE argument containing the
    # quoted path, not as several broken arguments.
    trap_commands = [c for c in client.commands if "trap" in c]
    assert len(trap_commands) == 1
    action = trap_commands[0].split("trap ", 1)[1].split(" EXIT")[0]
    import shlex

    words = shlex.split(f"trap {action} EXIT")
    assert len(words) == 3
    assert words[0] == "trap" and words[2] == "EXIT"
    # Re-evaluating the action yields rm with the spaced path as one arg.
    rm_words = shlex.split(words[1])
    assert rm_words == [
        "rm",
        "-f",
        posixpath.join(staging, f"my-{TS}.cnf"),
    ]
    # The credentials file was cleaned up.
    cnf_path = posixpath.join(staging, f"my-{TS}.cnf")
    assert cnf_path not in client.remote_fs


# ---------------------------------------------------------------------------
# Files archive creation
# ---------------------------------------------------------------------------


def test_create_files_archive_excludes_cache(
    tmp_path: Path, backup_dir: Path
) -> None:
    """The cache exclusion must actually keep cache files out of the tar."""
    client = FakeSSHClient(SITE_ROOT)
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)
    # Seed the fake remote FS with a cache file that must be excluded.
    client.remote_fs[posixpath.join(SITE_ROOT, "wp-content/cache/junk.js")] = (
        b"cached"
    )
    client.remote_fs[posixpath.join(SITE_ROOT, "index.php")] = b"<?php\n"

    archive = backup.create_files_archive(client, config, staging, TS)

    assert archive == files_archive_name(TS)
    tar_command = next(c for c in client.commands if c.startswith("tar czf"))
    assert "--exclude=./wp-content/cache" in tar_command
    # GNU tar treats options after the member operand as positional: they
    # have no effect and it exits with status 2. The exclude must come
    # before the "." member.
    assert tar_command.rstrip().endswith(" .")
    assert tar_command.index("--exclude=") < tar_command.rindex(" .")
    # The fake tar honours --exclude, so verify the archive contents.
    import io
    import tarfile

    with tarfile.open(
        fileobj=io.BytesIO(client.remote_fs[posixpath.join(staging, archive)]),
        mode="r:gz",
    ) as tar:
        names = tar.getnames()
    assert "index.php" in names
    assert not any("wp-content/cache" in name for name in names)


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
        client, config, include_files=True, include_database=False, bid=TS
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
    # The staging directory was restricted to the owner (0700) so other
    # host users cannot reach the archives or credentials inside it.
    assert client.directory_modes[staging] == 0o700


def test_run_backup_database_only_round_trip(
    tmp_path: Path, backup_dir: Path
) -> None:
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    local_paths = backup.run_backup(
        client, config, include_files=False, include_database=True, bid=TS
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
        client, config, include_files=True, include_database=True, bid=TS
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
            client, config, include_files=True, include_database=False, bid=TS
        )

    # Remote staging must be kept for retry.
    assert any(path.startswith(staging) for path in client.remote_fs)


def test_verify_downloads_undecodable_manifest_raises_checksum_error(
    tmp_path: Path,
) -> None:
    """An invalid-UTF-8 manifest must raise ChecksumError, not crash."""
    archive = files_archive_name(TS)
    archive_path = tmp_path / archive
    archive_path.write_bytes(b"payload")
    checksum_path = tmp_path / checksum_name(archive)
    checksum_path.write_bytes(b"\xff\xfe\x00invalid-utf8")

    with pytest.raises(ChecksumError, match="not valid UTF-8"):
        backup.verify_downloads(
            {
                archive: archive_path,
                checksum_name(archive): checksum_path,
            },
            [archive],
        )


def test_run_backup_undecodable_manifest_keeps_staging(
    tmp_path: Path, backup_dir: Path
) -> None:
    """An undecodable manifest must keep staging for retry, like a mismatch."""
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    original_get = client.sftp.get

    def corrupting_get(remote_path: str, local_path: str) -> None:
        original_get(remote_path, local_path)
        if remote_path.endswith(".sha256"):
            Path(local_path).write_bytes(b"\xff\xfe\x00invalid-utf8")

    client.sftp.get = corrupting_get  # type: ignore[method-assign]
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    with pytest.raises(ChecksumError, match="not valid UTF-8"):
        backup.run_backup(
            client, config, include_files=True, include_database=False, bid=TS
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
            client, config, include_files=True, include_database=False, bid=TS
        )

    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_run_backup_invalid_wp_cli_path_removes_staging(
    tmp_path: Path, backup_dir: Path
) -> None:
    """A base WPSSHBackupError (bad WP_CLI_PATH) must not leak staging."""
    client = FakeSSHClient(SITE_ROOT, wp_cli=None)
    config = make_config(tmp_path, wp_cli_path="/nonexistent/wp")
    staging = staging_dir_for(SITE_ROOT, TS)

    with pytest.raises(WPSSHBackupError, match="WP_CLI_PATH"):
        backup.run_backup(
            client, config, include_files=False, include_database=True, bid=TS
        )

    assert staging not in client.directories
    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_run_backup_uses_provided_backup_id(
    tmp_path: Path, backup_dir: Path
) -> None:
    client = FakeSSHClient(SITE_ROOT)
    config = make_config(tmp_path)
    bid = backup_id()
    backup.run_backup(client, config, True, False, bid)
    assert files_archive_name(bid) in [p.name for p in backup_dir.iterdir()]


def test_run_backup_staging_dir_is_exclusive(
    tmp_path: Path, backup_dir: Path
) -> None:
    """A second run with the same id must fail, not share the staging dir."""
    client = FakeSSHClient(SITE_ROOT)
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    backup.run_backup(client, config, True, False, TS)
    # The fake's bare mkdir now fails on an existing directory; simulate a
    # second run that somehow derived the same staging dir.
    client.directories.add(staging)

    with pytest.raises(Exception, match="Could not create staging"):
        backup.run_backup(client, config, True, False, TS)


def test_main_reports_sftp_failure_as_error(
    tmp_path: Path,
    backup_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """An SFTP failure must print ERROR: and exit 1, not a traceback."""
    import paramiko

    client = FakeSSHClient(SITE_ROOT)
    config = make_config(tmp_path)

    def failing_open_sftp() -> object:
        raise paramiko.SSHException("SFTP subsystem failed")

    client.open_sftp = failing_open_sftp  # type: ignore[method-assign]
    monkeypatch.setattr(backup, "load_config", lambda: config)
    monkeypatch.setattr(backup, "connect", lambda cfg: client)
    monkeypatch.setattr(
        backup, "backup_id", lambda now=None: TS
    )

    exit_code = backup.main([])

    assert exit_code == 1
    err = capsys.readouterr().err
    assert err.startswith("ERROR: ")
    assert "SFTP subsystem failed" in err
