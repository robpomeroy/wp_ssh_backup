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
    WPSSHBackupError,
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
        "ssh_known_hosts": None,
        "wp_site_root": SITE_ROOT,
        "wp_cli_path": None,
        "backup_dir": tmp_path / "backups",
        "retention_days": 30,
    }
    values.update(overrides)
    return Config(**values)


def make_local_set(
    backup_dir: Path,
    ts: str,
    kinds: tuple[str, ...] = ("files", "db"),
) -> dict[str, Path]:
    """Create a local backup set with valid checksums for the given kinds."""
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

    if "files" in kinds:
        payloads[files_archive_name(ts)] = tarball(
            {"wp-config.php": b"<?php // site\n", "index.php": b"<?php\n"}
        )
    if "db" in kinds:
        payloads[db_archive_name(ts)] = tarball(
            {f"wp-db-{ts}.sql": b"-- SQL dump\n"}
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


def test_choose_set_ignores_newer_checksum_only_group(
    tmp_path: Path,
) -> None:
    """An orphaned .sha256 group must not block a valid older set."""
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261013T0000Z")
    # A newer checksum-only group: no archives, just orphaned checksums.
    (backup_dir / "wp-db-20261014T0930Z.tar.gz.sha256").write_text("d  f\n")
    (backup_dir / "wp-files-20261014T0930Z.tar.gz.sha256").write_text("d  f\n")
    sets = restore.list_backup_sets(backup_dir)

    chosen = restore.choose_set(sets, None, True, True, backup_dir)

    assert restore.ts_of(chosen) == "20261013T0000Z"


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
    make_local_set(backup_dir, "20261014T0000Z", kinds=("files",))
    sets = restore.list_backup_sets(backup_dir)

    with pytest.raises(MissingArtifactError, match="missing required"):
        restore.choose_set(sets, "20261014T0000Z", False, True, backup_dir)


def test_choose_set_files_skips_newer_db_only_set(tmp_path: Path) -> None:
    """Regression: a newer db-only set must not block a files restore."""
    backup_dir = tmp_path / "backups"
    # Newer set: database only (the documented split schedules produce this).
    make_local_set(backup_dir, "20261014T0900Z", kinds=("db",))
    # Older set: files only.
    make_local_set(backup_dir, "20261013T0000Z", kinds=("files",))
    sets = restore.list_backup_sets(backup_dir)

    chosen = restore.choose_set(sets, None, True, False, backup_dir)

    assert restore.ts_of(chosen) == "20261013T0000Z"


def test_choose_set_database_skips_newer_files_only_set(
    tmp_path: Path,
) -> None:
    backup_dir = tmp_path / "backups"
    # Newer set: files only.
    make_local_set(backup_dir, "20261014T0900Z", kinds=("files",))
    # Older set: database only.
    make_local_set(backup_dir, "20261013T0000Z", kinds=("db",))
    sets = restore.list_backup_sets(backup_dir)

    chosen = restore.choose_set(sets, None, False, True, backup_dir)

    assert restore.ts_of(chosen) == "20261013T0000Z"


def test_choose_set_latest_matching_when_both_kinds_exist(
    tmp_path: Path,
) -> None:
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261012T0000Z")
    make_local_set(backup_dir, "20261013T0000Z", kinds=("files",))
    make_local_set(backup_dir, "20261014T0000Z")  # complete, newest
    sets = restore.list_backup_sets(backup_dir)

    chosen = restore.choose_set(sets, None, True, True, backup_dir)

    assert restore.ts_of(chosen) == "20261014T0000Z"


def test_choose_set_no_matching_candidates(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0000Z", kinds=("files",))
    sets = restore.list_backup_sets(backup_dir)

    with pytest.raises(MissingArtifactError, match="No backup set contains"):
        restore.choose_set(sets, None, False, True, backup_dir)


def test_choose_set_explicit_timestamp_stays_strict(tmp_path: Path) -> None:
    """An explicit timestamp must not fall back to an older complete set."""
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0900Z", kinds=("files",))
    make_local_set(backup_dir, "20261013T0000Z")  # complete, older
    sets = restore.list_backup_sets(backup_dir)

    with pytest.raises(MissingArtifactError, match="missing required"):
        restore.choose_set(sets, "20261014T0900Z", False, True, backup_dir)


# ---------------------------------------------------------------------------
# Timestamp resolution (full backup id or bare timestamp)
# ---------------------------------------------------------------------------


def test_resolve_timestamp_accepts_full_backup_id(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0930Z-a1b2c3")
    sets = restore.list_backup_sets(backup_dir)

    assert (
        restore.resolve_timestamp(sets, "20261014T0930Z-a1b2c3")
        == "20261014T0930Z-a1b2c3"
    )


def test_choose_set_with_full_backup_id(tmp_path: Path) -> None:
    """Regression: the documented bare form must not be the only option."""
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0930Z-a1b2c3")
    sets = restore.list_backup_sets(backup_dir)

    chosen = restore.choose_set(
        sets, "20261014T0930Z-a1b2c3", True, True, backup_dir
    )

    assert restore.ts_of(chosen) == "20261014T0930Z-a1b2c3"


def test_choose_set_with_bare_timestamp(tmp_path: Path) -> None:
    """A bare timestamp resolves when exactly one set matches the minute."""
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0930Z-a1b2c3")
    make_local_set(backup_dir, "20261013T0000Z")
    sets = restore.list_backup_sets(backup_dir)

    chosen = restore.choose_set(sets, "20261014T0930Z", True, True, backup_dir)

    assert restore.ts_of(chosen) == "20261014T0930Z-a1b2c3"


def test_choose_set_with_bare_timestamp_legacy_set(tmp_path: Path) -> None:
    """Bare timestamps also resolve legacy sets without a suffix."""
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0930Z")
    sets = restore.list_backup_sets(backup_dir)

    chosen = restore.choose_set(sets, "20261014T0930Z", True, True, backup_dir)

    assert restore.ts_of(chosen) == "20261014T0930Z"


def test_resolve_timestamp_ambiguous_minute_lists_ids(
    tmp_path: Path,
) -> None:
    """Several sets in one minute must be rejected with their full ids."""
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0930Z-a1b2c3")
    make_local_set(backup_dir, "20261014T0930Z-9f8e7d")
    sets = restore.list_backup_sets(backup_dir)

    with pytest.raises(MissingArtifactError) as excinfo:
        restore.choose_set(sets, "20261014T0930Z", True, True, backup_dir)

    message = str(excinfo.value)
    assert "Several backup sets share the timestamp" in message
    assert "20261014T0930Z-a1b2c3" in message
    assert "20261014T0930Z-9f8e7d" in message


def test_resolve_timestamp_unknown_value(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0930Z-a1b2c3")
    sets = restore.list_backup_sets(backup_dir)

    with pytest.raises(MissingArtifactError, match="No backup set"):
        restore.choose_set(sets, "20200101T0000Z", True, True, backup_dir)


# ---------------------------------------------------------------------------
# Default (no --timestamp) selection with same-minute sets
# ---------------------------------------------------------------------------


def test_latest_set_picks_newer_minute(tmp_path: Path) -> None:
    """Sets in different minutes resolve by timestamp as before."""
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0930Z-a1b2c3")
    make_local_set(backup_dir, "20261014T0931Z-b2c3d4")
    sets = restore.list_backup_sets(backup_dir)

    chosen = restore.choose_set(sets, None, True, True, backup_dir)

    assert restore.ts_of(chosen) == "20261014T0931Z-b2c3d4"


def test_latest_set_rejects_same_minute_ambiguity(tmp_path: Path) -> None:
    """Two complete sets in one minute must not be resolved by suffix."""
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0930Z-ffffff")  # sorts "latest"
    make_local_set(backup_dir, "20261014T0930Z-000000")
    sets = restore.list_backup_sets(backup_dir)

    with pytest.raises(MissingArtifactError) as excinfo:
        restore.choose_set(sets, None, True, True, backup_dir)

    message = str(excinfo.value)
    assert "share the newest timestamp" in message
    assert "20261014T0930Z-ffffff" in message
    assert "20261014T0930Z-000000" in message
    assert "Specify a full backup id" in message


def test_latest_set_ignores_older_incomplete_set(tmp_path: Path) -> None:
    """An older same-minute set missing artifacts does not block choice."""
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0930Z-000000", kinds=("files",))
    make_local_set(backup_dir, "20261014T0930Z-ffffff")
    sets = restore.list_backup_sets(backup_dir)

    chosen = restore.choose_set(sets, None, True, True, backup_dir)

    assert restore.ts_of(chosen) == "20261014T0930Z-ffffff"


def test_latest_set_ambiguity_only_among_candidates(
    tmp_path: Path,
) -> None:
    """Same-minute sets lacking the requested artifacts are not candidates."""
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0930Z-000000", kinds=("db",))
    make_local_set(backup_dir, "20261014T0930Z-111111", kinds=("db",))
    make_local_set(backup_dir, "20261014T0929Z-222222")
    sets = restore.list_backup_sets(backup_dir)

    chosen = restore.choose_set(sets, None, True, False, backup_dir)

    assert restore.ts_of(chosen) == "20261014T0929Z-222222"


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
        client, config, set_files, True, False, staging_bid="20261014T1000Z"
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
        client, config, set_files, False, True, staging_bid="20261014T1000Z"
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
        client, config, set_files, False, True, staging_bid="20261014T1000Z"
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
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )

    staging = staging_dir_for(SITE_ROOT, "20261014T1000Z")
    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_run_restore_invalid_wp_cli_path_removes_staging(
    tmp_path: Path,
) -> None:
    """A base WPSSHBackupError (bad WP_CLI_PATH) must not leak staging."""
    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli=None)
    config = make_config(tmp_path, wp_cli_path="/nonexistent/wp")

    with pytest.raises(WPSSHBackupError, match="WP_CLI_PATH"):
        restore.run_restore(
            client,
            config,
            set_files,
            False,
            True,
            staging_bid="20261014T1000Z",
        )

    staging = staging_dir_for(SITE_ROOT, "20261014T1000Z")
    assert staging not in client.directories
    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_write_remote_file_sets_mode_600(tmp_path: Path) -> None:
    client = FakeSSHClient(SITE_ROOT)
    write_remote_file(client.sftp, "/tmp/secret.cnf", "[client]\n", mode=0o600)
    assert client.sftp.modes["/tmp/secret.cnf"] == 0o600


def test_main_reports_ssh_failure_as_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """An SSH failure during restore must print ERROR: and exit 1."""
    import paramiko

    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    def failing_exec_command(
        command: str, timeout: float | None = None
    ) -> object:
        raise paramiko.SSHException("transport died")

    client.exec_command = failing_exec_command  # type: ignore[method-assign]
    monkeypatch.setattr(restore, "load_config", lambda: config)
    monkeypatch.setattr(restore, "connect", lambda cfg: client)

    exit_code = restore.main([])

    assert exit_code == 1
    err = capsys.readouterr().err
    assert err.startswith("ERROR: ")
    assert "transport died" in err


def test_import_database_site_path_with_spaces(tmp_path: Path) -> None:
    """Regression: a spaced site path must not break the mysql trap action."""
    import shlex

    spaced_root = "/home/user/my site/public_html"
    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(spaced_root, wp_cli=None)
    config = make_config(tmp_path, wp_site_root=spaced_root)
    client.remote_fs[posixpath.join(spaced_root, "wp-config.php")] = (
        "define( 'DB_NAME', 'wpdb' );\n"
        "define( 'DB_USER', 'u' );\n"
        "define( 'DB_PASSWORD', 'p' );\n"
        "define( 'DB_HOST', 'localhost' );\n"
    ).encode()

    restore.run_restore(
        client,
        config,
        set_files,
        False,
        True,
        staging_bid="20261014T1000Z",
    )

    staging = staging_dir_for(spaced_root, "20261014T1000Z")
    # The trap action reached the shell as ONE argument containing the
    # quoted cnf path, not as several broken arguments.
    trap_commands = [c for c in client.commands if "trap" in c]
    assert len(trap_commands) == 1
    action = trap_commands[0].split("trap ", 1)[1].split(" EXIT")[0]
    words = shlex.split(f"trap {action} EXIT")
    assert len(words) == 3
    assert words[0] == "trap" and words[2] == "EXIT"
    # Re-evaluating the action yields rm with the spaced path as one arg.
    cnf_path = posixpath.join(staging, f"my-{TS}.cnf")
    assert shlex.split(words[1]) == ["rm", "-f", cnf_path]
    # The import ran and the credentials file was cleaned up.
    mysql_commands = [c for c in client.commands if "mysql " in c]
    assert len(mysql_commands) == 1
    assert "--defaults-extra-file" in mysql_commands[0]
    assert cnf_path not in client.remote_fs
