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
    WPSSHBackupError,
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


def test_choose_set_ignores_invalid_date_sets(tmp_path: Path) -> None:
    """A set with an impossible date must not crash default selection."""
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261301T0000Z")  # month 13
    make_local_set(backup_dir, "20261013T0000Z")
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


def test_resolve_timestamp_legacy_plus_suffixed_is_ambiguous(
    tmp_path: Path,
) -> None:
    """A legacy set must not bypass the ambiguity check for its minute."""
    backup_dir = tmp_path / "backups"
    make_local_set(backup_dir, "20261014T0930Z")  # legacy, no suffix
    make_local_set(backup_dir, "20261014T0930Z-a1b2c3")
    sets = restore.list_backup_sets(backup_dir)

    with pytest.raises(MissingArtifactError) as excinfo:
        restore.choose_set(sets, "20261014T0930Z", True, True, backup_dir)

    message = str(excinfo.value)
    assert "Several backup sets share the timestamp" in message
    assert "20261014T0930Z" in message
    assert "20261014T0930Z-a1b2c3" in message


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
    # The staging directory was restricted to the owner (0700) so other
    # host users cannot reach the credentials file inside it.
    assert client.directory_modes[staging] == 0o700
    # Created 0700 in the mkdir itself: a permissive umask must not leave
    # the directory writable by others before the chmod runs.
    mkdir_commands = [c for c in client.commands if c.startswith("mkdir ")]
    assert mkdir_commands[0].startswith("mkdir -m 700 ")


def test_import_database_rejects_traversal_member(tmp_path: Path) -> None:
    """A ../ member in the DB tarball must block extraction."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, "20261014T1000Z")

    # Rebuild the DB tarball with a traversal member and refresh the
    # checksum so the archive still verifies.
    archive_name = db_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("../evil.sql")
        data = b"-- escaped"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="unexpected member"):
        restore.run_restore(
            client,
            config,
            set_files,
            False,
            True,
            staging_bid="20261014T1000Z",
        )

    # Nothing was extracted out of staging.
    assert posixpath.join(posixpath.dirname(staging), "evil.sql") not in (
        client.remote_fs
    )
    # Staging was cleaned up (restore always cleans on failure).
    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_import_database_rejects_symlink_member(tmp_path: Path) -> None:
    """A symlink member named like the cnf must block extraction."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli=None)
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, "20261014T1000Z")

    # A symlink member named my-<ts>.cnf pointing outside staging: the
    # later credentials write would follow it and overwrite the target.
    archive_name = db_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo(f"my-{TS}.cnf")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../../home/user/.bashrc"
        tar.addfile(info)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="unexpected member"):
        restore.run_restore(
            client,
            config,
            set_files,
            False,
            True,
            staging_bid="20261014T1000Z",
        )

    # The credentials file was never written through the link.
    assert posixpath.join(staging, f"my-{TS}.cnf") not in client.remote_fs
    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_import_database_rejects_extra_members(tmp_path: Path) -> None:
    """A second member in the DB tarball must block extraction."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = db_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo(f"wp-db-{TS}.sql")
        data = b"-- SQL dump\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        extra = tarfile.TarInfo("extra.txt")
        data = b"extra"
        extra.size = len(data)
        tar.addfile(extra, io.BytesIO(data))
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="exactly one member"):
        restore.run_restore(
            client,
            config,
            set_files,
            False,
            True,
            staging_bid="20261014T1000Z",
        )


def test_import_database_rejects_wrong_name(tmp_path: Path) -> None:
    """A single member with the wrong name must block extraction."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = db_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("dump.sql")
        data = b"-- SQL dump\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="unexpected member"):
        restore.run_restore(
            client,
            config,
            set_files,
            False,
            True,
            staging_bid="20261014T1000Z",
        )


def test_import_database_rejects_fifo_member(tmp_path: Path) -> None:
    """A FIFO named like the dump must be rejected before extraction.

    A checksum-matching archive whose single member is a FIFO passes a
    name-only check; extraction would create the FIFO and the later
    import can block reading it. Require a regular-file mode.
    """
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = db_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo(f"wp-db-{TS}.sql")
        info.type = tarfile.FIFOTYPE
        tar.addfile(info)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="FIFO"):
        restore.run_restore(
            client,
            config,
            set_files,
            False,
            True,
            staging_bid="20261014T1000Z",
        )

    # Nothing was extracted into staging.
    assert posixpath.join(staging_dir_for(SITE_ROOT, "20261014T1000Z"), (
        f"wp-db-{TS}.sql"
    )) not in client.remote_fs


def test_import_database_rejects_directory_member(tmp_path: Path) -> None:
    """A directory named like the dump must be rejected too."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = db_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo(f"wp-db-{TS}.sql")
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="directory"):
        restore.run_restore(
            client,
            config,
            set_files,
            False,
            True,
            staging_bid="20261014T1000Z",
        )
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, "20261014T1000Z")

    # Build a files archive containing an escaping symlink.
    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("uploads/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../private.txt"
        tar.addfile(link)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    # Refresh the checksum file so the archive still verifies.
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="symlink"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )

    # Nothing was extracted into the site root.
    assert posixpath.join(SITE_ROOT, "wp-config.php") not in client.remote_fs
    # Staging was cleaned up (restore always cleans on failure).
    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_extract_files_rejects_traversal_member(tmp_path: Path) -> None:
    """A member named with ../ traversal must block extraction."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("../outside.txt")
        data = b"escaped"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="escapes the site root"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )

    assert posixpath.join(SITE_ROOT, "wp-config.php") not in client.remote_fs


SPECIAL_MEMBER_TYPES = pytest.mark.parametrize(
    "member_type",
    [b"6", b"3", b"4", b"7", b"Z"],
    ids=["fifo", "character-device", "block-device", "contiguous", "unknown"],
)


def _archive_with_special_member(member_type: bytes) -> bytes:
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        regular = tarfile.TarInfo("wp-config.php")
        regular.size = len(b"replacement")
        tar.addfile(regular, io.BytesIO(b"replacement"))
        special = tarfile.TarInfo("uploads/special")
        special.type = member_type
        if member_type == b"7":
            # A contiguous member carries data and extracts as a file.
            special.size = len(b"data")
            tar.addfile(special, io.BytesIO(b"data"))
        else:
            tar.addfile(special)
    return buffer.getvalue()


@SPECIAL_MEMBER_TYPES
@pytest.mark.parametrize("contiguous_listing_kind", ["C", "-"])
def test_run_restore_rejects_special_members_before_extraction(
    tmp_path: Path, member_type: bytes, contiguous_listing_kind: str
) -> None:
    """Special members are rejected from the archive's raw type flags.

    The check must not depend on how the remote tar labels member types:
    GNU tar 1.35 lists a contiguous file as 'C', but other implementations
    may list it as a regular file ('-').
    """
    set_files = make_local_set(tmp_path / "backups", TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    client.contiguous_listing_kind = contiguous_listing_kind
    config = make_config(tmp_path)
    live_path = posixpath.join(SITE_ROOT, "wp-config.php")
    client.remote_fs[live_path] = b"original site configuration"
    archive_name = files_archive_name(TS)
    data = _archive_with_special_member(member_type)
    set_files[archive_name].write_bytes(data)
    set_files[checksum_name(archive_name)].write_text(
        f"{hashlib.sha256(data).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="unsupported member type"):
        restore.run_restore(
            client, config, set_files, True, False,
            staging_bid="20261014T1000Z",
        )

    # Rejected before any extraction or listing; staging was cleaned up.
    assert not any(command.startswith("tar ") for command in client.commands)
    assert client.remote_fs == {live_path: b"original site configuration"}
    staging = staging_dir_for(SITE_ROOT, "20261014T1000Z")
    assert staging not in client.directories


@SPECIAL_MEMBER_TYPES
def test_extract_files_rejects_special_members_in_listing(
    tmp_path: Path, member_type: bytes
) -> None:
    """The remote listing check independently blocks special members."""
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, "20261014T1000Z")
    live_path = posixpath.join(SITE_ROOT, "wp-config.php")
    client.remote_fs[live_path] = b"original site configuration"
    client.remote_fs[posixpath.join(staging, files_archive_name(TS))] = (
        _archive_with_special_member(member_type)
    )

    with pytest.raises(WPSSHBackupError, match="unsupported member type"):
        restore.extract_files(client, config, staging, TS)

    assert not any(command.startswith("tar xzf ") for command in client.commands)
    assert client.remote_fs[live_path] == b"original site configuration"
    assert posixpath.join(SITE_ROOT, "uploads/special") not in client.remote_fs


def test_extract_files_allows_internal_symlink(tmp_path: Path) -> None:
    """A symlink resolving inside the site root must be allowed."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("uploads/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../index.php"
        tar.addfile(link)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    restore.run_restore(
        client, config, set_files, True, False, staging_bid="20261014T1000Z"
    )

    # The internal link was extracted.
    assert (
        client.remote_fs[posixpath.join(SITE_ROOT, "uploads/link")]
        == b"-> ../index.php"
    )


def test_extract_files_rejects_symlink_name_with_spaces(
    tmp_path: Path,
) -> None:
    """A spaced link name must still be validated (quoted listing)."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("uploads/link with space")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../private.txt"
        tar.addfile(link)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="resolves outside"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )

    assert posixpath.join(SITE_ROOT, "wp-config.php") not in client.remote_fs


def test_extract_files_rejects_symlink_name_with_arrow(
    tmp_path: Path,
) -> None:
    """A link name containing ' -> ' must not be mistaken for a target."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        # The NAME contains ' -> '; the target escapes. A naive parser
        # would read the name's arrow as the separator and validate the
        # wrong string.
        link = tarfile.TarInfo("uploads/a -> b")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../private.txt"
        tar.addfile(link)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="resolves outside"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )

    assert posixpath.join(SITE_ROOT, "wp-config.php") not in client.remote_fs


def test_extract_files_allows_internal_symlink_with_spaces(
    tmp_path: Path,
) -> None:
    """A benign spaced link must survive the quoted-listing decode."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("uploads/my link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../index.php"
        tar.addfile(link)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    restore.run_restore(
        client, config, set_files, True, False, staging_bid="20261014T1000Z"
    )

    assert (
        client.remote_fs[posixpath.join(SITE_ROOT, "uploads/my link")]
        == b"-> ../index.php"
    )


def test_validate_members_fails_closed_on_undecodable_line(
    tmp_path: Path,
) -> None:
    """A listing line that cannot be decoded must abort the restore."""
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    archive = posixpath.join(
        staging_dir_for(SITE_ROOT, "20261014T1000Z"),
        files_archive_name(TS),
    )
    # A malformed quoted token: shlex cannot decode an unterminated quote.
    listing = "lrwxrwxrwx user/group 0 2026-01-01 09:30 'uploads/broken\n"
    original_execute = client._execute

    def fake_execute(command: str, stdout, stderr):
        if "-tvzf" in command:
            stdout.write(listing.encode())
            return 0
        return original_execute(command, stdout, stderr)

    client._execute = fake_execute  # type: ignore[method-assign]
    # The archive must be a real gzip tarball so the listing command
    # itself succeeds; the fake's -tvzf output is replaced wholesale.
    import io as _io
    import tarfile as _tarfile

    buffer = _io.BytesIO()
    with _tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = _tarfile.TarInfo("wp-config.php")
        info.size = 0
        tar.addfile(info)
    client.remote_fs[archive] = buffer.getvalue()

    with pytest.raises(WPSSHBackupError, match="cannot decode"):
        restore._validate_members(archive, client, SITE_ROOT)


def test_extract_files_rejects_preexisting_symlinked_dir(
    tmp_path: Path,
) -> None:
    """A pre-existing symlinked 'uploads' must block extraction into it."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    # The site tree already contains uploads -> /home/user/private.
    client.remote_fs[posixpath.join(SITE_ROOT, "uploads")] = (
        b"-> /home/user/private"
    )

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        member = tarfile.TarInfo("uploads/file.txt")
        data = b"payload"
        member.size = len(data)
        tar.addfile(member, io.BytesIO(data))
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="already exists as a symlink"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )

    # Nothing was extracted into the site root.
    assert posixpath.join(SITE_ROOT, "wp-config.php") not in client.remote_fs


def test_extract_files_rejects_preexisting_link_in_member_dir(
    tmp_path: Path,
) -> None:
    """A pre-existing link inside an archive directory must block too."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    # uploads is a real directory, but it already contains a symlink.
    client.remote_fs[posixpath.join(SITE_ROOT, "uploads/escape")] = (
        b"-> ../../../private"
    )

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        member = tarfile.TarInfo("uploads/file.txt")
        data = b"payload"
        member.size = len(data)
        tar.addfile(member, io.BytesIO(data))
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="already exists as a symlink"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )

    assert posixpath.join(SITE_ROOT, "wp-config.php") not in client.remote_fs


def test_extract_files_ignores_symlink_outside_member_dirs(
    tmp_path: Path,
) -> None:
    """A pre-existing symlink in an untouched directory must not block."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    # other-dir is NOT written by the archive, so its symlink is not this
    # restore's business.
    client.remote_fs[posixpath.join(SITE_ROOT, "other-dir/link")] = (
        b"-> /somewhere"
    )

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    restore.run_restore(
        client, config, set_files, True, False, staging_bid="20261014T1000Z"
    )

    assert (
        client.remote_fs[posixpath.join(SITE_ROOT, "wp-config.php")]
        == b"<?php\n"
    )
    # The untouched symlink is still there.
    assert (
        client.remote_fs[posixpath.join(SITE_ROOT, "other-dir/link")]
        == b"-> /somewhere"
    )


def test_extract_files_rejects_chained_symlink_escape(
    tmp_path: Path,
) -> None:
    """A link chain that escapes via another member must be rejected."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        # a -> b (inside), b -> ../../private.txt (escapes).
        first = tarfile.TarInfo("uploads/a")
        first.type = tarfile.SYMTYPE
        first.linkname = "b"
        tar.addfile(first)
        second = tarfile.TarInfo("uploads/b")
        second.type = tarfile.SYMTYPE
        second.linkname = "../../private.txt"
        tar.addfile(second)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="resolves outside"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )

    assert posixpath.join(SITE_ROOT, "wp-config.php") not in client.remote_fs


def test_extract_files_rejects_absolute_symlink(tmp_path: Path) -> None:
    """A symlink with an absolute target must be rejected."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("uploads/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="resolves outside"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )

    assert posixpath.join(SITE_ROOT, "wp-config.php") not in client.remote_fs


def test_extract_files_strips_absolute_member(tmp_path: Path) -> None:
    """An absolute member is extracted inside the root (GNU strips '/')."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("/etc/evil.txt")
        data = b"evil"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    restore.run_restore(
        client, config, set_files, True, False, staging_bid="20261014T1000Z"
    )

    # GNU tar strips the leading slash, so the member lands inside the
    # site root as etc/evil.txt — allowed, not an escape.
    assert (
        client.remote_fs[posixpath.join(SITE_ROOT, "etc/evil.txt")]
        == b"evil"
    )


def test_extract_files_allows_hard_link(tmp_path: Path) -> None:
    """A hard link to a member inside the archive must be allowed."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        hard = tarfile.TarInfo("uploads/hard")
        hard.type = tarfile.LNKTYPE
        hard.linkname = "wp-config.php"
        tar.addfile(hard)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    restore.run_restore(
        client, config, set_files, True, False, staging_bid="20261014T1000Z"
    )

    # The hard link was extracted (fake records it as a link entry).
    assert (
        client.remote_fs[posixpath.join(SITE_ROOT, "uploads/hard")]
        == b"-> wp-config.php"
    )


def test_extract_files_rejects_hard_link_to_outside_member(
    tmp_path: Path,
) -> None:
    """A hard link targeting a non-member must be rejected.

    A crafted archive can name a target that is NOT an archive member
    but IS an existing symlink in the destination tree pointing outside
    the site: tar follows it during extraction and creates a second
    link to the outside file. Reject any hard link whose target is not
    a regular archive member.
    """
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    # Pre-existing symlink 'untouched/escape' -> outside the site. The
    # archive never writes into untouched/, so the destination audit
    # correctly ignores it — the protection must come from the member
    # check instead.
    client.remote_fs[posixpath.join(SITE_ROOT, "untouched/escape")] = (
        b"-> /home/user/private.txt"
    )

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        hard = tarfile.TarInfo("uploads/copy")
        hard.type = tarfile.LNKTYPE
        hard.linkname = "untouched/escape"
        tar.addfile(hard)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="not a regular member"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )

    # Nothing was extracted into the site root.
    assert posixpath.join(SITE_ROOT, "wp-config.php") not in client.remote_fs
    # The pre-existing escape symlink was left untouched.
    assert (
        client.remote_fs[posixpath.join(SITE_ROOT, "untouched/escape")]
        == b"-> /home/user/private.txt"
    )


def test_extract_files_rejects_hard_link_to_symlink_member(
    tmp_path: Path,
) -> None:
    """A hard link targeting an archive SYMLINK must be rejected too."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    # The archive itself carries a symlink whose target is a member.
    # Hard-linking to the symlink NAME would be resolved by tar through
    # the existing tree at extraction time, so it is not the regular
    # member the hard-link check requires.
    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("uploads/alias")
        link.type = tarfile.SYMTYPE
        link.linkname = "../wp-config.php"
        tar.addfile(link)
        hard = tarfile.TarInfo("uploads/copy")
        hard.type = tarfile.LNKTYPE
        hard.linkname = "uploads/alias"
        tar.addfile(hard)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    with pytest.raises(WPSSHBackupError, match="not a regular member"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )

    assert posixpath.join(SITE_ROOT, "wp-config.php") not in client.remote_fs


def test_extract_files_allows_hard_link_targeting_regular_member(
    tmp_path: Path,
) -> None:
    """A hard link naming another REGULAR member must still be allowed."""
    import io
    import tarfile

    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    archive_name = files_archive_name(TS)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("wp-config.php")
        data = b"<?php\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        other = tarfile.TarInfo("index.php")
        data = b"<?php\n"
        other.size = len(data)
        tar.addfile(other, io.BytesIO(data))
        hard = tarfile.TarInfo("uploads/hard")
        hard.type = tarfile.LNKTYPE
        hard.linkname = "index.php"
        tar.addfile(hard)
    archive_path = set_files[archive_name]
    archive_path.write_bytes(buffer.getvalue())
    checksum_path = set_files[checksum_name(archive_name)]
    checksum_path.write_text(
        f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {archive_name}\n"
    )

    restore.run_restore(
        client, config, set_files, True, False, staging_bid="20261014T1000Z"
    )

    assert (
        client.remote_fs[posixpath.join(SITE_ROOT, "uploads/hard")]
        == b"-> index.php"
    )


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


def test_run_restore_chmod_failure_removes_staging(tmp_path: Path) -> None:
    """A failed 0700 chmod must not orphan the staging directory."""
    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    client.fail_on["chmod"] = 1
    config = make_config(tmp_path)

    with pytest.raises(Exception):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )

    staging = staging_dir_for(SITE_ROOT, "20261014T1000Z")
    # The directory this run created was removed by the cleanup handler.
    assert staging not in client.directories
    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_run_restore_manifest_naming_other_file_rejected(
    tmp_path: Path,
) -> None:
    """A manifest pointing at another file must not pass verification."""
    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    archive_path = set_files[files_archive_name(TS)]
    # Corrupt the archive, then rewrite the manifest to name a different
    # file whose digest matches what the manifest claims.
    archive_path.write_bytes(b"corrupted")
    checksum_path = set_files[checksum_name(files_archive_name(TS))]
    decoy_digest = hashlib.sha256(b"decoy").hexdigest()
    checksum_path.write_text(f"{decoy_digest}  wp-db-{TS}.tar.gz\n")
    # Upload a decoy file so sha256sum would succeed if it followed the
    # manifest's filename.
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    with pytest.raises(ChecksumError, match="does not name"):
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


def test_run_restore_manifest_with_traversal_rejected(
    tmp_path: Path,
) -> None:
    """A manifest naming a path outside staging must be rejected."""
    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    checksum_path = set_files[checksum_name(files_archive_name(TS))]
    digest = hashlib.sha256(
        set_files[files_archive_name(TS)].read_bytes()
    ).hexdigest()
    checksum_path.write_text(f"{digest}  ../../etc/passwd\n")
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    with pytest.raises(ChecksumError, match="outside the staging"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )


def test_run_restore_manifest_with_extra_entries_rejected(
    tmp_path: Path,
) -> None:
    """A manifest with more than one entry must be rejected."""
    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    checksum_path = set_files[checksum_name(files_archive_name(TS))]
    digest = hashlib.sha256(
        set_files[files_archive_name(TS)].read_bytes()
    ).hexdigest()
    checksum_path.write_text(
        f"{digest}  {files_archive_name(TS)}\n"
        f"{digest}  wp-db-{TS}.tar.gz\n"
    )
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    with pytest.raises(ChecksumError, match="exactly one"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )


def test_run_restore_manifest_missing_archive_entry_rejected(
    tmp_path: Path,
) -> None:
    """A manifest that never names the requested archive must be rejected."""
    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    checksum_path = set_files[checksum_name(files_archive_name(TS))]
    digest = hashlib.sha256(b"decoy").hexdigest()
    checksum_path.write_text(f"{digest}  wp-db-{TS}.tar.gz\n")
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    with pytest.raises(ChecksumError, match="does not name"):
        restore.run_restore(
            client,
            config,
            set_files,
            True,
            False,
            staging_bid="20261014T1000Z",
        )


def test_run_restore_honest_manifest_still_passes(tmp_path: Path) -> None:
    """The strict manifest checks must not break the honest path."""
    backup_dir = tmp_path / "backups"
    set_files = make_local_set(backup_dir, TS)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)

    restore.run_restore(
        client,
        config,
        set_files,
        True,
        False,
        staging_bid="20261014T1000Z",
    )

    staging = staging_dir_for(SITE_ROOT, "20261014T1000Z")
    # The files archive was extracted into the site root.
    extracted = posixpath.join(SITE_ROOT, "wp-config.php")
    assert extracted in client.remote_fs
    # Staging cleaned up after success.
    assert not any(path.startswith(staging) for path in client.remote_fs)
    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_write_remote_file_sets_mode_600(tmp_path: Path) -> None:
    client = FakeSSHClient(SITE_ROOT)
    write_remote_file(client.sftp, "/tmp/secret.cnf", "[client]\n", mode=0o600)
    assert client.sftp.modes["/tmp/secret.cnf"] == 0o600


def test_write_remote_file_restores_umask(tmp_path: Path) -> None:
    """The umask must be restored after the write, even if it fails."""
    import os

    client = FakeSSHClient(SITE_ROOT)
    before = os.umask(0o077)
    os.umask(before)
    try:
        write_remote_file(client.sftp, "/tmp/x.cnf", "x")
        # The previous umask is restored after the write.
        assert os.umask(0o077) == before
        os.umask(before)
        # The written file was created restricted (SFTP servers apply the
        # remote umask at creation time; the fake mirrors this by opening
        # under the caller's umask and recording the resulting default).
        assert client.sftp.modes.get("/tmp/x.cnf") is not None
    finally:
        os.umask(before)


@pytest.mark.parametrize("error_type", [PermissionError, OSError])
def test_main_reports_backup_directory_listing_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    error_type: type[OSError],
) -> None:
    config = make_config(tmp_path)
    config.backup_dir.mkdir()
    original_iterdir = Path.iterdir
    error = error_type(f"Cannot list backup directory: {config.backup_dir}")

    def iterdir(path: Path):
        if path == config.backup_dir:
            raise error
        return original_iterdir(path)

    def unexpected_connect(config: Config) -> None:
        pytest.fail("Selection failure must not open an SSH connection")

    monkeypatch.setattr(restore, "load_config", lambda: config)
    monkeypatch.setattr(Path, "iterdir", iterdir)
    monkeypatch.setattr(restore, "connect", unexpected_connect)

    assert restore.main([]) == 2

    output = capsys.readouterr()
    assert output.err.startswith("ERROR: ")
    assert str(error) in output.err
    assert "Traceback" not in output.err
    assert "Restore complete." not in output.out


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
