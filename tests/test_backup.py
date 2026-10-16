"""Orchestration tests for backup.py using the fake SSH/SFTP layer."""

from __future__ import annotations

import hashlib
import os
import posixpath
from pathlib import Path
from typing import BinaryIO

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


def make_temp_set(backup_dir: Path, *archives: str) -> dict[str, Path]:
    """Write .part downloads for each archive, keyed by final name."""
    temp_paths: dict[str, Path] = {}
    for archive in archives:
        archive_path = backup_dir / (archive + ".part")
        archive_path.write_bytes(b"payload")
        manifest = f"{hashlib.sha256(b'payload').hexdigest()}  {archive}\n"
        checksum_path = backup_dir / (checksum_name(archive) + ".part")
        checksum_path.write_bytes(manifest.encode())
        temp_paths[archive] = archive_path
        temp_paths[checksum_name(archive)] = checksum_path
    return temp_paths


def digests_for(temp_paths: dict[str, Path]) -> dict[str, str]:
    """Digests of the current .part bytes, keyed by final name."""
    return {
        final: hashlib.sha256(path.read_bytes()).hexdigest()
        for final, path in temp_paths.items()
    }


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
    original_getfo = client.sftp.getfo

    def corrupting_getfo(remote_path: str, local_file: object) -> None:
        original_getfo(remote_path, local_file)
        if remote_path.endswith(".tar.gz"):
            local_file.seek(0)
            local_file.write(b"corrupted")

    client.sftp.getfo = corrupting_getfo  # type: ignore[method-assign]
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    with pytest.raises(ChecksumError):
        backup.run_backup(
            client, config, include_files=True, include_database=False, bid=TS
        )

    # Remote staging must be kept for retry.
    assert any(path.startswith(staging) for path in client.remote_fs)


def test_run_backup_checksum_mismatch_leaves_no_final_name_files(
    tmp_path: Path, backup_dir: Path
) -> None:
    """A failed verification must not leave a corrupt set in BACKUP_DIR."""
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    original_getfo = client.sftp.getfo

    def corrupting_getfo(remote_path: str, local_file: object) -> None:
        original_getfo(remote_path, local_file)
        if remote_path.endswith(".tar.gz"):
            local_file.seek(0)
            local_file.write(b"corrupted")

    client.sftp.getfo = corrupting_getfo  # type: ignore[method-assign]
    config = make_config(tmp_path)

    with pytest.raises(ChecksumError):
        backup.run_backup(
            client, config, include_files=True, include_database=False, bid=TS
        )

    # No file from this run may remain under its final name: a corrupt
    # archive-plus-manifest pair would be advertised by find_backup_sets()
    # as a complete set and a default restore could select it.
    assert list(backup_dir.iterdir()) == []
    from common import find_backup_sets

    assert find_backup_sets(backup_dir) == {}


def test_verify_downloads_undecodable_manifest_raises_checksum_error(
    tmp_path: Path,
) -> None:
    """An invalid-UTF-8 manifest must raise ChecksumError, not crash."""
    archive = files_archive_name(TS)
    archive_path = tmp_path / (archive + ".part")
    archive_path.write_bytes(b"payload")
    checksum_path = tmp_path / (checksum_name(archive) + ".part")
    checksum_path.write_bytes(b"\xff\xfe\x00invalid-utf8")

    with pytest.raises(ChecksumError, match="not valid UTF-8"):
        backup.verify_downloads(
            {
                archive: archive_path,
                checksum_name(archive): checksum_path,
            },
            [archive],
        )


def test_verify_downloads_returns_publication_digests(
    tmp_path: Path,
) -> None:
    """verify_downloads must bind each final name to a digest.

    publish_downloads() re-verifies every published file against the
    digest verify_downloads() captured, so the returned mapping must
    cover the archives (bound to their manifest digest) and the
    checksum files (bound to their own digest at verification time).
    """
    archive = files_archive_name(TS)
    payload = b"payload"
    manifest = f"{hashlib.sha256(payload).hexdigest()}  {archive}\n"
    archive_path = tmp_path / (archive + ".part")
    archive_path.write_bytes(payload)
    checksum_path = tmp_path / (checksum_name(archive) + ".part")
    checksum_path.write_bytes(manifest.encode())

    digests = backup.verify_downloads(
        {archive: archive_path, checksum_name(archive): checksum_path},
        [archive],
    )

    assert digests[archive] == hashlib.sha256(payload).hexdigest()
    assert digests[checksum_name(archive)] == hashlib.sha256(
        manifest.encode()
    ).hexdigest()


def test_download_artifacts_uses_temp_names(
    tmp_path: Path, backup_dir: Path
) -> None:
    """Downloads must land under .part names, invisible to set discovery."""
    from common import find_backup_sets, sftp_download

    client = FakeSSHClient(SITE_ROOT)
    staging = staging_dir_for(SITE_ROOT, TS)
    archive = files_archive_name(TS)
    client.remote_fs[posixpath.join(staging, archive)] = b"payload"
    client.remote_fs[posixpath.join(staging, checksum_name(archive))] = (
        f"{'a' * 64}  {archive}\n".encode()
    )

    with client.open_sftp() as sftp:
        temp_paths = backup.download_artifacts(
            sftp, staging, [archive], backup_dir
        )

    # The temp files exist under .part names...
    assert (backup_dir / (archive + ".part")).is_file()
    assert (
        backup_dir / (checksum_name(archive) + ".part")
    ).is_file()
    # ...and are invisible to find_backup_sets (no complete set yet).
    assert find_backup_sets(backup_dir) == {}
    # The returned mapping is keyed by final names.
    assert temp_paths[archive] == backup_dir / (archive + ".part")
    del sftp_download


def test_publish_downloads_publishes_verified_files(
    backup_dir: Path,
) -> None:
    """publish_downloads publishes .part files under their final names."""
    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)

    local_paths = backup.publish_downloads(
        temp_paths,
        [archive],
        backup_dir,
        digests_for(temp_paths),
    )

    assert local_paths[archive] == backup_dir / archive
    assert (backup_dir / archive).is_file()
    assert (backup_dir / checksum_name(archive)).is_file()
    assert not temp_paths[archive].exists()
    assert not temp_paths[checksum_name(archive)].exists()


def test_publish_downloads_refuses_overwrite_of_existing(
    backup_dir: Path,
) -> None:
    """Pre-existing final-name files must be preserved, not overwritten."""
    archive = files_archive_name(TS)
    existing = backup_dir / archive
    existing.write_bytes(b"prior-content")
    temp_paths = make_temp_set(backup_dir, archive)

    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        backup.publish_downloads(
            temp_paths,
            [archive],
            backup_dir,
            digests_for(temp_paths),
        )

    # The pre-existing file is untouched; nothing was moved.
    assert existing.read_bytes() == b"prior-content"
    assert temp_paths[archive].is_file()
    assert temp_paths[checksum_name(archive)].is_file()


@pytest.mark.parametrize("kind", ["file", "dangling-symlink", "live-symlink"])
def test_publish_downloads_refuses_existing_symlink(
    tmp_path: Path, backup_dir: Path, kind: str
) -> None:
    """A symlink at a final name must be rejected, not replaced.

    Path.exists() is False for a dangling symlink, so the existence
    check alone would let Path.replace() silently replace it.
    """
    import os

    if kind != "file" and os.name == "nt":
        pytest.skip("symlink creation requires privileges on Windows")

    archive = files_archive_name(TS)
    final_path = backup_dir / archive
    target = tmp_path / "target"
    if kind == "dangling-symlink":
        final_path.symlink_to(tmp_path / "missing-target")
    elif kind == "live-symlink":
        target.write_bytes(b"prior-content")
        final_path.symlink_to(target)
    else:
        final_path.write_bytes(b"prior-content")
    temp_paths = make_temp_set(backup_dir, archive)

    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        backup.publish_downloads(
            temp_paths,
            [archive],
            backup_dir,
            digests_for(temp_paths),
        )

    # The pre-existing path is untouched; nothing was moved.
    assert temp_paths[archive].is_file()
    assert temp_paths[checksum_name(archive)].is_file()
    if kind == "dangling-symlink":
        assert final_path.is_symlink()
        assert not final_path.exists()
    elif kind == "live-symlink":
        assert final_path.is_symlink()
        assert target.read_bytes() == b"prior-content"
    else:
        assert final_path.read_bytes() == b"prior-content"


def test_publish_downloads_rolls_back_partial_publication(
    backup_dir: Path,
) -> None:
    """A mid-publication failure must leave no final-name files behind.

    A failing publication after the first files were published (e.g.
    permission error) used to leave a lone final-name artifact that
    discovery could pair with a stale checksum. Publication must be
    transactional: the final paths this run created are removed so the
    caller's cleanup discards the still intact temporary downloads.
    """
    # Two sets so at least one publication happens before the failure.
    bid2 = "20261014T0931Z-b2c3d4"
    archive1 = files_archive_name(TS)
    archive2 = files_archive_name(bid2)
    temp_paths = make_temp_set(backup_dir, archive1, archive2)

    import unittest.mock

    original_publish = backup._publish_no_replace

    calls = {"n": 0}

    def exploding_publish(
        handle: BinaryIO, temp_path: Path, final_path: Path
    ) -> BinaryIO:
        calls["n"] += 1
        if calls["n"] == 3:
            # First two publications (archive1 + its checksum)
            # succeeded; the third fails, simulating a
            # mid-publication error.
            raise OSError("simulated mid-publication failure")
        return original_publish(handle, temp_path, final_path)

    with unittest.mock.patch.object(
        backup, "_publish_no_replace", exploding_publish
    ):
        with pytest.raises(OSError, match="simulated mid-publication"):
            backup.publish_downloads(
                temp_paths,
                [archive1, archive2],
                backup_dir,
                digests_for(temp_paths),
            )

    # No final-name file from this run remains: the first two published
    # paths were rolled back, and none of the four finals exist.
    for final in (
        archive1,
        checksum_name(archive1),
        archive2,
        checksum_name(archive2),
    ):
        assert not (backup_dir / final).exists()
    # The temporary downloads were never unlinked, so the caller's
    # _discard_temp_downloads() will remove them.
    assert temp_paths[archive1].exists()
    assert temp_paths[checksum_name(archive1)].exists()
    assert temp_paths[archive2].exists()
    assert temp_paths[checksum_name(archive2)].exists()


def test_publish_downloads_no_replace_survives_post_check_race(
    backup_dir: Path,
) -> None:
    """A final path created after the pre-check must not be overwritten.

    The existence pre-check and publication are not one atomic step: a
    concurrent backup process (or a local attacker who can write
    BACKUP_DIR) can create a final path in between. Publication must use
    a no-replace operation so the newcomer is preserved and the run
    fails instead of silently replacing it.
    """
    import unittest.mock

    bid2 = "20261014T0931Z-b2c3d4"
    archive1 = files_archive_name(TS)
    archive2 = files_archive_name(bid2)
    temp_paths = make_temp_set(backup_dir, archive1, archive2)

    original_publish = backup._publish_no_replace

    def racing_publish(
        handle: BinaryIO, temp_path: Path, final_path: Path
    ) -> BinaryIO:
        if final_path.name == checksum_name(archive2):
            # Simulate another process creating the final path after
            # the pre-check, just before this run publishes it.
            final_path.write_bytes(b"created-by-other-process")
        return original_publish(handle, temp_path, final_path)

    with unittest.mock.patch.object(
        backup, "_publish_no_replace", racing_publish
    ):
        with pytest.raises(FileExistsError, match="Refusing to overwrite"):
            backup.publish_downloads(
                temp_paths,
                [archive1, archive2],
                backup_dir,
                digests_for(temp_paths),
            )

    # The other process's file is preserved, not overwritten.
    checksum2 = backup_dir / checksum_name(archive2)
    assert checksum2.read_bytes() == b"created-by-other-process"
    # This run's earlier publications were rolled back.
    assert not (backup_dir / archive1).exists()
    assert not (backup_dir / checksum_name(archive1)).exists()
    assert not (backup_dir / archive2).exists()
    # The temporary downloads remain for the caller's cleanup.
    for temp_path in temp_paths.values():
        assert temp_path.exists()


def test_publish_downloads_rejects_symlinked_temp(
    backup_dir: Path,
) -> None:
    """A .part path swapped for a symlink must not be published.

    os.link() follows a symlink at the source path, so publication from
    the pathname would link the target's unverified inode. The .part
    files are opened through no-follow descriptors before publication;
    this test simulates the swap by making os.open() reject the leaf
    with ELOOP, the same failure O_NOFOLLOW produces on POSIX.
    """
    import errno
    import os
    import unittest.mock

    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)

    def open_rejects_symlink(path, *args, **kwargs):
        if str(path).endswith(".part"):
            raise OSError(errno.ELOOP, "Too many levels of symbolic links")
        return real_open(path, *args, **kwargs)

    real_open = os.open
    with unittest.mock.patch.object(
        backup.os, "open", open_rejects_symlink
    ):
        with pytest.raises(
            WPSSHBackupError, match="Refusing to publish through symlink"
        ):
            backup.publish_downloads(
                temp_paths,
                [archive],
                backup_dir,
                digests_for(temp_paths),
            )

    # Nothing was published and the temps were not touched.
    assert not (backup_dir / archive).exists()
    assert not (backup_dir / checksum_name(archive)).exists()
    assert temp_paths[archive].is_file()
    assert temp_paths[checksum_name(archive)].is_file()


def test_publish_downloads_rejects_temp_replaced_before_publication(
    backup_dir: Path,
) -> None:
    """A .part replaced after verification must not be published.

    A writer who can write BACKUP_DIR can replace a verified .part
    pathname with different bytes before publication opens it. The
    digest is re-verified through the held descriptor after linking, so
    the replacement is detected and the publication is rolled back
    instead of publishing unverified bytes.
    """
    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    digests = digests_for(temp_paths)

    # Simulate a writer replacing the verified .part pathname with
    # different bytes after verification, before publication opens it.
    temp_paths[archive].unlink()
    temp_paths[archive].write_bytes(b"attacker-bytes")

    with pytest.raises(ChecksumError, match="changed after verification"):
        backup.publish_downloads(
            temp_paths,
            [archive],
            backup_dir,
            digests,
        )

    # The rejected publication was rolled back; the replacement's bytes
    # never appeared under a final name.
    assert not (backup_dir / archive).exists()
    assert not (backup_dir / checksum_name(archive)).exists()
    # The temporary downloads remain for the caller's cleanup.
    assert temp_paths[archive].is_file()
    assert temp_paths[checksum_name(archive)].is_file()


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows refuses to unlink a file this process holds open",
)
def test_publish_downloads_rejects_temp_replaced_after_open(
    backup_dir: Path,
) -> None:
    """A .part swapped after publication opened it must not be published.

    os.link() links the source pathname's current target, so a writer
    who replaces a verified .part pathname after publication opened it
    would publish the replacement's unverified inode. The created link
    must reference the held descriptor's inode; the identity check
    rejects the swap and the publication is rolled back.

    Skipped on Windows: the held descriptor itself prevents the
    replacement there (the file cannot be unlinked while open), so the
    scenario is POSIX-specific.
    """
    import unittest.mock

    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    digests = digests_for(temp_paths)

    original_publish = backup._publish_no_replace

    def replacing_publish(
        handle: BinaryIO, temp_path: Path, final_path: Path
    ) -> BinaryIO:
        if temp_path.name == archive + ".part":
            # Simulate a writer replacing the verified .part pathname
            # after publication opened it: the path now points at
            # different bytes, while the held descriptor still
            # references the verified inode.
            temp_path.unlink()
            temp_path.write_bytes(b"attacker-bytes")
        return original_publish(handle, temp_path, final_path)

    with unittest.mock.patch.object(
        backup, "_publish_no_replace", replacing_publish
    ):
        with pytest.raises(
            WPSSHBackupError, match="was replaced after verification"
        ):
            backup.publish_downloads(
                temp_paths,
                [archive],
                backup_dir,
                digests,
            )

    # The rejected publication was rolled back; the replacement's bytes
    # never appeared under a final name.
    assert not (backup_dir / archive).exists()
    assert not (backup_dir / checksum_name(archive)).exists()
    # The temporary downloads remain for the caller's cleanup.
    assert temp_paths[archive].is_file()
    assert temp_paths[checksum_name(archive)].is_file()


def test_publish_downloads_rejects_mutated_temp(
    backup_dir: Path,
) -> None:
    """A .part mutated in place after verification must not be published.

    A hard link shares the temporary file's inode, so bytes appended to
    the .part path between verification and publication would also
    change the published backup. The digest is re-verified through the
    held descriptor after linking, so the mutation is detected and the
    publication is rolled back.
    """
    import unittest.mock

    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    digests = digests_for(temp_paths)

    original_publish = backup._publish_no_replace

    def mutating_publish(
        handle: BinaryIO, temp_path: Path, final_path: Path
    ) -> BinaryIO:
        if temp_path.name == archive + ".part":
            # Simulate a writer appending to the verified .part in
            # place after verification, before the digest re-check.
            with open(temp_path, "ab") as mutating:
                mutating.write(b"tampered")
        return original_publish(handle, temp_path, final_path)

    with unittest.mock.patch.object(
        backup, "_publish_no_replace", mutating_publish
    ):
        with pytest.raises(ChecksumError, match="changed after verification"):
            backup.publish_downloads(
                temp_paths,
                [archive],
                backup_dir,
                digests,
            )

    # The mutated publication was rolled back; no final-name file
    # contains the tampered bytes.
    assert not (backup_dir / archive).exists()
    assert not (backup_dir / checksum_name(archive)).exists()
    # The temporary downloads remain for the caller's cleanup.
    assert temp_paths[archive].is_file()
    assert temp_paths[checksum_name(archive)].is_file()


def test_sftp_download_creates_private_file(tmp_path: Path) -> None:
    """Downloaded files must be 0600 regardless of the process umask.

    POSIX permission bits are not represented by Windows NTFS stat, so
    this asserts on the POSIX platforms the tool targets (CI runs
    ubuntu); on Windows the file is still created O_EXCL/0600-asking.
    """
    import os
    import sys

    from common import sftp_download

    if sys.platform == "win32":
        pytest.skip("POSIX mode bits are not reflected by Windows stat")

    client = FakeSSHClient(SITE_ROOT)
    client.remote_fs[posixpath.join(SITE_ROOT, "secret.tar.gz")] = (
        b"payload"
    )

    old_umask = os.umask(0o022)
    try:
        with client.open_sftp() as sftp:
            local = sftp_download(
                sftp,
                posixpath.join(SITE_ROOT, "secret.tar.gz"),
                tmp_path / "secret.tar.gz",
            )
    finally:
        os.umask(old_umask)

    assert (os.stat(local).st_mode & 0o777) == 0o600


def test_sftp_download_refuses_existing_symlink(tmp_path: Path) -> None:
    """A planted symlink at the destination must not be followed.

    Skipped on Windows: creating symlinks requires privileges there,
    and the O_EXCL-no-follow behaviour is POSIX-specific anyway.
    """
    import os

    from common import sftp_download

    if os.name == "nt":
        pytest.skip("symlink creation requires privileges on Windows")

    client = FakeSSHClient(SITE_ROOT)
    client.remote_fs[posixpath.join(SITE_ROOT, "archive.tar.gz")] = (
        b"payload"
    )

    target = tmp_path / "victim.txt"
    target.write_bytes(b"innocent")
    link = tmp_path / "archive.tar.gz.part"
    os.symlink(target, link)

    with client.open_sftp() as sftp:
        with pytest.raises(FileExistsError):
            sftp_download(
                sftp,
                posixpath.join(SITE_ROOT, "archive.tar.gz"),
                link,
            )

    # The planted target was NOT overwritten by the download.
    assert target.read_bytes() == b"innocent"


def test_sftp_download_refuses_existing_file(tmp_path: Path) -> None:
    """A pre-existing file at the destination must not be truncated."""
    from common import sftp_download

    client = FakeSSHClient(SITE_ROOT)
    client.remote_fs[posixpath.join(SITE_ROOT, "archive.tar.gz")] = (
        b"payload"
    )

    existing = tmp_path / "archive.tar.gz.part"
    existing.write_bytes(b"prior-content")

    with client.open_sftp() as sftp:
        with pytest.raises(FileExistsError):
            sftp_download(
                sftp,
                posixpath.join(SITE_ROOT, "archive.tar.gz"),
                existing,
            )

    assert existing.read_bytes() == b"prior-content"


def test_run_backup_undecodable_manifest_keeps_staging(
    tmp_path: Path, backup_dir: Path
) -> None:
    """An undecodable manifest must keep staging for retry, like a mismatch."""
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    original_getfo = client.sftp.getfo

    def corrupting_getfo(remote_path: str, local_file: object) -> None:
        original_getfo(remote_path, local_file)
        if remote_path.endswith(".sha256"):
            local_file.seek(0)
            local_file.write(b"\xff\xfe\x00invalid-utf8")

    client.sftp.getfo = corrupting_getfo  # type: ignore[method-assign]
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    with pytest.raises(ChecksumError, match="not valid UTF-8"):
        backup.run_backup(
            client, config, include_files=True, include_database=False, bid=TS
        )

    # Remote staging must be kept for retry.
    assert any(path.startswith(staging) for path in client.remote_fs)
    # And no partial downloads may linger in BACKUP_DIR.
    assert list(backup_dir.iterdir()) == []


def test_run_backup_sftp_failure_discards_temp_downloads(
    tmp_path: Path, backup_dir: Path
) -> None:
    """A dropped transfer must leave no partial files in BACKUP_DIR."""
    import paramiko

    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    original_getfo = client.sftp.getfo

    def failing_getfo(remote_path: str, local_file: object) -> None:
        if remote_path.endswith(".tar.gz"):
            # The archive lands, then the connection drops before the
            # manifest is fetched.
            original_getfo(remote_path, local_file)
            raise paramiko.SSHException("connection dropped")
        original_getfo(remote_path, local_file)

    client.sftp.getfo = failing_getfo  # type: ignore[method-assign]
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    with pytest.raises(paramiko.SSHException):
        backup.run_backup(
            client, config, include_files=True, include_database=False, bid=TS
        )

    assert list(backup_dir.iterdir()) == []
    # The remote staging dir is removed on non-checksum failures.
    assert not any(path.startswith(staging) for path in client.remote_fs)


@pytest.mark.parametrize("artifact", ["archive", "checksum"])
@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_run_backup_preserves_existing_temp_paths(
    tmp_path: Path,
    backup_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
    kind: str,
) -> None:
    import os

    if kind == "symlink" and os.name == "nt":
        pytest.skip("symlink creation requires privileges on Windows")

    archive = files_archive_name(TS)
    name = archive if artifact == "archive" else checksum_name(archive)
    existing = backup_dir / (name + ".part")
    target = tmp_path / "target"
    if kind == "directory":
        existing.mkdir()
        (existing / "keep").write_bytes(b"prior-content")
    elif kind == "symlink":
        target.write_bytes(b"prior-content")
        existing.symlink_to(target)
    else:
        existing.write_bytes(b"prior-content")

    original_unlink = Path.unlink
    attempted: list[Path] = []

    def unlink(path: Path, missing_ok: bool = False) -> None:
        attempted.append(path)
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", unlink)
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    with pytest.raises(OSError) as caught:
        backup.run_backup(
            client, make_config(tmp_path),
            include_files=True, include_database=False, bid=TS,
        )

    assert not isinstance(caught.value, IsADirectoryError)
    assert existing not in attempted
    assert list(backup_dir.iterdir()) == [existing]
    if kind == "directory":
        assert (existing / "keep").read_bytes() == b"prior-content"
    else:
        assert existing.read_bytes() == b"prior-content"
    if kind == "symlink":
        assert existing.is_symlink()
        assert target.read_bytes() == b"prior-content"
    assert staging_dir_for(SITE_ROOT, TS) not in client.directories


@pytest.mark.parametrize("failure", ["transfer", "checksum"])
def test_run_backup_cleanup_failure_preserves_original_exception(
    tmp_path: Path,
    backup_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    failure: str,
) -> None:
    import paramiko

    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    original_getfo = client.sftp.getfo
    original_error = paramiko.SSHException("original transfer failure")
    archive = backup_dir / (files_archive_name(TS) + ".part")
    original_unlink = Path.unlink
    attempted: list[Path] = []

    def getfo(remote_path, local_file):
        original_getfo(remote_path, local_file)
        if failure == "transfer":
            raise original_error
        if remote_path.endswith(".sha256"):
            local_file.seek(0)
            local_file.write(b"\xff")

    def unlink(path: Path, missing_ok: bool = False) -> None:
        attempted.append(path)
        if path == archive:
            raise PermissionError("cleanup denied")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(client.sftp, "getfo", getfo)
    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", unlink)
        expected = paramiko.SSHException if failure == "transfer" else ChecksumError
        with pytest.raises(expected) as caught:
            backup.run_backup(
                client, make_config(tmp_path),
                include_files=True, include_database=False, bid=TS,
            )

    if failure == "transfer":
        assert caught.value is original_error
    else:
        assert "not valid UTF-8" in str(caught.value)
        assert backup_dir / (checksum_name(files_archive_name(TS)) + ".part") in attempted
    assert list(backup_dir.iterdir()) == [archive]
    warning = capsys.readouterr().err
    assert "WARNING:" in warning
    assert str(archive) in warning
    assert "cleanup denied" in warning
    staging = staging_dir_for(SITE_ROOT, TS)
    assert (staging in client.directories) == (failure == "checksum")


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


def test_run_backup_chmod_failure_removes_staging(
    tmp_path: Path, backup_dir: Path
) -> None:
    """A failed 0700 chmod must not orphan the staging directory."""
    client = FakeSSHClient(SITE_ROOT)
    client.fail_on["chmod"] = 1
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    with pytest.raises(Exception):
        backup.run_backup(
            client, config, include_files=True, include_database=False, bid=TS
        )

    # The directory this run created was removed by the cleanup handler.
    assert staging not in client.directories
    assert not any(path.startswith(staging) for path in client.remote_fs)


def test_run_backup_chmod_runs_before_any_artifacts(
    tmp_path: Path, backup_dir: Path
) -> None:
    """The 0700 chmod must be a separate command issued before the dump."""
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)
    staging = staging_dir_for(SITE_ROOT, TS)

    backup.run_backup(
        client, config, include_files=False, include_database=True, bid=TS
    )

    # mkdir and chmod are separate commands; chmod comes before any
    # artifact-producing command (mysqldump / wp db export / tar czf).
    mkdir_commands = [c for c in client.commands if c.startswith("mkdir ")]
    chmod_commands = [c for c in client.commands if c.startswith("chmod ")]
    artifact_commands = [
        c for c in client.commands
        if "mysqldump" in c or "db export" in c or "tar czf" in c
    ]
    assert len(mkdir_commands) == 1
    assert len(chmod_commands) == 1
    assert "&&" not in mkdir_commands[0]
    # The directory is created 0700 in the mkdir itself, so a permissive
    # umask never leaves it writable by others before the chmod runs.
    assert mkdir_commands[0].startswith("mkdir -m 700 ")
    assert chmod_commands[0].startswith(f"chmod 700 '{staging}'")
    assert client.commands.index(chmod_commands[0]) < client.commands.index(
        artifact_commands[0]
    )
    # The staging directory was restricted to the owner (0700).
    assert client.directory_modes[staging] == 0o700


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


@pytest.mark.parametrize(
    ("failure_stage", "error_type"),
    [
        (None, None),
        ("pruning", PermissionError),
        ("pruning", FileNotFoundError),
        ("stat", PermissionError),
        ("stat", FileNotFoundError),
    ],
)
def test_main_handles_local_post_processing(
    tmp_path: Path,
    backup_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    failure_stage: str | None,
    error_type: type[OSError] | None,
) -> None:
    client = FakeSSHClient(SITE_ROOT)
    config = make_config(tmp_path)
    archive = backup_dir / files_archive_name(TS)
    original_prune = backup.prune_local_backups
    original_stat = Path.stat

    def failing_stat(path: Path, *args, **kwargs):
        if path == archive and error_type is not None:
            raise error_type("Backup directory unavailable")
        return original_stat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        def prune(directory: Path, retention_days: int) -> list[str]:
            if failure_stage == "pruning" and error_type is not None:
                raise error_type("Backup directory unavailable")
            removed = original_prune(directory, retention_days)
            if failure_stage == "stat":
                patch.setattr(Path, "stat", failing_stat)
            return removed

        patch.setattr(backup, "load_config", lambda: config)
        patch.setattr(backup, "connect", lambda cfg: client)
        patch.setattr(backup, "backup_id", lambda: TS)
        patch.setattr(backup, "prune_local_backups", prune)

        exit_code = backup.main(["--files"])

    output = capsys.readouterr()
    assert archive.is_file()
    assert (backup_dir / checksum_name(archive.name)).is_file()
    assert staging_dir_for(SITE_ROOT, TS) not in client.directories
    if failure_stage is None:
        assert exit_code == 0
        assert f"Backup complete: {TS}" in output.out
        assert output.err == ""
    else:
        assert exit_code == 1
        assert output.err.startswith(f"ERROR: Backup {TS} was downloaded")
        assert "verified" in output.err
        assert str(backup_dir) in output.err
        assert "Backup directory unavailable" in output.err
        assert "Backup complete:" not in output.out
        assert "Traceback" not in output.err
