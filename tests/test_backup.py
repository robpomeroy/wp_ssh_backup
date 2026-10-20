"""Orchestration tests for backup.py using the fake SSH/SFTP layer."""

from __future__ import annotations

import errno
import hashlib
import os
import posixpath
import unittest.mock
from pathlib import Path
from typing import BinaryIO

import pytest

import backup
import publish
import publish_lock
import safe_fs
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


def make_downloaded_fds(
    temp_paths: dict[str, Path],
) -> dict[Path, int]:
    """Open the fresh .part inodes the download would have handed over.

    Simulates the descriptors sftp_download() returns: one O_RDWR
    descriptor per .part path, opened after the test wrote the files.
    The caller owns them; publish_downloads() consumes (closes) them.
    """
    return {
        path: os.open(path, os.O_RDWR)
        for path in temp_paths.values()
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


def test_run_backup_rejects_swapped_download_pair(
    tmp_path: Path, backup_dir: Path
) -> None:
    """A self-consistent pair swapped after download must never publish.

    A writer who can modify BACKUP_DIR can replace the downloaded
    archive and manifest with a pair that is internally consistent
    (the manifest digests the swapped archive). Verification hashes the
    descriptors the download handed over — never the .part pathnames —
    so a pathname swap cannot change what is verified or published. The
    attacker's pair never reaches a final name: either the published
    backup is the downloaded payload, or the run fails cleanly with no
    final-name files.

    On Windows the held download descriptor even prevents the swap from
    taking effect (a held-open file cannot be unlinked); on POSIX the
    swap succeeds but is ignored because the held descriptors still
    reference the downloaded inodes (ext4 links the verified inode; on
    tmpfs the unlinked inode cannot be linked and the run is rolled
    back).
    """
    client = FakeSSHClient(SITE_ROOT, wp_cli="/usr/bin/wp")
    config = make_config(tmp_path)
    original_verify = backup.verify_downloads
    outer: dict[str, bytes] = {}

    def swapping_verify(
        local_paths: dict[str, Path],
        archive_names: list[str],
        downloaded_fds: dict[Path, int],
    ) -> dict[str, str]:
        # Capture the real transfer's archive bytes (what the held
        # descriptors must hash and publish) before the swap.
        outer["real_archive"] = local_paths[
            files_archive_name(TS)
        ].read_bytes()
        # Attempt to replace the downloaded archive and manifest with a
        # self-consistent attacker pair. On POSIX the pathname swap
        # succeeds (fresh inodes); on Windows the held descriptor blocks
        # the unlink. Either way verification hashes the held download
        # descriptors, never the pathnames.
        archive_path = local_paths[files_archive_name(TS)]
        checksum_path = local_paths[checksum_name(files_archive_name(TS))]
        attacker_manifest = (
            f"{hashlib.sha256(b'attacker-archive').hexdigest()}  "
            f"{files_archive_name(TS)}\n"
        )
        try:
            archive_path.unlink()
            archive_path.write_bytes(b"attacker-archive")
            checksum_path.unlink()
            checksum_path.write_bytes(attacker_manifest.encode())
        except PermissionError:
            # Windows: the held download descriptor blocks the swap.
            pass
        return original_verify(
            local_paths, archive_names, downloaded_fds
        )

    try:
        with unittest.mock.patch.object(
            backup, "verify_downloads", swapping_verify
        ):
            backup.run_backup(
                client,
                config,
                include_files=True,
                include_database=False,
                bid=TS,
            )
    except Exception:
        # The unattested inode was unlinked by the swap; some
        # filesystems (tmpfs) cannot link a nameless inode, so the run
        # is rolled back with no final-name files and no attacker bytes
        # published.
        assert not (backup_dir / files_archive_name(TS)).exists()
        assert not (
            backup_dir / checksum_name(files_archive_name(TS))
        ).exists()
        return

    # The attacker pair's bytes never appear under a final name: the
    # published archive is the real downloaded payload (hashed from the
    # held descriptor), not the attacker bytes. The published checksum
    # digests the real archive, so the pair is self-consistent with the
    # published payload.
    published = backup_dir / files_archive_name(TS)
    assert published.exists()
    assert published.read_bytes() == outer["real_archive"]
    published_manifest = (
        backup_dir / checksum_name(files_archive_name(TS))
    ).read_bytes()
    assert hashlib.sha256(outer["real_archive"]).hexdigest() in (
        published_manifest.decode()
    )


def test_verify_downloads_undecodable_manifest_raises_checksum_error(
    tmp_path: Path,
) -> None:
    """An invalid-UTF-8 manifest must raise ChecksumError, not crash."""
    archive = files_archive_name(TS)
    archive_path = tmp_path / (archive + ".part")
    archive_path.write_bytes(b"payload")
    checksum_path = tmp_path / (checksum_name(archive) + ".part")
    checksum_path.write_bytes(b"\xff\xfe\x00invalid-utf8")
    archive_fd = os.open(archive_path, os.O_RDWR)
    checksum_fd = os.open(checksum_path, os.O_RDWR)
    try:
        downloaded_fds = {
            archive_path: archive_fd,
            checksum_path: checksum_fd,
        }
        with pytest.raises(ChecksumError, match="not valid UTF-8"):
            backup.verify_downloads(
                {
                    archive: archive_path,
                    checksum_name(archive): checksum_path,
                },
                [archive],
                downloaded_fds,
            )
    finally:
        # verify_downloads consumed (closed) the fds via its context
        # manager; closing again is harmless.
        for fd in (archive_fd, checksum_fd):
            try:
                os.close(fd)
            except OSError:
                pass


def test_verify_downloads_rejects_multi_entry_manifest(
    tmp_path: Path,
) -> None:
    """A manifest with extra entries must not be accepted.

    The local verifier must require exactly one entry naming the
    requested archive, matching verify_remote_checksums(): a manifest
    containing the valid entry plus arbitrary extras would otherwise be
    accepted and published as a complete backup set, only to be rejected
    later by restore's remote verifier.
    """
    archive = files_archive_name(TS)
    archive_path = tmp_path / (archive + ".part")
    archive_path.write_bytes(b"payload")
    checksum_path = tmp_path / (checksum_name(archive) + ".part")
    # The valid entry plus an arbitrary extra entry.
    manifest = (
        f"{hashlib.sha256(b'payload').hexdigest()}  {archive}\n"
        f"{'a' * 64}  unrelated-file\n"
    )
    checksum_path.write_bytes(manifest.encode())
    archive_fd = os.open(archive_path, os.O_RDWR)
    checksum_fd = os.open(checksum_path, os.O_RDWR)
    try:
        downloaded_fds = {
            archive_path: archive_fd,
            checksum_path: checksum_fd,
        }
        with pytest.raises(
            ChecksumError, match="exactly one entry"
        ):
            backup.verify_downloads(
                {
                    archive: archive_path,
                    checksum_name(archive): checksum_path,
                },
                [archive],
                downloaded_fds,
            )
    finally:
        for fd in (archive_fd, checksum_fd):
            try:
                os.close(fd)
            except OSError:
                pass


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
    archive_fd = os.open(archive_path, os.O_RDWR)
    checksum_fd = os.open(checksum_path, os.O_RDWR)
    try:
        downloaded_fds = {
            archive_path: archive_fd,
            checksum_path: checksum_fd,
        }
        digests = backup.verify_downloads(
            {
                archive: archive_path,
                checksum_name(archive): checksum_path,
            },
            [archive],
            downloaded_fds,
        )
    finally:
        for fd in (archive_fd, checksum_fd):
            try:
                os.close(fd)
            except OSError:
                pass

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
        temp_paths, downloaded_fds = backup.download_artifacts(
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
    # The download handed over a descriptor of the inode it wrote; the
    # caller owns and must close it.
    try:
        for path, fd in downloaded_fds.items():
            st = os.fstat(fd)
            assert (st.st_dev, st.st_ino) == (
                os.stat(path).st_dev,
                os.stat(path).st_ino,
            )
            assert st.st_size == path.stat().st_size
    finally:
        for fd in downloaded_fds.values():
            os.close(fd)
    del sftp_download


def test_publish_downloads_publishes_verified_files(
    backup_dir: Path,
) -> None:
    """publish_downloads publishes .part files under their final names."""
    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)

    local_paths = publish.publish_downloads(
        temp_paths,
        [archive],
        backup_dir,
        digests_for(temp_paths),
        make_downloaded_fds(temp_paths),
    )

    assert local_paths[archive] == backup_dir / archive
    assert (backup_dir / archive).is_file()
    assert (backup_dir / checksum_name(archive)).is_file()
    assert not temp_paths[archive].exists()
    assert not temp_paths[checksum_name(archive)].exists()


def test_publish_downloads_success_cleanup_leaves_replaced_temp(
    backup_dir: Path,
) -> None:
    """Success-path temp cleanup removes only temps this run created.

    Regression: after a successful publication the temporary .part
    paths were unlinked unconditionally, so a writer who replaced a
    .part path with a different inode during publication would have the
    replacement deleted. The cleanup now removes a temp only while it
    still references the inode this run created; a replaced path is
    left in place with a warning.
    """
    if os.name == "nt":
        pytest.skip(
            "Windows publication links the .part pathname, so a temp "
            "replaced before publication fails the identity check "
            "instead of reaching the success-path cleanup"
        )

    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    digests = digests_for(temp_paths)
    downloaded_fds = make_downloaded_fds(temp_paths)

    # Replace the archive .part path with a different inode before
    # publication, as a concurrent writer would. The held descriptor
    # still references the original inode, so publication succeeds; the
    # success-path cleanup must leave the replacement alone. A scratch
    # hard link keeps the original inode named so the publication can
    # link it even on filesystems that refuse to link nameless inodes
    # (tmpfs).
    scratch = backup_dir / "scratch-link"
    os.link(temp_paths[archive], scratch)
    replacement = backup_dir / "replacement"
    replacement.write_bytes(b"other")
    os.replace(replacement, temp_paths[archive])

    local_paths = publish.publish_downloads(
        temp_paths,
        [archive],
        backup_dir,
        digests,
        downloaded_fds,
    )

    assert local_paths[archive] == backup_dir / archive
    assert (backup_dir / archive).read_bytes() == b"payload"
    # The replaced temp is left in place, not deleted.
    assert temp_paths[archive].read_bytes() == b"other"
    # The untouched checksum temp was removed by the cleanup.
    assert not temp_paths[checksum_name(archive)].exists()


@pytest.mark.parametrize(
    "errno_value",
    [
        errno.EINVAL,
        errno.ENOTSUP,
        errno.EOPNOTSUPP,
        errno.ENOSYS,
        errno.EPERM,
        errno.EACCES,
    ],
)
def test_publish_downloads_falls_back_when_linkat_unsupported(
    backup_dir: Path, errno_value: int
) -> None:
    """A POSIX platform without linkat(AT_EMPTY_PATH) still publishes.

    linkat(AT_EMPTY_PATH) is Linux-specific: macOS/BSD reject the flag
    with EINVAL, and some filesystems/kernels return ENOTSUP,
    EOPNOTSUPP, ENOSYS, or a permission error. _publish_no_replace must
    fall back to the no-replace rename on those errors instead of
    failing the whole backup; the renamed file is re-opened no-follow
    and re-identified, so the published inode is still the verified one.
    """
    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    digests = digests_for(temp_paths)

    original_link = publish.link_inode_no_replace

    def unsupported_link(link_fd: int, final_path: Path) -> None:
        raise OSError(
            errno_value,
            os.strerror(errno_value),
            str(final_path),
        )

    with unittest.mock.patch.object(
        publish, "link_inode_no_replace", unsupported_link
    ):
        local_paths = publish.publish_downloads(
            temp_paths,
            [archive],
            backup_dir,
            digests,
            make_downloaded_fds(temp_paths),
        )

    # The rename fallback published the verified bytes under the final
    # names, and the temporary downloads were consumed.
    assert local_paths[archive] == backup_dir / archive
    assert (backup_dir / archive).read_bytes() == b"payload"
    assert (backup_dir / checksum_name(archive)).is_file()
    assert not temp_paths[archive].exists()
    assert not temp_paths[checksum_name(archive)].exists()
    # The fallback must not have been reached through the Windows
    # os.link path: _link_inode_no_replace was the only thing patched.
    assert original_link is publish.link_inode_no_replace


def test_publish_downloads_fallback_closes_replacement_handles(
    backup_dir: Path,
) -> None:
    """The rename fallback's replacement handles are closed after verify.

    Regression: _publish_by_rename returns a fresh handle for the
    renamed file, but _held_temp_downloads only tracks the original
    download handles, so publish_downloads leaked one descriptor per
    artifact whenever linkat(AT_EMPTY_PATH) was unavailable (POSIX
    fallback) or hard links were unsupported (Windows volumes). The
    replacement handles are now tracked and closed after verification.
    Holding a reference across the call must observe them closed: on
the old code they were left to the refcount.
    """
    if os.name != "posix":
        pytest.skip(
            "the linkat fallback is forced by patching a POSIX-only "
            "helper and the scenario is POSIX-specific"
        )

    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    digests = digests_for(temp_paths)
    captured: list[BinaryIO] = []

    def unsupported_link(link_fd: int, final_path: Path) -> None:
        raise OSError(
            errno.EINVAL, os.strerror(errno.EINVAL), str(final_path)
        )

    original_verify = publish.verify_published_inode

    def capturing_verify(
        handle: BinaryIO, final_path: Path, expected_sha256: str
    ) -> None:
        captured.append(handle)
        original_verify(handle, final_path, expected_sha256)

    with unittest.mock.patch.object(
        publish, "link_inode_no_replace", unsupported_link
    ), unittest.mock.patch.object(
        publish, "verify_published_inode", capturing_verify
    ):
        publish.publish_downloads(
            temp_paths,
            [archive],
            backup_dir,
            digests,
            make_downloaded_fds(temp_paths),
        )

    # Every published handle was the fallback's replacement handle, and
    # publish_downloads closed them explicitly: a handle still held by
    # the caller must already be closed rather than waiting on the
    # refcount.
    assert captured
    assert all(handle.closed for handle in captured)


def test_publish_downloads_recheck_rejects_replaced_final(
    backup_dir: Path,
) -> None:
    """A final replaced after its own verification must fail the run.

    Regression: the per-final inode check only covered the instant it
    ran — a final verified early in the loop could be unlinked and
    replaced while the remaining files published, and publish_downloads
    would still report success with a mismatched archive/manifest pair.
    The final all-finals re-check (under the publication lock) now
    rejects any final that no longer references the inode this run
    published, and the run rolls back.

    Skipped on Windows: the held download descriptors prevent the
    replacement there (the scenario is POSIX-specific), and the rollback
    cannot rename an open file on Windows anyway.
    """
    if os.name == "nt":
        pytest.skip(
            "Windows publication holds the temp descriptors open, so a "
            "final cannot be unlinked-and-replaced while they are held; "
            "the scenario is POSIX-specific"
        )

    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    digests = digests_for(temp_paths)

    original_verify = publish.verify_published_inode

    def replacing_verify(
        handle: BinaryIO, final_path: Path, expected_sha256: str
    ) -> None:
        original_verify(handle, final_path, expected_sha256)
        if final_path.name == archive:
            # The archive was just verified; a writer now replaces it
            # with a different inode while the checksum file publishes.
            (backup_dir / archive).unlink()
            (backup_dir / archive).write_bytes(b"attacker-bytes")

    with unittest.mock.patch.object(
        publish, "verify_published_inode", replacing_verify
    ):
        with pytest.raises(
            WPSSHBackupError, match="Refusing to report success"
        ):
            publish.publish_downloads(
                temp_paths,
                [archive],
                backup_dir,
                digests,
                make_downloaded_fds(temp_paths),
            )

    # The attacker's replacement is not this run's inode, so rollback
    # leaves it in place; the checksum final this run created was rolled
    # back; the temps remain for the caller's cleanup.
    assert (backup_dir / archive).read_bytes() == b"attacker-bytes"
    assert not (backup_dir / checksum_name(archive)).exists()
    assert temp_paths[archive].is_file()
    assert temp_paths[checksum_name(archive)].is_file()
    # The publication lock was released even on failure.
    assert not (backup_dir / publish_lock.PUBLISH_LOCK_NAME).exists()


def test_publish_downloads_release_lock_on_success(
    backup_dir: Path,
) -> None:
    """A successful publication releases the exclusive lock."""
    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)

    publish.publish_downloads(
        temp_paths,
        [archive],
        backup_dir,
        digests_for(temp_paths),
        make_downloaded_fds(temp_paths),
    )

    assert not (backup_dir / publish_lock.PUBLISH_LOCK_NAME).exists()


def test_publish_downloads_lock_blocks_concurrent_publish(
    backup_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lock held by a live process fails the run instead of interleaving."""
    import os as _os
    import re

    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    lock = backup_dir / publish_lock.PUBLISH_LOCK_NAME
    # A lock written by a LIVE process (our own PID) must not be stolen.
    lock.write_text(f"{_os.getpid()}\n")
    # Avoid the retry sleeps: the lock is held the whole time.
    monkeypatch.setattr(
        publish_lock, "time", unittest.mock.Mock(sleep=lambda _: None)
    )

    with pytest.raises(
        WPSSHBackupError, match=re.escape("Another backup appears")
    ):
        publish.publish_downloads(
            temp_paths,
            [archive],
            backup_dir,
            digests_for(temp_paths),
            make_downloaded_fds(temp_paths),
        )

    # A lock held by a live process must not be removed.
    assert lock.exists()


def test_publish_downloads_reclaims_stale_lock(
    backup_dir: Path,
) -> None:
    """A lock whose owning PID is dead is reclaimed and the run proceeds.

    Regression: a process killed after os.open succeeded left the
    O_EXCL lock behind, and every later run retried 40 times and failed
    permanently until an administrator deleted the hidden lock. The lock
    records its creator's PID; when that PID is verifiably dead, the
    lock is atomically renamed aside and removed, and publication
    proceeds.
    """
    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    lock = backup_dir / publish_lock.PUBLISH_LOCK_NAME
    # A PID far beyond any valid process range: verifiably dead.
    lock.write_text(f"{2**30}\n")

    publish.publish_downloads(
        temp_paths,
        [archive],
        backup_dir,
        digests_for(temp_paths),
        make_downloaded_fds(temp_paths),
    )

    # The stale lock was reclaimed; the run succeeded and released it.
    assert (backup_dir / archive).exists()
    assert not lock.exists()
    # No .stale- leftovers remain.
    assert not any(
        ".lock.stale-" in p.name for p in backup_dir.iterdir()
    )


def test_try_create_publish_lock_fallback_never_replaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without hard links the lock is created with O_EXCL, never renamed.

    Regression: the no-hard-link fallback used os.rename(tmp, lock),
    which REPLACES an existing destination on POSIX — so a live lock
    could be overwritten and two publishers could run concurrently. The
    fallback now uses O_CREAT|O_EXCL on the lock name itself, a true
    no-replace primitive.
    """
    lock = tmp_path / publish_lock.PUBLISH_LOCK_NAME

    def no_link(src, dst):
        raise OSError(errno.EPERM, "hard links not supported")

    def forbidden_rename(src, dst):
        raise AssertionError(
            "os.rename replaces an existing destination on POSIX; "
            "the lock fallback must use O_CREAT|O_EXCL"
        )

    monkeypatch.setattr(publish_lock.os, "link", no_link)
    monkeypatch.setattr(publish_lock.os, "rename", forbidden_rename)

    # First acquisition succeeds and records the owner.
    identity = publish_lock.try_create_publish_lock(lock)
    assert identity is not None
    assert lock.read_text().strip() == str(os.getpid())

    # A second acquisition must fail and must NOT replace the live lock.
    assert publish_lock.try_create_publish_lock(lock) is None
    assert lock.read_text().strip() == str(os.getpid())
    # The recorded identity still describes the lock on disk.
    st = os.lstat(lock)
    assert (st.st_dev, st.st_ino) == identity


def test_publish_downloads_never_reclaims_unparseable_lock(
    backup_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unparseable lock is never reclaimed on age alone.

    Ownership is recorded atomically (the PID is written to a private
    temp file that is then hard-linked into place), so a lock created by
    this tool is never visible without its owner. An unparseable lock is
    therefore corruption or a foreign file, and reclaiming it on age
    alone could steal a live creator's lock (e.g. one paused between
    create and write). Acquisition must fail and name the admin path.
    """
    import re

    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    lock = backup_dir / publish_lock.PUBLISH_LOCK_NAME
    lock.write_bytes(b"")
    # Even a very old unparseable lock must not be reclaimed.
    old = publish_lock.time.time() - 3600
    import os as _os

    _os.utime(lock, (old, old))
    monkeypatch.setattr(
        publish_lock, "time", unittest.mock.Mock(sleep=lambda _: None)
    )

    with pytest.raises(
        WPSSHBackupError, match=re.escape("Another backup appears")
    ):
        publish.publish_downloads(
            temp_paths,
            [archive],
            backup_dir,
            digests_for(temp_paths),
            make_downloaded_fds(temp_paths),
        )

    # The unparseable lock is left in place for the administrator.
    assert lock.exists()


def test_steal_stale_lock_does_not_steal_new_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale-lock steal must not remove a lock re-created meanwhile.

    Regression: the steal renamed the lock by PATHNAME after an
    unprotected liveness check. Two contenders observing the same dead
    PID could both proceed: one reclaims the old lock and creates a new
    one, then the other renames that NEW (live) lock to its quarantine
    path and unlinks it — both then publish concurrently, defeating the
    lock. The steal is now inode-bound: the lock's inode is captured
    before the rename, and the renamed entry is unlinked only if it is
    still that same inode; a different (newer) lock is restored instead.
    """
    lock = tmp_path / publish_lock.PUBLISH_LOCK_NAME
    # A stale lock owned by a dead PID.
    lock.write_text(f"{2**30}\n")
    original_rename = os.rename

    def rename_new_lock(src, dst):
        if src == lock:
            # Simulate the other contender: it already reclaimed the
            # stale lock and created a NEW live lock at the name, so
            # this process's rename moves the NEW lock, not the stale
            # one it read. The new lock must be a genuinely different
            # inode: unlink+recreate can reuse the freed inode number
            # (ext4/tmpfs), and os.rename cannot replace an existing
            # destination on Windows, so the new lock is written to a
            # separate path and moved over the name with os.replace
            # (a distinct function, unaffected by this monkeypatch).
            fresh = tmp_path / "fresh-lock"
            fresh.write_text(f"{os.getpid()}\n")
            os.replace(fresh, lock)
        return original_rename(src, dst)

    monkeypatch.setattr(publish_lock.os, "rename", rename_new_lock)

    # The steal must refuse: the renamed entry is a NEW live lock (a
    # different inode than the stale one that was read), so it is
    # restored and the name is NOT freed.
    assert publish_lock.steal_stale_lock(lock) is False
    # The new lock is preserved (restored to the name).
    assert lock.exists()
    assert lock.read_text().strip() == str(os.getpid())


def test_steal_stale_lock_restore_does_not_clobber_newer_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Restoring a quarantined lock must never replace a newer lock.

    Regression: after the stale inode was quarantined, the restore used
    os.rename(stale, lock), which REPLACES a lock another contender
    created at the name in the meantime (POSIX rename overwrites). That
    contender would believe it still held the lock while this process
    published. The restore is now a no-replace hard link: when the name
    is already taken, the quarantined entry is left in place and the
    newer lock is untouched.
    """
    lock = tmp_path / publish_lock.PUBLISH_LOCK_NAME
    lock.write_text(f"{2**30}\n")  # stale lock, dead PID
    original_rename = os.rename
    # Distinct contents so the assertion can tell the two contenders
    # apart: the FIRST lock is the one this process's rename moves to
    # the quarantine path; the SECOND is the one that must survive.
    first_pid = os.getpid()
    second_pid = os.getpid() + 1

    def rename_moves_new_lock(src, dst):
        if src == lock:
            # A contender already reclaimed the stale lock and created a
            # NEW lock at the name, so this process's rename moves the
            # NEW lock (a different inode) to the quarantine path.
            first = tmp_path / "contender-lock-1"
            first.write_text(f"{first_pid}\n")
            os.replace(first, lock)
            result = original_rename(src, dst)
            # Before the restore runs, ANOTHER contender takes the name.
            second = tmp_path / "contender-lock-2"
            second.write_text(f"{second_pid}\n")
            os.replace(second, lock)
            return result
        return original_rename(src, dst)

    monkeypatch.setattr(publish_lock.os, "rename", rename_moves_new_lock)

    # Restoring the quarantined lock must fail loudly: the name is taken
    # by a newer lock whose owner may still be publishing, so a normal
    # retry (which would create a lock at the now-free name) is unsafe.
    with pytest.raises(
        WPSSHBackupError, match="Could not restore the publish lock"
    ):
        publish_lock.steal_stale_lock(lock)
    # The contender's lock is untouched and the quarantined entry is
    # left in place for the administrator.
    assert lock.exists()
    assert lock.read_text().strip() == str(second_pid)
    assert any(".quarantine-" in p.name for p in tmp_path.iterdir())


def test_publish_by_rename_publishes_verified_inode(
    tmp_path: Path,
) -> None:
    """The rename fallback publishes the verified bytes and returns a
    handle to the published inode, without a double-close error.

    Regression: the fallback used to close the raw descriptor and then
    close the fdopen wrapper, which on Python raises
    OSError: [Errno 9] Bad file descriptor when the wrapper owns the
    descriptor, aborting every POSIX linkat fallback before the
    publication. The descriptor is now closed exactly once.
    """
    temp = tmp_path / "a.part"
    final = tmp_path / "a"
    temp.write_bytes(b"payload")
    fd = os.open(temp, os.O_RDWR)
    handle = os.fdopen(fd, "rb", closefd=False)
    # The fallback closes the descriptor it consumed on Windows and
    # leaves it open on POSIX (the caller's cleanup closes it). The
    # test does not close it here: on Windows the descriptor number is
    # reused by the re-opened final file, so closing it would close the
    # returned handle's descriptor.
    new_handle = publish.publish_by_rename(handle, temp, final)
    try:
        assert final.read_bytes() == b"payload"
        assert new_handle.read() == b"payload"
    finally:
        new_handle.close()


@pytest.mark.skipif(
    os.name != "posix",
    reason="the linkat fallback and its source-swap race are POSIX",
)
def test_publish_by_rename_rejects_swapped_regular_source(
    tmp_path: Path,
) -> None:
    """A temp path swapped for a different REGULAR file must be rejected.

    Regression: on POSIX the fallback published via os.link(temp_path,
    final_path); if a writer replaced temp_path with a different regular
    file after verification, os.link would link the REPLACEMENT, and the
    final was only checked to be a regular file (never compared against
    the held descriptor's inode). The fallback now compares the
    published descriptor against the held inode and rolls back on
    mismatch, so bytes that were never verified can never be published.
    """
    temp = tmp_path / "a.part"
    final = tmp_path / "a"
    temp.write_bytes(b"verified-payload")
    fd = os.open(temp, os.O_RDWR)
    handle = os.fdopen(fd, "rb", closefd=False)
    # A writer replaces temp_path with a different regular file while
    # the held descriptor still references the verified inode.
    replacement = tmp_path / "replacement.part"
    replacement.write_bytes(b"attacker-bytes")
    os.replace(replacement, temp)

    with pytest.raises(
        WPSSHBackupError, match="was replaced after verification"
    ):
        publish.publish_by_rename(handle, temp, final)
    # The replacement inode was linked into the final name, but it is NOT
    # this run's verified inode, so the rollback leaves it in place
    # rather than deleting another process's file. The run fails instead
    # of publishing unverified bytes under the final name.
    assert final.read_bytes() == b"attacker-bytes"


@pytest.mark.skipif(
    os.name != "nt",
    reason="the rename branch is only reached when os.name is 'nt'",
)
def test_publish_by_rename_rejects_swapped_source_before_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A temp path swapped before the Windows rename must be caught.

    Regression: the Windows fallback closed the held descriptor before
    os.rename(temp_path, final_path); a writer replacing temp_path in
    that close-rename interval would move a REPLACEMENT inode into the
    final backup name, and the original inode was no longer retained for
    comparison. The held inode's identity is now captured before the
    close and the renamed file is compared against it, rolling back on
    mismatch.

    The swap is injected by monkeypatching os.rename: Windows refuses to
    replace a file held open, so the writer's swap can only land in the
    interval AFTER the fallback closes the descriptor and BEFORE the
    rename — exactly the window the fix guards.
    """
    temp = tmp_path / "a.part"
    final = tmp_path / "a"
    temp.write_bytes(b"verified-payload")
    fd = os.open(temp, os.O_RDWR)
    handle = os.fdopen(fd, "rb", closefd=False)

    replacement = tmp_path / "replacement.part"
    replacement.write_bytes(b"attacker-bytes")
    original_rename = os.rename

    def swap_then_rename(src, dst):
        if src == temp:
            # Swap the temp pathname for a different inode just before
            # the fallback's rename moves it into the final name.
            os.replace(replacement, temp)
        return original_rename(src, dst)

    monkeypatch.setattr(publish.os, "rename", swap_then_rename)

    with pytest.raises(
        WPSSHBackupError, match="was replaced after verification"
    ):
        publish.publish_by_rename(handle, temp, final)
    # The replacement inode was moved into the final name, but it is NOT
    # this run's verified inode, so the rollback leaves it in place
    # rather than deleting another process's file. The run fails instead
    # of publishing unverified bytes under the final name.
    assert final.read_bytes() == b"attacker-bytes"


def test_publish_by_rename_refuses_existing_destination(
    tmp_path: Path,
) -> None:
    """A destination that appears after the pre-check is never replaced.

    Regression: on POSIX the fallback used os.rename(), which silently
    replaces an existing destination, so a concurrent backup (or a
    local writer) that created final_path after the pre-check would be
    overwritten. The fallback now uses an atomic no-replace primitive
    (a hard link on POSIX, Windows rename which refuses to replace) and
    fails with FileExistsError instead.
    """
    temp = tmp_path / "a.part"
    final = tmp_path / "a"
    temp.write_bytes(b"payload")
    final.write_bytes(b"existing")
    fd = os.open(temp, os.O_RDWR)
    handle = os.fdopen(fd, "rb", closefd=False)
    with pytest.raises(FileExistsError):
        publish.publish_by_rename(handle, temp, final)
    # The pre-existing destination is untouched and the temp is intact.
    assert final.read_bytes() == b"existing"
    assert temp.read_bytes() == b"payload"


def test_publish_by_rename_reopen_failure_removes_owned_final(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On reopen failure the fallback removes only the entry it created.

    The published entry still references the inode this run created, so
    it is removed to avoid leaving an unverified file under a final
    name.
    """
    temp = tmp_path / "a.part"
    final = tmp_path / "a"
    temp.write_bytes(b"payload")
    fd = os.open(temp, os.O_RDWR)
    handle = os.fdopen(fd, "rb", closefd=False)

    def boom(path: Path, **kwargs: object) -> int:
        raise WPSSHBackupError("cannot reopen")

    monkeypatch.setattr(safe_fs, "open_nofollow_regular", boom)
    with pytest.raises(WPSSHBackupError, match="cannot reopen"):
        publish.publish_by_rename(handle, temp, final)
    assert not final.exists()


def test_publish_by_rename_reopen_failure_leaves_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On reopen failure a replacement at final_path is left in place.

    Regression: the fallback used to unlink final_path unconditionally
    on reopen failure, so a replacement installed by another process
    after the publication would be deleted. The cleanup now removes the
    path only while it still references the inode this run published.
    """
    temp = tmp_path / "a.part"
    final = tmp_path / "a"
    temp.write_bytes(b"payload")
    fd = os.open(temp, os.O_RDWR)
    handle = os.fdopen(fd, "rb", closefd=False)

    def boom(path: Path, **kwargs: object) -> int:
        # Simulate a writer replacing the published entry with a
        # different inode before the re-open fails.
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"other")
        os.replace(replacement, final)
        raise WPSSHBackupError("cannot reopen")

    monkeypatch.setattr(safe_fs, "open_nofollow_regular", boom)
    with pytest.raises(WPSSHBackupError, match="cannot reopen"):
        publish.publish_by_rename(handle, temp, final)
    # The replacement is left in place, not deleted.
    assert final.read_bytes() == b"other"


def test_publish_downloads_refuses_overwrite_of_existing(
    backup_dir: Path,
) -> None:
    """Pre-existing final-name files must be preserved, not overwritten."""
    archive = files_archive_name(TS)
    existing = backup_dir / archive
    existing.write_bytes(b"prior-content")
    temp_paths = make_temp_set(backup_dir, archive)

    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        publish.publish_downloads(
            temp_paths,
            [archive],
            backup_dir,
            digests_for(temp_paths),
            make_downloaded_fds(temp_paths),
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
        publish.publish_downloads(
            temp_paths,
            [archive],
            backup_dir,
            digests_for(temp_paths),
            make_downloaded_fds(temp_paths),
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

    original_publish = publish.publish_no_replace

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
        publish, "publish_no_replace", exploding_publish
    ):
        with pytest.raises(OSError, match="simulated mid-publication"):
            publish.publish_downloads(
                temp_paths,
                [archive1, archive2],
                backup_dir,
                digests_for(temp_paths),
                make_downloaded_fds(temp_paths),
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
    bid2 = "20261014T0931Z-b2c3d4"
    archive1 = files_archive_name(TS)
    archive2 = files_archive_name(bid2)
    temp_paths = make_temp_set(backup_dir, archive1, archive2)

    original_publish = publish.publish_no_replace

    def racing_publish(
        handle: BinaryIO, temp_path: Path, final_path: Path
    ) -> BinaryIO:
        if final_path.name == checksum_name(archive2):
            # Simulate another process creating the final path after
            # the pre-check, just before this run publishes it.
            final_path.write_bytes(b"created-by-other-process")
        return original_publish(handle, temp_path, final_path)

    with unittest.mock.patch.object(
        publish, "publish_no_replace", racing_publish
    ):
        with pytest.raises(FileExistsError, match="Refusing to overwrite"):
            publish.publish_downloads(
                temp_paths,
                [archive1, archive2],
                backup_dir,
                digests_for(temp_paths),
                make_downloaded_fds(temp_paths),
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


def test_publish_downloads_ignores_symlinked_temp(
    backup_dir: Path,
) -> None:
    """A .part path swapped for a symlink cannot change the publication.

    Publication links the held download descriptor's inode (via
    linkat(AT_EMPTY_PATH) on POSIX, or os.link on Windows where the held
    fd blocks the swap), never the pathname. A symlink planted at a
    .part path after download therefore cannot make publication link the
    target's unverified inode; the published bytes remain the verified
    payload, or the run fails cleanly (tmpfs cannot link a nameless
    inode) — the attacker's target is never published.
    """
    import os

    if os.name == "nt":
        pytest.skip("POSIX symlink semantics; Windows holds the fd")

    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    digests = digests_for(temp_paths)
    victim = backup_dir / "victim"
    victim.write_bytes(b"target-bytes")
    # Hand the download descriptors over first (as the download does),
    # then swap the archive .part pathname for a symlink to a victim.
    downloaded_fds = make_downloaded_fds(temp_paths)
    temp_paths[archive].unlink()
    temp_paths[archive].symlink_to(victim)

    try:
        local_paths = publish.publish_downloads(
            temp_paths,
            [archive],
            backup_dir,
            digests,
            downloaded_fds,
        )
    except Exception:
        # The held archive inode was made nameless by the unlink; some
        # filesystems (tmpfs) cannot link a nameless inode, so the run
        # is rolled back. The attacker's bytes must never be published.
        assert not (backup_dir / archive).exists()
        assert not (backup_dir / checksum_name(archive)).exists()
        return

    # The published archive is the verified payload, not the symlink
    # target's bytes.
    assert (backup_dir / archive).read_bytes() == b"payload"
    assert victim.read_bytes() == b"target-bytes"
    assert (backup_dir / checksum_name(archive)).is_file()
    assert local_paths[archive] == backup_dir / archive


def test_publish_downloads_rejects_temp_replaced_before_publication(
    backup_dir: Path,
) -> None:
    """A .part replaced before publication must not change the publication.

    A writer who can write BACKUP_DIR can replace a verified .part
    pathname with different bytes before publication. Publication
    links the held download descriptor's inode (never the pathname), so
    a replacement path cannot be published: the published bytes remain
    the verified ones, or the run fails cleanly (tmpfs cannot link a
    nameless inode). On Windows the held descriptor prevents the
    replacement from taking effect at all. The attacker's bytes never
    reach a final name.
    """
    import os

    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    digests = digests_for(temp_paths)

    # Simulate a writer replacing the verified .part pathname with
    # different bytes before publication. The held descriptors still
    # reference the verified inode (they were opened before the swap).
    # On Windows the held descriptor blocks the unlink entirely.
    downloaded_fds = make_downloaded_fds(temp_paths)
    try:
        temp_paths[archive].unlink()
        temp_paths[archive].write_bytes(b"attacker-bytes")
    except PermissionError:
        # Windows: cannot unlink a held-open file. The replacement
        # cannot take effect, which is the same guarantee.
        pass

    try:
        local_paths = publish.publish_downloads(
            temp_paths,
            [archive],
            backup_dir,
            digests,
            downloaded_fds,
        )
    except Exception:
        # The held archive inode was made nameless by the unlink; some
        # filesystems (tmpfs) cannot link a nameless inode, so the run
        # is rolled back. The attacker's bytes must not be published.
        assert not (backup_dir / archive).exists()
        assert not (backup_dir / checksum_name(archive)).exists()
        return

    # The published bytes are the verified payload (linked from the held
    # inode), and the attacker's replacement never appears under a final
    # name.
    assert (backup_dir / archive).read_bytes() == b"payload"
    assert local_paths[checksum_name(archive)] == (
        backup_dir / checksum_name(archive)
    )

    # If the replacement took effect (POSIX, non-tmpfs), its bytes
    # remain on disk only at the .part path (now a different inode than
    # the published one); the checksum .part is gone (its inode was
    # published and the temp unlinked). If it did not (Windows), the
    # .part still holds the published payload inode.
    if os.name != "nt" and temp_paths[archive].exists():
        assert temp_paths[archive].read_bytes() == b"attacker-bytes"


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows refuses to unlink a file this process holds open",
)
def test_publish_downloads_publishes_held_inode_not_pathname(
    backup_dir: Path,
) -> None:
    """A .part swapped after it was opened can never publish attacker bytes.

    The download handed its descriptor over before the swap, so the
    digest re-check and the link both reference the held inode: a
    writer who replaces the .part pathname after it was opened cannot
    make publication link the replacement inode. What happens instead
    depends on how the swap was performed and the filesystem:

    - If the verified inode still has a name (no unlink), the held
      inode is linked and the digest re-check passes: the published
      bytes are the verified ones.
    - If a writer unlinked the verified inode (making it nameless),
      linkat(AT_EMPTY_PATH) fails (ENOENT on tmpfs), publication aborts
      and the run is rolled back.

    In every case the final name never contains the attacker's bytes.

    Skipped on Windows: the held descriptor itself prevents the
    replacement there (the file cannot be unlinked while open), so the
    scenario is POSIX-specific.
    """
    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    digests = digests_for(temp_paths)
    downloaded_fds = make_downloaded_fds(temp_paths)

    original_publish = publish.publish_no_replace

    def replacing_publish(
        handle: BinaryIO, temp_path: Path, final_path: Path
    ) -> BinaryIO:
        if temp_path.name == archive + ".part":
            # Simulate a writer replacing the verified .part pathname
            # after publication opened it: the path now points at
            # different bytes, while the held descriptors still
            # reference the verified inode.
            temp_path.unlink()
            temp_path.write_bytes(b"attacker-bytes")
        return original_publish(handle, temp_path, final_path)

    with unittest.mock.patch.object(
        publish, "publish_no_replace", replacing_publish
    ):
        # Publication either succeeds with the verified bytes (ext4 and
        # other filesystems that can link the still-named inode) or
        # fails safely (tmpfs: the unlinked inode cannot be linked, so
        # the run is rolled back). Regardless of which happens, the
        # attacker's bytes never appear at the final name.
        try:
            backups = publish.publish_downloads(
                temp_paths,
                [archive],
                backup_dir,
                digests,
                downloaded_fds,
            )
        except Exception:
            # Any failure here must leave the final names clean and the
            # run rolled back (handled by publish_downloads), never a
            # file containing attacker bytes.
            assert not (backup_dir / archive).exists()
            assert not (backup_dir / checksum_name(archive)).exists()
            return

    final_archive = backups[archive]
    if final_archive.exists():
        assert final_archive.read_bytes() == b"payload"


def test_publish_downloads_rejects_final_replaced_during_verification(
    backup_dir: Path,
) -> None:
    """A final path replaced while the digest is re-read must fail.

    The digest re-check hashes the held inode, which says nothing about
    what the final name contains: the final directory entry can be
    unlinked and replaced between the identity check and the digest
    re-read, leaving an attacker-controlled file at the published name
    while the call reports success. The entry is re-checked against the
    held inode after hashing, so the replacement is rejected.
    """
    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    digests = digests_for(temp_paths)

    original_assert = publish.assert_published_inode

    def replacing_after_first_check(handle: BinaryIO, final_path: Path):
        original_assert(handle, final_path)
        if final_path.name == archive:
            # Simulate a writer unlinking the published file and
            # planting different bytes at the final name after the
            # first identity check, before the digest re-read.
            final_path.unlink()
            final_path.write_bytes(b"attacker-bytes")

    with unittest.mock.patch.object(
        publish, "assert_published_inode", replacing_after_first_check
    ):
        with pytest.raises(
            WPSSHBackupError, match="was replaced after verification"
        ):
            publish.publish_downloads(
                temp_paths,
                [archive],
                backup_dir,
                digests,
                make_downloaded_fds(temp_paths),
            )

    # The replacement is not this run's verified inode, so rollback
    # leaves it in place with a warning instead of unlinking a file
    # this run did not create.
    assert (backup_dir / archive).read_bytes() == b"attacker-bytes"
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
    archive = files_archive_name(TS)
    temp_paths = make_temp_set(backup_dir, archive)
    digests = digests_for(temp_paths)

    original_publish = publish.publish_no_replace

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
        publish, "publish_no_replace", mutating_publish
    ):
        with pytest.raises(ChecksumError, match="changed after verification"):
            publish.publish_downloads(
                temp_paths,
                [archive],
                backup_dir,
                digests,
                make_downloaded_fds(temp_paths),
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


def test_run_backup_cleanup_preserves_replaced_temp(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    """Cleanup must not unlink a .part replaced by another run's file.

    _discard_temp_downloads() records the inode each download created
    and removes the path only while it still refers to that inode. If a
    concurrent writer replaces the .part pathname after the transfer
    fails, the replacement is a different inode and must be left in
    place with a warning, never unlinked.
    """
    path = tmp_path / "wp-files-20261014T0930Z.tar.gz.part"
    path.write_bytes(b"this-run-bytes")
    identity = (os.stat(path).st_dev, os.stat(path).st_ino)
    # A concurrent writer replaces the pathname with a different inode.
    # unlink+write_bytes can reuse the freed inode on some filesystems
    # (ext4), so the replacement is staged at a fresh path and renamed
    # over the original — a guaranteed different inode.
    replacement = tmp_path / "replacement.part"
    replacement.write_bytes(b"other-run-bytes")
    os.replace(replacement, path)

    backup._discard_temp_downloads([(path, identity)])

    # The replacement is preserved, with a warning.
    assert path.exists()
    assert path.read_bytes() == b"other-run-bytes"
    warning = capsys.readouterr().err
    assert "WARNING:" in warning
    assert "replaced by another file" in warning
    assert str(path) in warning


def test_unlink_if_same_inode_atomic_restore_preserves_new_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A file that reappears at path after the claim is never overwritten.

    Regression: restoring a replaced path used os.rename(quarantine,
    path), which replaces any file a concurrent process created at path
    after the claim — deleting another process's file during cleanup.
    The restore is now a no-replace hard link, so the newcomer is
    preserved and the quarantined entry is left in place with a warning
    instead of overwriting it.
    """
    path = tmp_path / "wp-files-x.tar.gz.part"
    path.write_bytes(b"this-run-bytes")
    identity = (os.stat(path).st_dev, os.stat(path).st_ino)
    # A concurrent writer replaces the pathname with a different inode.
    replacement = tmp_path / "replacement.part"
    replacement.write_bytes(b"other-run-bytes")
    os.replace(replacement, path)

    original_rename = os.rename

    def renaming(src, dst):
        original_rename(src, dst)
        if Path(src) == path and ".quarantine-" in Path(dst).name:
            # After the path is claimed for quarantine, another process
            # creates a fresh file at the original pathname.
            newcomer = tmp_path / "newcomer.part"
            newcomer.write_bytes(b"newcomer-bytes")
            os.replace(newcomer, path)

    monkeypatch.setattr(os, "rename", renaming)
    safe_fs.unlink_if_same_inode_atomic(path, identity)

    # The newcomer created after the claim is preserved, not clobbered
    # by the restore of the quarantined replacement.
    assert path.exists()
    assert path.read_bytes() == b"newcomer-bytes"
    # The quarantined replacement was left in place rather than deleted.
    quarantined = [
        p for p in tmp_path.iterdir() if ".quarantine-" in p.name
    ]
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == b"other-run-bytes"
    warning = capsys.readouterr().err
    assert "WARNING:" in warning
    assert "could not restore replaced" in warning
    assert str(path) in warning


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
    original_unlink = os.unlink
    attempted: list[Path] = []

    def getfo(remote_path, local_file):
        original_getfo(remote_path, local_file)
        if failure == "transfer":
            raise original_error
        if remote_path.endswith(".sha256"):
            local_file.seek(0)
            local_file.write(b"\xff")

    def unlink(path, *, dir_fd=None):
        # Cleanup claims a path by renaming it to a unique quarantine
        # name first, so the unlink is attempted on the quarantine
        # name, not the original pathname. Simulate a cleanup failure
        # for the archive's quarantine entry.
        attempted.append(Path(path))
        if archive.name in Path(path).name:
            raise PermissionError("cleanup denied")
        return original_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(client.sftp, "getfo", getfo)
    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", unlink)
        expected = (
            paramiko.SSHException if failure == "transfer" else ChecksumError
        )
        with pytest.raises(expected) as caught:
            backup.run_backup(
                client, make_config(tmp_path),
                include_files=True, include_database=False, bid=TS,
            )

    if failure == "transfer":
        assert caught.value is original_error
    else:
        assert "not valid UTF-8" in str(caught.value)
        assert any(
            checksum_name(files_archive_name(TS)) + ".part" in p.name
            for p in attempted
        )
    # The archive's temporary file is still there, restored under its
    # original name: the cleanup could not unlink it, so it is put back
    # rather than stranded under the quarantine name. The quarantine
    # link may linger as well, because removing it is the very
    # operation that failed.
    assert archive.exists()
    leftovers = [
        p for p in backup_dir.iterdir() if ".quarantine-" in p.name
    ]
    assert set(backup_dir.iterdir()) - set(leftovers) == {archive}
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
