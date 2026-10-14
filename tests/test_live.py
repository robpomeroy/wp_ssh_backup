"""Opt-in live tests against a real host.

These tests are skipped unless BOTH conditions hold:
  * the environment variable WP_SSH_BACKUP_LIVE_TEST is set to 1, and
  * a valid .env file exists (they use the real configuration).

Run with:  WP_SSH_BACKUP_LIVE_TEST=1 pytest tests/test_live.py
"""

from __future__ import annotations

import os
import posixpath
from pathlib import Path

import pytest

from common import (
    checksum_name,
    connect,
    files_archive_name,
    load_config,
    run_remote_cmd_checked,
    shquote,
    sha256_file,
    staging_dir_for,
    utc_timestamp,
    verify_local_checksum,
)

pytestmark = pytest.mark.live

LIVE_ENABLED = os.getenv("WP_SSH_BACKUP_LIVE_TEST") == "1"


def live_config():
    return load_config()


@pytest.fixture()
def live_client():
    if not LIVE_ENABLED:
        pytest.skip("WP_SSH_BACKUP_LIVE_TEST not set to 1")
    config = live_config()
    client = connect(config)
    yield client, config
    client.close()


def test_live_connection(live_client) -> None:
    client, _config = live_client
    out = run_remote_cmd_checked(client, "echo ok")
    assert out.strip() == "ok"


def test_live_backup_and_restore_round_trip(
    live_client, tmp_path: Path
) -> None:
    """Full backup -> verify -> restore into a scratch directory."""
    client, config = live_client
    ts = utc_timestamp()
    staging = staging_dir_for(config.wp_site_root, ts)

    # A scratch directory to restore into, so the live site is untouched.
    scratch_parent = posixpath.dirname(config.wp_site_root)
    scratch = posixpath.join(scratch_parent, "restore-scratch")
    run_remote_cmd_checked(client, f"mkdir -p {shquote(scratch)}")

    try:
        # --- Backup -------------------------------------------------------
        run_remote_cmd_checked(client, f"mkdir -p {shquote(staging)}")
        archive = files_archive_name(ts)
        run_remote_cmd_checked(
            client,
            f"tar czf {shquote(posixpath.join(staging, archive))} "
            f"-C {shquote(config.wp_site_root)} . "
            f"--exclude=./wp-content/cache",
            timeout=3600,
        )
        run_remote_cmd_checked(
            client,
            f"cd {shquote(staging)} && "
            f"sha256sum {shquote(archive)} "
            f"> {shquote(checksum_name(archive))}",
        )

        # Download and verify locally.
        local_archive = tmp_path / archive
        checksum_local = tmp_path / checksum_name(archive)
        with client.open_sftp() as sftp:
            sftp.get(posixpath.join(staging, archive), str(local_archive))
            sftp.get(
                posixpath.join(staging, checksum_name(archive)),
                str(checksum_local),
            )
        digest = checksum_local.read_text().split()[0]
        verify_local_checksum(local_archive, digest)
        assert sha256_file(local_archive) == digest

        # --- Restore into scratch -----------------------------------------
        with client.open_sftp() as sftp:
            sftp.put(
                str(local_archive),
                posixpath.join(staging, "scratch.tar.gz"),
            )
        run_remote_cmd_checked(
            client,
            f"tar xzf {shquote(posixpath.join(staging, 'scratch.tar.gz'))} "
            f"-C {shquote(scratch)}",
            timeout=3600,
        )
        listing = run_remote_cmd_checked(client, f"ls {shquote(scratch)}")
        assert listing.strip(), "scratch directory should not be empty"
    finally:
        run_remote_cmd_checked(client, f"rm -rf {shquote(scratch)}")
        run_remote_cmd_checked(client, f"rm -rf {shquote(staging)}")
