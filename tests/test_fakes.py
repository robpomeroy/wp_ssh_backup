"""Tests for the fake SSH/SFTP layer's fidelity to paramiko.

These assert the fakes raise the same exceptions paramiko would in the
situations the backup/restore flows rely on for their error handling.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeSSHClient


def test_sftp_open_missing_read_path_raises() -> None:
    """open(path, 'rb') on a missing file must raise like paramiko SFTP."""
    client = FakeSSHClient("/home/user/public_html")

    with pytest.raises(FileNotFoundError):
        client.open_sftp().open("/no/such/file", "rb")


def test_sftp_open_missing_manifest_hits_missing_file_branch(
    tmp_path: object,
) -> None:
    """A missing remote manifest must surface as FileNotFoundError."""
    client = FakeSSHClient("/home/user/public_html")

    sftp = client.open_sftp()
    with pytest.raises(FileNotFoundError):
        with sftp.open("/staging/wp-db-x.tar.gz.sha256", "rb"):
            pass  # pragma: no cover - never entered


def test_sftp_open_write_mode_creates_new_file(tmp_path: object) -> None:
    """Write mode must still create files that do not yet exist."""
    client = FakeSSHClient("/home/user/public_html")
    sftp = client.open_sftp()

    with sftp.open("/staging/new.cnf", "wb") as handle:
        handle.write(b"[client]\n")

    assert client.remote_fs["/staging/new.cnf"] == b"[client]\n"
