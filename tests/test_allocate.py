"""Tests for allocate_remote_dir (exclusive remote directory allocation)."""

from __future__ import annotations

import posixpath

import pytest

from common import (
    WPSSHBackupError,
    allocate_remote_dir,
    backup_id,
    parse_backup_id,
    staging_dir_for,
)
from tests.fakes import FakeSSHClient

SITE_ROOT = "/home/user/public_html"


def test_allocate_returns_sibling_with_prefix_and_fresh_id() -> None:
    client = FakeSSHClient(SITE_ROOT)

    path = allocate_remote_dir(client, SITE_ROOT, "restore-scratch-")

    parent = posixpath.dirname(SITE_ROOT)
    assert path.startswith(parent + "/restore-scratch-")
    suffix = path.rsplit("-", 1)[-1]
    # Name embeds a fresh backup id: timestamp + 6 hex chars.
    assert len(suffix) == 6
    int(suffix, 16)


def test_allocate_creates_directory_with_bare_mkdir() -> None:
    client = FakeSSHClient(SITE_ROOT)

    path = allocate_remote_dir(client, SITE_ROOT, "wp-ssh-backup-staging-")

    mkdir_commands = [c for c in client.commands if c.startswith("mkdir ")]
    assert len(mkdir_commands) == 1
    assert "mkdir -p" not in mkdir_commands[0]
    assert path in mkdir_commands[0]


def test_allocate_retries_on_collision_with_new_id() -> None:
    client = FakeSSHClient(SITE_ROOT)
    calls: list[str] = []
    original_mkdir = client._mkdir

    def counting_mkdir(command: str, stderr: object) -> int:
        calls.append(command)
        if len(calls) == 1:
            # First attempt collides (directory already exists).
            client.directories.add(
                command.split("'")[1].rstrip("/")
            )
        return original_mkdir(command, stderr)

    client._mkdir = counting_mkdir  # type: ignore[method-assign]

    path = allocate_remote_dir(client, SITE_ROOT, "scratch-")

    assert len(calls) == 2
    # The two attempts used different ids.
    first = calls[0].split("'")[1]
    second = calls[1].split("'")[1]
    assert first != second
    assert path == second


def test_allocate_gives_up_after_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeSSHClient(SITE_ROOT)
    # Force every attempt to derive the same candidate directory, which
    # already exists — so every bare mkdir collides.
    fixed_bid = backup_id()
    fixed_path = posixpath.join(
        posixpath.dirname(SITE_ROOT), "scratch-" + fixed_bid
    )
    client.directories.add(fixed_path)
    monkeypatch.setattr(
        "common.backup_id", lambda now=None: fixed_bid
    )

    with pytest.raises(WPSSHBackupError, match="exclusive remote directory"):
        allocate_remote_dir(client, SITE_ROOT, "scratch-", attempts=3)

    # All attempts targeted the same, colliding directory.
    mkdir_commands = [c for c in client.commands if c.startswith("mkdir ")]
    assert len(mkdir_commands) == 3
    assert len({c.split("'")[1] for c in mkdir_commands}) == 1


def test_allocate_rejects_prefix_with_slash() -> None:
    client = FakeSSHClient(SITE_ROOT)

    with pytest.raises(WPSSHBackupError, match="must not contain"):
        allocate_remote_dir(client, SITE_ROOT, "bad/prefix")


def test_allocated_dir_is_exclusive_between_two_allocations() -> None:
    client = FakeSSHClient(SITE_ROOT)

    first = allocate_remote_dir(client, SITE_ROOT, "scratch-")
    second = allocate_remote_dir(client, SITE_ROOT, "scratch-")

    assert first != second


def test_allocated_id_parses_as_backup_id() -> None:
    client = FakeSSHClient(SITE_ROOT)

    path = allocate_remote_dir(client, SITE_ROOT, "scratch-")

    suffix = posixpath.basename(path)[len("scratch-"):]
    parsed = parse_backup_id(suffix)
    assert parsed.tzinfo is not None


def test_staging_dir_for_matches_allocated_staging_shape() -> None:
    """The allocator's staging names mirror staging_dir_for's layout."""
    bid = backup_id()
    expected = staging_dir_for(SITE_ROOT, bid)
    assert posixpath.basename(expected) == "wp-ssh-backup-staging-" + bid
