"""Tests for the executable build script.

The build script is what produces the release binaries, so the parts
that can be checked without a full PyInstaller run are checked here:
the file names it produces and the checksum file it writes.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

import build_executables


def test_executable_name_without_a_suffix() -> None:
    """Without a suffix the name is the plain program name."""
    expected = "wp-ssh-backup.exe" if sys.platform == "win32" else "wp-ssh-backup"
    assert build_executables.executable_name("wp-ssh-backup", None) == expected


def test_executable_name_with_a_suffix() -> None:
    """With a suffix the platform is part of the name."""
    expected = (
        "wp-ssh-backup-linux-x64.exe"
        if sys.platform == "win32"
        else "wp-ssh-backup-linux-x64"
    )
    assert (
        build_executables.executable_name("wp-ssh-backup", "linux-x64")
        == expected
    )


def test_executable_name_appends_the_suffix_before_the_extension() -> None:
    """The .exe extension stays last, so Windows runs the file."""
    name = build_executables.executable_name("wp-ssh-backup", "windows-x64")
    assert name.startswith("wp-ssh-backup-windows-x64")
    assert name.endswith(".exe" if sys.platform == "win32" else "-windows-x64")


def test_write_checksums_lists_every_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The checksum file names each executable and its digest."""
    monkeypatch.setattr(build_executables, "DIST_DIR", tmp_path)

    first = tmp_path / "wp-ssh-backup-linux-x64"
    second = tmp_path / "wp-ssh-backup-restore-linux-x64"
    first.write_bytes(b"first")
    second.write_bytes(b"second")

    path = build_executables.write_checksums(
        [first, second], "linux-x64"
    )

    assert path.name == "wp-ssh-backup-linux-x64.sha256"
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    # The format is the one sha256sum and shasum both produce, so the
    # file can be checked with either tool.
    for line, target in zip(lines, [first, second], strict=True):
        digest, name = line.split("  ", 1)
        assert name == target.name
        assert digest == hashlib.sha256(target.read_bytes()).hexdigest()


def test_write_checksums_orders_the_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The entries are sorted, so the file is the same every run."""
    monkeypatch.setattr(build_executables, "DIST_DIR", tmp_path)

    names = ["wp-ssh-backup-c-linux-x64", "wp-ssh-backup-a-linux-x64"]
    paths = []
    for name in names:
        target = tmp_path / name
        target.write_bytes(name.encode("utf-8"))
        paths.append(target)

    path = build_executables.write_checksums(paths, "linux-x64")
    listed = [
        line.split("  ", 1)[1]
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert listed == sorted(names)


def test_write_checksums_without_a_suffix_uses_the_plain_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A build without a suffix writes wp-ssh-backup.sha256."""
    monkeypatch.setattr(build_executables, "DIST_DIR", tmp_path)

    target = tmp_path / "wp-ssh-backup"
    target.write_bytes(b"data")

    path = build_executables.write_checksums([target], None)
    assert path.name == "wp-ssh-backup.sha256"


def test_linux_build_image_is_pinned() -> None:
    """The Linux build image is pinned by tag.

    The image decides the glibc floor of the Linux executable, because
    PyInstaller does not bundle the C library. A floating tag would
    let the floor rise without anyone noticing, and the executable
    would stop starting on the systems the project supports.
    """
    image = build_executables.LINUX_BUILD_IMAGE
    assert ":" in image, f"{image} is not pinned to a specific tag"
    tag = image.rsplit(":", 1)[1]
    assert tag not in ("latest", "stable"), f"{image} floats"
    # The tag names the distribution, which is what sets the glibc.
    assert "buster" in tag or "bullseye" in tag or "bookworm" in tag


def test_linux_build_glibc_is_the_documented_floor() -> None:
    """The documented glibc floor matches the build image.

    The README tells users which systems the Linux executable runs on.
    That claim has to follow from the image the binary is built in, or
    the documentation is a guess.
    """
    # Debian 10 (buster) ships glibc 2.28, Debian 11 (bullseye) 2.31
    # and Debian 12 (bookworm) 2.36.
    expected = {
        "buster": "2.28",
        "bullseye": "2.31",
        "bookworm": "2.36",
    }
    tag = build_executables.LINUX_BUILD_IMAGE.rsplit(":", 1)[1]
    for distribution, glibc in expected.items():
        if distribution in tag:
            assert build_executables.LINUX_BUILD_GLIBC == glibc
            return
    raise AssertionError(
        f"{tag} names no distribution this test knows the glibc of"
    )
