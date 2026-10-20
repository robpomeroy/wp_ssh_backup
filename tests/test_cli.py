"""Tests for the version number, the changelog and the CLI helpers."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import authorize_host
import backup
import restore
from cli import (
    add_scope_arguments,
    add_version_argument,
    resolve_scope,
    version_string,
)
from version import __version__

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = PROJECT_ROOT / "CHANGELOG.md"

ENTRY_POINTS = [
    (authorize_host, "authorize_host.py"),
    (backup, "backup.py"),
    (restore, "restore.py"),
]


def test_version_is_a_dotted_release_number() -> None:
    """The version must be a plain dotted number the CLI can print."""
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)


def test_changelog_documents_the_current_version() -> None:
    """The changelog must document the version the programs report.

    A version bump that forgets the changelog would otherwise ship
    silently; this test keeps the two in step.
    """
    text = CHANGELOG.read_text(encoding="utf-8")
    assert f"## [{__version__}]" in text


def test_changelog_follows_keep_a_changelog() -> None:
    """The changelog must keep the Keep a Changelog structure."""
    text = CHANGELOG.read_text(encoding="utf-8")
    assert text.startswith("# Changelog")
    assert "Keep a Changelog" in text
    assert "## [Unreleased]" in text


@pytest.mark.parametrize(("module", "prog"), ENTRY_POINTS)
def test_entry_point_reports_its_version(
    module, prog: str, capsys: pytest.CaptureFixture
) -> None:
    """--version prints the program name and version, then exits 0."""
    with pytest.raises(SystemExit) as caught:
        module.main(["--version"])

    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == f"{prog} {__version__}"


@pytest.mark.parametrize(("module", "prog"), ENTRY_POINTS)
def test_entry_point_accepts_short_version_flag(
    module, prog: str, capsys: pytest.CaptureFixture
) -> None:
    """-v is an accepted spelling of --version."""
    with pytest.raises(SystemExit) as caught:
        module.main(["-v"])

    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == f"{prog} {__version__}"


def test_version_string_uses_the_prog_name() -> None:
    """version_string() composes the program name and the version."""
    assert version_string("backup.py") == f"backup.py {__version__}"


def test_add_version_argument_uses_the_parser_prog() -> None:
    """The flag reports the parser's own program name."""
    import argparse

    parser = argparse.ArgumentParser(prog="custom.py")
    add_version_argument(parser)
    assert parser.prog == "custom.py"


def test_resolve_scope_defaults_to_both() -> None:
    """No scope flag means both the files and the database."""
    import argparse

    parser = argparse.ArgumentParser()
    add_scope_arguments(
        parser,
        files_help="f",
        database_help="d",
        all_help="a",
    )
    args = parser.parse_args([])
    assert resolve_scope(args) == (True, True)


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--files"], (True, False)),
        (["--database"], (False, True)),
        (["--all"], (True, True)),
    ],
)
def test_resolve_scope_honours_each_flag(
    argv: list[str], expected: tuple[bool, bool]
) -> None:
    """Each scope flag selects exactly what it names."""
    import argparse

    parser = argparse.ArgumentParser()
    add_scope_arguments(
        parser,
        files_help="f",
        database_help="d",
        all_help="a",
    )
    args = parser.parse_args(argv)
    assert resolve_scope(args) == expected


def test_scope_flags_are_mutually_exclusive() -> None:
    """--files and --database cannot be combined."""
    import argparse

    parser = argparse.ArgumentParser()
    add_scope_arguments(
        parser,
        files_help="f",
        database_help="d",
        all_help="a",
    )
    with pytest.raises(SystemExit) as caught:
        parser.parse_args(["--files", "--database"])
    assert caught.value.code == 2
