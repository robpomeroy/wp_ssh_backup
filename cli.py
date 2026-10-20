"""Shared command-line helpers for the WP SSH Backup entry points.

authorize_host.py, backup.py and restore.py all build an argparse parser
and all offer the same version flag; backup.py and restore.py also offer
the same mutually exclusive scope flags. The helpers here keep those
definitions in one place so the three programs cannot drift apart.
"""

from __future__ import annotations

import argparse
import time
from collections.abc import Generator
from contextlib import contextmanager

from version import __version__

__all__ = [
    "add_scope_arguments",
    "human_size",
    "add_version_argument",
    "resolve_scope",
    "timed",
    "version_string",
]


def version_string(prog: str) -> str:
    """Return the text printed for --version.

    Args:
        prog: The program name shown to the user.

    Returns:
        The program name, a space and the version number.
    """
    return f"{prog} {__version__}"


def add_version_argument(parser: argparse.ArgumentParser) -> None:
    """Add the -v/--version flag to a parser.

    The flag prints the program name and version to stdout and exits with
    status 0 (argparse's standard "version" action), so it works the same
    way whether the program is run directly or through a wrapper.

    Args:
        parser: The parser to add the flag to.
    """
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=version_string(parser.prog),
        help="Show the program version and exit.",
    )


def add_scope_arguments(
    parser: argparse.ArgumentParser,
    *,
    files_help: str,
    database_help: str,
    all_help: str,
) -> None:
    """Add the --files/--database/--all group to a parser.

    The three flags are mutually exclusive; when none is given both the
    files and the database are included, which is the documented default
    (see resolve_scope).

    Args:
        parser: The parser to add the group to.
        files_help: Help text for --files.
        database_help: Help text for --database.
        all_help: Help text for --all.
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--files",
        action="store_true",
        help=files_help,
    )
    group.add_argument(
        "--database",
        action="store_true",
        help=database_help,
    )
    group.add_argument(
        "--all",
        action="store_true",
        help=all_help,
    )


def resolve_scope(args: argparse.Namespace) -> tuple[bool, bool]:
    """Resolve the scope flags into (include_files, include_database).

    Args:
        args: The parsed namespace holding the scope flags.

    Returns:
        A tuple of (include_files, include_database). When no scope flag
        was given, both are True.
    """
    neither = not (args.files or args.database)
    include_files = args.files or args.all or neither
    include_database = args.database or args.all or neither
    return include_files, include_database


def human_size(num_bytes: int | float) -> str:
    """
    Convert a size in bytes to a human-readable string with appropriate units.

    Args:
        num_bytes: The size in bytes.

    Returns:
        A human-readable string representing the size.
    """
    size = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


@contextmanager
def timed(label: str) -> Generator[None, None, None]:
    """Time a block of work and report how long it took.

    The message is printed only when the block completed successfully.
    The print sits after the yield, so it runs when the `with` block
    exits normally; if the block raises, the exception is thrown in at
    the yield point and the completion message is never printed. A
    failed operation is therefore never reported as having finished.

    Args:
        label: What the block does, e.g. "Files extracted".

    Yields:
        None, while the block runs.
    """
    started = time.monotonic()
    yield
    print(f"{label} ({time.monotonic() - started:.1f}s).")
