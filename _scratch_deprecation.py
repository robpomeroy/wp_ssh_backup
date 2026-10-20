"""Scratch file: does Pylance still flag the Generator form?

Both forms are declared here so the result is unambiguous: if only the
Iterator form is flagged, the Generator form is fine and the
common.py / safe_fs.py diagnostics are stale.
"""

from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager


@contextmanager
def uses_iterator() -> Iterator[None]:
    yield


@contextmanager
def uses_generator() -> Generator[None, None, None]:
    yield
