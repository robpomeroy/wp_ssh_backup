"""The single source of truth for the WP SSH Backup version number.

Every entry point (authorize_host.py, backup.py, restore.py) reports this
version, and the CHANGELOG.md file at the project root must document it. A
test asserts that the two cannot drift apart.
"""

from __future__ import annotations

__version__ = "0.1.0"
__version_info__ = tuple(int(part) for part in __version__.split("."))
