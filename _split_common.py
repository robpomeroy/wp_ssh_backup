"""Split common.py into focused modules.

Each new module owns one or more sections of the old file. The section
bodies are copied verbatim; only the docstring and imports are new.

common.py is then rewritten as a re-export facade so every existing
"from common import X" keeps working.

Run from the repo root:  python _split_common.py
"""

import re
import sys
from pathlib import Path

COMMON = Path("common.py")
BANNER = re.compile(
    r"^# -{20,}\n^# (?P<title>[^\n]+)\n^# -{20,}\n",
    re.MULTILINE,
)

# module name -> (docstring, imports, [section titles])
MODULES = {
    "errors.py": (
        "Exception types raised by WP SSH Backup.\n\n"
        "Every error the tool raises derives from :class:`WPSSHBackupError`,\n"
        "so a caller can catch the whole family with one except clause and\n"
        "still distinguish the individual failure modes when it needs to.\n",
        "",
        ["Errors"],
    ),
    "config.py": (
        "Loading and validation of the tool's configuration.\n\n"
        "The configuration is read from a .env file and the process\n"
        "environment, validated, and frozen into a :class:`Config` value\n"
        "object. Nothing else in the tool reads the environment directly.\n",
        "import os\n"
        "from dataclasses import dataclass\n"
        "from pathlib import Path\n\n"
        "from errors import ConfigError\n",
        ["Configuration"],
    ),
    "shell.py": (
        "Quoting for remote shell commands.\n\n"
        "A path that reaches the remote host is attacker-influenced data:\n"
        "it can contain spaces, quotes and shell metacharacters. These\n"
        "helpers quote it so the remote shell receives it as exactly one\n"
        "argument, whatever it contains.\n",
        "",
        [],
    ),
    "host_keys.py": (
        "Host key fingerprints and known_hosts entries.\n\n"
        "The fingerprint is the value an administrator compares out of\n"
        "band before trusting a host key, and the known_hosts entry is\n"
        "the line written to the trust store.\n",
        "import base64\n"
        "import hashlib\n\n"
        "import paramiko\n",
        [],
    ),
    "naming.py": (
        "Timestamps, backup identifiers and artifact file names.\n\n"
        "Every artifact name the tool produces is derived here, so the\n"
        "naming scheme is described in exactly one place.\n",
        "import posixpath\n"
        "import secrets\n"
        "from datetime import datetime, timezone\n",
        ["Timestamps and file naming"],
    ),
    "checksums.py": (
        "SHA-256 checksums of local files and of remote manifests.\n\n"
        "The manifest parsing is strict: a malformed or duplicated\n"
        "record is an error rather than something to skip, because a\n"
        "manifest that silently loses entries cannot be trusted to\n"
        "describe an archive.\n",
        "import hashlib\n"
        "import re\n"
        "from pathlib import Path\n\n"
        "from errors import ChecksumError\n",
        ["Checksums", "Checksum manifests"],
    ),
    "retention.py": (
        "The backup sets held locally, and the retention policy.\n\n"
        "A set is the group of files that share one backup identifier:\n"
        "the archive, its checksum manifest, and the database archive\n"
        "when the run included one.\n",
        "import re\n"
        "from datetime import datetime, timedelta, timezone\n"
        "from pathlib import Path\n\n"
        "from naming import (\n"
        "    BACKUP_ID_PATTERN,\n"
        "    backup_id_from_archive_name,\n"
        "    parse_backup_id,\n"
        ")\n",
        ["Local backup sets and retention"],
    ),
    "wp_config.py": (
        "Parsing wp-config.php on the remote host.\n\n"
        "The parser reads the define() calls that carry the database\n"
        "settings, without executing any PHP and without a full PHP\n"
        "grammar: it only needs to find the DB_* constants and their\n"
        "values.\n",
        "import posixpath\n"
        "import re\n\n"
        "import paramiko\n\n"
        "from errors import MissingArtifactError\n"
        "from remote import read_remote_file, remote_path_exists\n",
        ["wp-config.php parsing"],
    ),
    "db_config.py": (
        "The MySQL option file that carries the database credentials.\n\n"
        "The password never appears on a command line: it is written to\n"
        "an owner-only option file that mysqldump and mysql read through\n"
        "--defaults-extra-file.\n",
        "import posixpath\n\n"
        "import paramiko\n\n"
        "from errors import ConfigError\n"
        "from remote import write_remote_file\n"
        "from wp_config import read_wp_db_settings\n",
        ["MySQL option file (credential hardening)",
         "Database credentials on the remote host"],
    ),
    "remote.py": (
        "SSH and SFTP transport.\n\n"
        "The transport layer: opening a connection to a trusted host,\n"
        "running a command, and moving files over SFTP. Everything here\n"
        "is concerned with the wire, not with what the commands mean.\n",
        "import threading\n"
        "from pathlib import Path\n\n"
        "import paramiko\n\n"
        "from config import Config\n"
        "from errors import (\n"
        "    RemoteCommandError,\n"
        "    UnknownHostKeyError,\n"
        "    WPSSHBackupError,\n"
        ")\n"
        "from shell import shquote\n",
        ["SSH", "SFTP"],
    ),
    "remote_ops.py": (
        "Remote operations that the backup and restore flows share.\n\n"
        "These build on the transport layer: they create and remove\n"
        "remote directories, locate the wp CLI, and clean up after a\n"
        "run whether it succeeded or failed.\n",
        "import posixpath\n"
        "import sys\n\n"
        "import paramiko\n\n"
        "from config import Config\n"
        "from errors import WPSSHBackupError\n"
        "from naming import backup_id, staging_dir_for\n"
        "from remote import run_remote_cmd, run_remote_cmd_checked\n"
        "from shell import shquote\n",
        ["Higher-level remote helpers shared by backup and restore"],
    ),
    "cli.py": (
        "Shared command-line helpers for the WP SSH Backup entry points.\n\n"
        "authorize_host.py, backup.py and restore.py all build an argparse\n"
        "parser and all offer the same version flag; backup.py and restore.py\n"
        "also offer the same mutually exclusive scope flags. The helpers\n"
        "here keep those definitions in one place so the three programs\n"
        "cannot drift apart.\n",
        "import argparse\n"
        "import time\n"
        "from collections.abc import Generator\n"
        "from contextlib import contextmanager\n\n"
        "from version import __version__\n",
        [],
    ),
}

# Functions that live in the "Misc" section but belong with a specific
# module. The name is the function; the value is the target module.
MISC_MOVES = {
    "shquote": "shell.py",
    "trap_rm_action": "shell.py",
    "fingerprint": "host_keys.py",
    "known_hosts_entry": "host_keys.py",
}

# The two remaining Misc helpers move into cli.py, which already exists
# and is the natural home for presentation helpers.
MISC_TO_CLI = {"human_size", "timed"}

# The "Misc" section also holds the module docstring's helper imports;
# the facade in common.py re-exports everything.


def split_sections(text):
    matches = list(BANNER.finditer(text))
    out = {}
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        out[m.group("title")] = text[start:end]
    return out


def split_functions(body):
    """Split a section body into (preamble, [(name, source), ...])."""
    lines = body.split("\n")
    # The preamble is everything before the first top-level def/class.
    first = None
    for i, line in enumerate(lines):
        if re.match(r"^(def |class |@)", line):
            first = i
            break
    if first is None:
        return body, []

    preamble = "\n".join(lines[:first]).rstrip() + "\n"

    # Each function is a top-level def/class plus any decorators.
    starts = []
    for i, line in enumerate(lines):
        if re.match(r"^(def |class )", line):
            starts.append(i)

    funcs = []
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
        # Trim trailing blank lines from the block.
        block = lines[start:end]
        while block and block[-1].strip() == "":
            block.pop()
        funcs.append((re.match(r"^(?:def|class) (\w+)", block[0]).group(1),
                      "\n".join(block)))
    return preamble, funcs


def main():
    text = COMMON.read_text(encoding="utf-8")
    sections = split_sections(text)

    mapped = {t for v in MODULES.values() for t in v[3]}
    unknown = set(sections) - mapped - {"Misc"}
    if unknown:
        raise SystemExit(f"unmapped sections: {sorted(unknown)}")

    misc_preamble, misc_funcs = split_functions(sections["Misc"])

    # Distribute the Misc functions.
    misc_to_module = {}
    for name, source in misc_funcs:
        if name in MISC_MOVES:
            misc_to_module.setdefault(MISC_MOVES[name], []).append(
                (name, source)
            )
        elif name in MISC_TO_CLI:
            misc_to_module.setdefault("cli.py", []).append((name, source))
        else:
            raise SystemExit(f"unmapped Misc function: {name}")

    if "--write" not in sys.argv:
        for title, body in sections.items():
            target = next(
                (m for m, v in MODULES.items() if title in v[3]), "common.py"
            )
            print(f"{title:55} -> {target}")
        print()
        for module, items in misc_to_module.items():
            print(f"Misc -> {module:12} {[n for n, _ in items]}")
        return

    # --- Build each module's body ------------------------------------
    bodies: dict[str, list[str]] = {name: [] for name in MODULES}

    for module, (docstring, imports, titles) in MODULES.items():
        if docstring is None:
            continue
        bodies[module].append(f'"""{docstring}"""')
        bodies[module].append("")
        bodies[module].append("from __future__ import annotations")
        bodies[module].append("")
        if imports:
            bodies[module].append(imports.rstrip())
            bodies[module].append("")

    for module, (docstring, imports, titles) in MODULES.items():
        for title in titles:
            body = sections[title]
            preamble, funcs = split_functions(body)
            chunk = []
            if preamble.strip():
                # Drop the banner comment; the module docstring covers it.
                chunk.append(preamble.strip())
                chunk.append("")
            chunk.extend(src for _, src in funcs)
            bodies[module].append("\n\n".join(chunk).rstrip())
            bodies[module].append("")

    for module, items in misc_to_module.items():
        chunk = "\n\n".join(src for _, src in items)
        bodies[module].append(chunk)
        bodies[module].append("")

    for module, parts in bodies.items():
        if not parts:
            continue
        if module == "cli.py":
            append_to_cli(parts)
            continue
        content = "\n".join(parts).rstrip() + "\n"
        Path(module).write_text(content, encoding="utf-8", newline="\r\n")
        print(f"wrote {module} ({len(content.splitlines())} lines)")

    write_facade(text)


def append_to_cli(parts):
    """Add the moved helpers to the existing cli.py.

    cli.py already exists with its own imports, __all__ and functions.
    The two helpers that move there (human_size, timed) are appended,
    and their names are added to __all__.
    """
    path = Path("cli.py")
    text = path.read_text(encoding="utf-8")
    source = text.replace("\r\n", "\n")

    # The functions to add are the last two chunks of the body.
    funcs = []
    for part in parts:
        if part.strip().startswith('"""'):
            continue
        if part.strip().startswith("import ") or part.strip().startswith(
            "from "
        ):
            continue
        if part.strip():
            funcs.append(part.rstrip())

    # Merge the new imports into the existing import block.
    new_imports = (
        "import time\n"
        "from collections.abc import Generator\n"
        "from contextlib import contextmanager\n"
    )
    source = source.replace(
        "import argparse\n",
        "import argparse\n" + new_imports,
        1,
    )

    # Extend __all__.
    source = source.replace(
        '__all__ = [\n    "add_scope_arguments",',
        '__all__ = [\n    "add_scope_arguments",\n'
        '    "human_size",',
        1,
    )
    source = source.replace(
        '    "resolve_scope",\n',
        '    "resolve_scope",\n    "timed",\n',
        1,
    )

    source = source.rstrip() + "\n\n\n" + "\n\n".join(funcs) + "\n"

    path.write_text(source, encoding="utf-8", newline="\r\n")
    print(f"appended to cli.py ({len(funcs)} helpers)")


def write_facade(old_text):
    """Rewrite common.py as a re-export facade."""
    exported = collect_exports()
    lines = [
        '"""Shared helpers for WP SSH Backup.',
        "",
        "The implementations live in focused modules:",
        "",
        "- :mod:`errors` -- the exception types",
        "- :mod:`config` -- loading and validating the configuration",
        "- :mod:`remote` -- the SSH and SFTP transport",
        "- :mod:`remote_ops` -- remote operations shared by both flows",
        "- :mod:`wp_config` -- parsing wp-config.php",
        "- :mod:`db_config` -- the MySQL option file",
        "- :mod:`naming` -- timestamps, identifiers and file names",
        "- :mod:`checksums` -- SHA-256 checksums and manifests",
        "- :mod:`retention` -- local backup sets and retention",
        "- :mod:`shell` -- quoting for remote shell commands",
        "- :mod:`host_keys` -- fingerprints and known_hosts entries",
        "",
        "This module re-exports them, so existing imports keep working.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
    ]
    for module, names in exported.items():
        lines.append(f"from {module} import (")
        for name in names:
            lines.append(f"    {name},")
        lines.append(")")
    lines.append("")
    lines.append("__all__ = [")
    for names in exported.values():
        for name in names:
            lines.append(f'    "{name}",')
    lines.append("]")
    lines.append("")

    COMMON.write_text(
        "\n".join(lines), encoding="utf-8", newline="\r\n"
    )
    print(f"wrote common.py (facade)")


def collect_exports():
    """The public names each module exports."""
    return {
        "errors": [
            "ChecksumError",
            "ConfigError",
            "MissingArtifactError",
            "RemoteCommandError",
            "UnknownHostKeyError",
            "WPSSHBackupError",
        ],
        "config": ["Config", "load_config"],
        "remote": [
            "connect",
            "read_remote_file",
            "remote_path_exists",
            "run_remote_cmd",
            "run_remote_cmd_checked",
            "sftp_download",
            "write_remote_file",
        ],
        "remote_ops": [
            "allocate_remote_dir",
            "create_staging_dir",
            "detect_wp_cli",
            "remove_remote_file",
            "remove_remote_staging",
        ],
        "wp_config": ["parse_wp_config", "read_wp_db_settings"],
        "db_config": [
            "mysql_client_config",
            "read_db_settings",
            "split_db_host",
            "write_mysql_client_config",
        ],
        "naming": [
            "backup_id",
            "backup_id_from_archive_name",
            "checksum_name",
            "db_archive_name",
            "files_archive_name",
            "parse_backup_id",
            "parse_timestamp",
            "staging_dir_for",
            "utc_timestamp",
        ],
        "checksums": [
            "parse_sha256sum_output",
            "sha256_file",
            "validate_manifest_entries",
            "verify_local_checksum",
        ],
        "retention": ["find_backup_sets", "prune_local_backups"],
        "shell": ["shquote", "trap_rm_action"],
        "host_keys": ["fingerprint", "known_hosts_entry"],
        "cli": ["human_size", "timed"],
    }


if __name__ == "__main__":
    main()
