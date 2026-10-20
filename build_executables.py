"""Build the standalone executables for the three entry points.

Each entry point becomes a single-file executable that bundles the
interpreter, paramiko and everything else it needs, so a user can
download one file and run it without installing Python.

The build is identical on every platform; PyInstaller picks the right
format for the host. The output lands in dist/.

Usage:
    python build_executables.py                  # dist/wp-ssh-backup[.exe]
    python build_executables.py --suffix linux-x64

With a suffix, the executables are named for the platform they were
built on, which is what the release workflow attaches to a release:

    dist/wp-ssh-backup-linux-x64
    dist/wp-ssh-backup-windows-x64.exe
    dist/wp-ssh-backup-macos-arm64
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

# The entry point script, and the name of the executable built from it.
TARGETS = [
    ("backup.py", "wp-ssh-backup"),
    ("restore.py", "wp-ssh-backup-restore"),
    ("authorize_host.py", "wp-ssh-backup-authorize-host"),
]

# paramiko pulls these in as hard dependencies (bcrypt, cryptography
# and pynacl back its key types). PyInstaller's paramiko hook finds
# them, but they are listed explicitly so a hook change cannot
# silently produce a binary that cannot import them. An import that
# fails only at run time -- on the user's machine, with no Python to
# debug it with -- is exactly the failure this avoids.
HIDDEN_IMPORTS = [
    "bcrypt",
    "nacl",
    "cryptography",
    "paramiko",
    "dotenv",
]

# Where PyInstaller puts its intermediate files. Keeping the .spec
# files out of the project root stops them cluttering the checkout.
WORK_DIR = PROJECT_ROOT / "build"
DIST_DIR = PROJECT_ROOT / "dist"
SPEC_DIR = WORK_DIR / "spec"


def executable_name(name: str, suffix: str | None) -> str:
    """Return the file name of the built executable for this platform.

    Args:
        name: The base name, e.g. "wp-ssh-backup".
        suffix: The platform suffix, e.g. "linux-x64", or None for the
            plain name.

    Returns:
        The file name, with the .exe extension on Windows.
    """
    extension = ".exe" if sys.platform == "win32" else ""
    if suffix:
        return f"{name}-{suffix}{extension}"
    return f"{name}{extension}"


def build(script: str, name: str, suffix: str | None) -> Path:
    """Build one executable with PyInstaller.

    Args:
        script: The entry point script to bundle.
        name: The base name of the executable.
        suffix: The platform suffix, or None for the plain name.

    Returns:
        The path of the built executable.
    """
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--name",
        executable_name(name, suffix),
        "--clean",
        "--noconfirm",
        "--log-level",
        "WARN",
        "--distpath",
        str(DIST_DIR),
        "--workpath",
        str(WORK_DIR),
        "--specpath",
        str(SPEC_DIR),
        # UPX is not used. It is not installed on the build machines
        # and a mangled binary is a hard problem to diagnose.
        "--noupx",
    ]
    for module in HIDDEN_IMPORTS:
        command += ["--hidden-import", module]
    command.append(script)

    print(f"Building {executable_name(name, suffix)} from {script}...")
    subprocess.run(command, cwd=PROJECT_ROOT, check=True)

    path = DIST_DIR / executable_name(name, suffix)
    if not path.is_file():
        raise SystemExit(f"expected {path} to exist after the build")
    return path


def verify(path: Path) -> None:
    """Run the built executable's --version to prove it starts.

    A binary that cannot import one of its dependencies fails only
    when it is run, so the build is not finished until the executable
    has actually run.
    """
    result = subprocess.run(
        [str(path), "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    print(f"  {result.stdout.strip()}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the standalone WP SSH Backup executables.",
    )
    parser.add_argument(
        "--suffix",
        help=(
            "Platform suffix for the executable names, e.g. 'linux-x64' "
            "or 'macos-arm64'. Omit for the plain names."
        ),
    )
    args = parser.parse_args(argv)

    built: list[Path] = []
    for script, name in TARGETS:
        built.append(build(script, name, args.suffix))

    print()
    print("Verifying the executables...")
    for path in built:
        verify(path)

    print()
    print("Built:")
    for path in built:
        size_mb = path.stat().st_size / 1024 / 1024
        print(f"  {path}  ({size_mb:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
