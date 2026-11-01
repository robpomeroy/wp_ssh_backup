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
import hashlib
import subprocess
import sys
import uuid
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

# The image the Linux binary is built in.
#
# PyInstaller does not bundle the C library: the executable links
# against whatever glibc the build machine has, and fails to start on
# anything older. The official python:3.10 images are named after the
# distribution they come from, so this one fixes the floor at the
# glibc of Debian 10 (2.28). That covers Debian 10 and later, and
# Ubuntu 20.04 and later.
#
# The image is pinned by tag so the glibc floor cannot silently rise
# when the tag moves.
LINUX_BUILD_IMAGE = "python:3.10-buster"
LINUX_BUILD_GLIBC = "2.28"


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


def write_checksums(paths: list[Path], suffix: str | None) -> Path:
    """Write a SHA-256 checksum file for the built executables.

    The file is written here rather than in the workflow because the
    checksum command differs between platforms: GNU coreutils provides
    "sha256sum" on Linux, BSD provides "shasum -a 256" on macOS, and
    PowerShell has neither. Hashing in Python works everywhere and
    produces the same output format on all of them, so a user can
    check the file with whichever tool they have.

    Args:
        paths: The executables to checksum.
        suffix: The platform suffix, used in the file name, or None.

    Returns:
        The path of the checksum file that was written.
    """
    name = f"wp-ssh-backup-{suffix}" if suffix else "wp-ssh-backup"
    checksum_path = DIST_DIR / f"{name}.sha256"

    lines = []
    for path in sorted(paths):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")

    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return checksum_path


def build_in_container(suffix: str) -> None:
    """Build the executables inside a Linux container.

    The build runs in a container so the glibc floor of the resulting
    binary is set by the image rather than by whichever runner
    happened to build it. See LINUX_BUILD_IMAGE.

    The source and the results travel as a tar stream through a
    named volume, rather than as a bind mount of the checkout: a bind
    mount of a network share is not visible inside the container.

    Args:
        suffix: The platform suffix for the executable names.
    """
    print(f"Building in {LINUX_BUILD_IMAGE} (glibc {LINUX_BUILD_GLIBC})...")

    script = (
        "set -e\n"
        "cd /work/proj\n"
        "python -m pip install -r requirements.txt "
        "'pyinstaller>=6.0,<7.0'\n"
        "python build_executables.py --suffix " + suffix + "\n"
    )

    # The script is delivered inside the archive, so it travels with
    # the source.
    script_path = WORK_DIR / "container_build.sh"
    script_path.parent.mkdir(parents=True, exist_ok=True)
    # newline="" keeps the line endings as written. A carriage return
    # left at the end of a line would become part of the argument it
    # ends, and the executable would be built with a stray \r in its
    # name.
    script_path.write_text(script, encoding="utf-8", newline="\n")

    # A fresh volume per run, so nothing left behind by an earlier
    # run can be picked up as if it were part of this build.
    volume = "wpssh-build-" + uuid.uuid4().hex[:12]
    try:
        _build_in_container(volume, suffix)
    finally:
        subprocess.run(
            ["docker", "volume", "rm", "-f", volume],
            check=False,
        )


def _build_in_container(volume: str, suffix: str) -> None:
    """Build in the given container volume.

    Args:
        volume: The name of the Docker volume to use.
        suffix: The platform suffix for the executable names.
    """
    tar = subprocess.Popen(
        ["tar", "-cf", "-", "--exclude=./venv", "--exclude=./dist",
         "--exclude=./.git", "--exclude=./__pycache__",
         "."],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
    )
    docker = subprocess.Popen(
        [
            "docker",
            "run",
            "--rm",
            "-i",
            "-v",
            volume + ":/work",
            LINUX_BUILD_IMAGE,
            "bash",
            "-c",
            "mkdir -p /work/proj /work/out-dist && "
            "tar -xf - -C /work/proj && "
            "cd /work/proj && bash build/container_build.sh && "
            "cp -f dist/* /work/out-dist/",
        ],
        stdin=tar.stdout,
    )
    if tar.stdout is not None:
        tar.stdout.close()
    docker_code = docker.wait()
    tar_code = tar.wait()
    if tar_code != 0 or docker_code != 0:
        raise SystemExit(
            f"container build failed (tar={tar_code}, docker={docker_code})"
        )

    # Copy the results back out of the volume as a tar stream, which
    # avoids a bind mount of the checkout: a bind mount of a network
    # share is not visible inside the container.
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    copy = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            volume + ":/work",
            LINUX_BUILD_IMAGE,
            "tar", "-cf", "-", "-C", "/work/out-dist", ".",
        ],
        stdout=subprocess.PIPE,
        check=True,
    )
    # The archive is rooted at ".", so the members have "./" in front
    # of them; --strip-components=1 removes it.
    subprocess.run(
        [
            "tar",
            "-xf",
            "-",
            "-C",
            str(DIST_DIR),
            "--strip-components=1",
        ],
        input=copy.stdout,
        check=True,
    )


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
    parser.add_argument(
        "--container",
        action="store_true",
        help=(
            "Build in a Linux container instead of on this machine. "
            "Use this for the Linux binary: it pins the glibc floor "
            "of the result."
        ),
    )
    args = parser.parse_args(argv)

    if args.container:
        build_in_container(args.suffix or "linux-x64")
        return 0

    built: list[Path] = []
    for script, name in TARGETS:
        built.append(build(script, name, args.suffix))

    print()
    print("Verifying the executables...")
    for path in built:
        verify(path)

    checksum_path = write_checksums(built, args.suffix)

    print()
    print("Built:")
    for path in built:
        size_mb = path.stat().st_size / 1024 / 1024
        print(f"  {path}  ({size_mb:.1f} MB)")
    print(f"  {checksum_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
