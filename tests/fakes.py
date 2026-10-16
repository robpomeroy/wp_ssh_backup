"""A fake SSH/SFTP layer for orchestration tests.

FakeSSHClient simulates a remote Linux host well enough to exercise the backup
and restore flows: it interprets the specific commands the tool issues (mkdir,
rm, tar, sha256sum, wp/mysqldump/mysql) against an in-memory filesystem, and
FakeSFTPClient moves bytes between that filesystem and local disk.
"""

from __future__ import annotations

import fnmatch
import hashlib
import io
import posixpath
import re
import shlex
import tarfile


class FakeSFTPClient:
    """Moves file content between the fake remote FS and local paths."""

    def __init__(self, remote_fs: dict[str, bytes]) -> None:
        self.remote_fs = remote_fs
        self.modes: dict[str, int] = {}

    def __enter__(self) -> "FakeSFTPClient":
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    def close(self) -> None:
        pass

    def stat(self, path: str) -> object:
        if path not in self.remote_fs:
            raise FileNotFoundError(path)
        return object()

    def open(self, path: str, mode: str = "rb"):
        if "w" in mode or "a" in mode:
            return _FakeWriteFile(self, path)
        if path not in self.remote_fs:
            # Paramiko SFTP raises for a missing file; returning an empty
            # stream would send callers down the wrong error branch (e.g.
            # an empty manifest instead of a missing one).
            raise FileNotFoundError(path)
        return _FakeReadFile(self.remote_fs[path])

    def chmod(self, path: str, mode: int) -> None:
        self.modes[path] = mode

    def get(self, remote_path: str, local_path: str) -> None:
        if remote_path not in self.remote_fs:
            raise FileNotFoundError(remote_path)
        from pathlib import Path

        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as handle:
            handle.write(self.remote_fs[remote_path])

    def getfo(self, remote_path: str, local_file: object) -> None:
        """Mirror paramiko's getfo: stream remote bytes into a file object."""
        if remote_path not in self.remote_fs:
            raise FileNotFoundError(remote_path)
        local_file.write(self.remote_fs[remote_path])

    def put(self, local_path: str, remote_path: str) -> None:
        with open(local_path, "rb") as handle:
            self.remote_fs[remote_path] = handle.read()


class _FakeReadFile:
    def __init__(self, data: bytes | None) -> None:
        self._data = data

    def __enter__(self) -> "_FakeReadFile":
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    def read(self) -> bytes:
        return self._data if self._data is not None else b""


class _FakeWriteFile:
    def __init__(self, owner: FakeSFTPClient, path: str) -> None:
        self._owner = owner
        self._path = path
        self._buffer = io.BytesIO()

    def __enter__(self) -> "_FakeWriteFile":
        return self

    def __exit__(self, *exc: object) -> None:
        self._owner.remote_fs[self._path] = self._buffer.getvalue()

    def write(self, data: bytes) -> int:
        return self._buffer.write(data)


class FakeSSHClient:
    """Interprets the remote commands issued by backup.py / restore.py."""

    def __init__(self, site_root: str, wp_cli: str | None = None) -> None:
        self.remote_fs: dict[str, bytes] = {}
        self.sftp = FakeSFTPClient(self.remote_fs)
        self.site_root = site_root
        self.wp_cli = wp_cli
        self.commands: list[str] = []
        self.fail_on: dict[str, int] = {}
        self.directories: set[str] = set()
        self.directory_modes: dict[str, int] = {}
        # Host-key simulation: the key the "server" presents, and the set of
        # fingerprints the "client" already trusts.
        self.server_key: object | None = None
        self.trusted_fingerprints: set[str] = set()
        self.connect_calls: list[dict] = []
        # Verbose-listing type letter for contiguous (CONTTYPE) members.
        # GNU tar 1.35 prints 'C'; other tar implementations may print '-'.
        self.contiguous_listing_kind = "C"

    # -- paramiko API -------------------------------------------------------

    def open_sftp(self) -> FakeSFTPClient:
        return self.sftp

    def close(self) -> None:
        pass

    def load_system_host_keys(self) -> None:
        pass

    def load_host_keys(self, filename: str) -> None:
        pass

    def set_missing_host_key_policy(self, policy: object) -> None:
        self._policy = policy

    def connect(self, **kwargs: object) -> None:
        """Simulate the host-key check performed by paramiko.connect()."""
        self.connect_calls.append(kwargs)
        if self.server_key is None:
            return
        import paramiko

        from common import fingerprint

        fp = fingerprint(self.server_key)  # type: ignore[arg-type]
        if fp not in self.trusted_fingerprints:
            # Same message paramiko's RejectPolicy raises.
            raise paramiko.SSHException(
                "Server {!r} not found in known_hosts".format("fake")
            )

    def exec_command(self, command: str, timeout: float | None = None):
        self.commands.append(command)
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        exit_code = self._execute(command, stdout, stderr)
        return (
            _ChannelWriter(),
            _Stream(stdout, exit_code),
            _Stream(stderr, exit_code),
        )

    # -- command interpretation --------------------------------------------

    def _execute(
        self, command: str, stdout: io.BytesIO, stderr: io.BytesIO
    ) -> int:
        for pattern, code in self.fail_on.items():
            if pattern in command:
                stderr.write(f"simulated failure for {pattern}\n".encode())
                return code

        # Strip a leading "cd '<dir>' && " prefix, remembering the directory
        # so relative paths in sha256sum commands can be resolved.
        cwd: str | None = None
        compound = re.match(
            r"^cd\s+'([^']+)'\s+&&\s+(.*)$", command, re.DOTALL
        )
        if compound:
            cwd = compound.group(1)
            command = compound.group(2)

        # Split compound commands on top-level ' && ' (outside single
        # quotes) and run each part, stopping at the first failure like
        # a real shell would (mkdir X && chmod 700 X, trap ... EXIT && ...).
        parts = _split_compound(command)
        if len(parts) > 1:
            for part in parts:
                code = self._execute(part, stdout, stderr)
                if code != 0:
                    return code
            return 0

        if command.startswith("mkdir ") and not command.startswith(
            "mkdir -p "
        ):
            return self._mkdir(command, stderr)
        if command.startswith("mkdir -p "):
            return self._mkdir_p(command)
        if command.startswith("chmod "):
            return self._chmod(command, stderr)
        if command.startswith("trap "):
            # Registering an EXIT handler is a no-op here; the cleanup the
            # trap would perform is covered by the explicit rm -f calls.
            return 0
        if command.startswith("rm -rf "):
            return self._rm_rf(command)
        if command.startswith("rm -f "):
            return self._rm_f(command)
        if command.startswith("test -x "):
            return 0 if self.wp_cli else 1
        if command == "tar --version":
            return self._tar_version(command, stdout, stderr)
        if command.startswith("command -v "):
            if self.wp_cli:
                stdout.write(f"{self.wp_cli}\n".encode())
                return 0
            return 1
        if re.search(r"\bsha256sum\b", command) and " -c " in command:
            return self._sha256sum_check(command, stderr, cwd)
        if re.search(r"\bsha256sum\b", command):
            return self._sha256sum_generate(command, stdout, stderr, cwd)
        if command.startswith("tar czf "):
            return self._tar_create(command, stderr)
        if command.startswith("tar xzf "):
            return self._tar_extract(command, stderr)
        if re.search(r"^tar\s+.*\s-tvzf\s", command):
            return self._tar_list(command, stdout, stderr, verbose=True)
        if re.search(r"^tar\s+.*\s-tzf\s", command):
            return self._tar_list(command, stdout, stderr, verbose=False)
        if re.search(r"^find\s+", command) and "-type l" in command:
            return self._find_type_l(command, stdout, stderr)
        if "mysqldump" in command:
            return self._mysqldump(command, stderr)
        if (
            re.search(r"\bmysql\b", command)
            and "defaults-extra-file" in command
        ):
            return self._mysql(command, stderr)
        if re.search(r"\bwp\b.*\bdb export\b", command):
            return self._wp_db_export(command, stderr)
        if re.search(r"\bwp\b.*\bdb import\b", command):
            return 0
        stderr.write(f"unrecognised command: {command}\n".encode())
        return 127

    # -- individual commands ------------------------------------------------

    def _tar_version(
        self, command: str, stdout: io.BytesIO, stderr: io.BytesIO
    ) -> int:
        """tar --version: GNU tar by default; tests may override."""
        stdout.write(b"tar (GNU tar) 1.35\n")
        return 0

    def _quoted(self, command: str) -> list[str]:
        return re.findall(r"'([^']*)'", command)

    def _mkdir(self, command: str, stderr: io.BytesIO) -> int:
        """Bare mkdir: fails if the directory already exists."""
        target = re.search(r"mkdir\s+(?:-m\s+\d{3,4}\s+)?'([^']+)'", command)
        if target:
            path = target.group(1).rstrip("/")
            if path in self.directories:
                stderr.write(
                    f"mkdir: cannot create directory {path!r}: "
                    "File exists\n".encode()
                )
                return 1
            self.directories.add(path)
            mode = re.search(r"-m\s+(\d{3,4})", command)
            if mode:
                self.directory_modes[path] = int(mode.group(1), 8)
        return 0

    def _chmod(self, command: str, stderr: io.BytesIO) -> int:
        """chmod NNN <path>: record the requested mode for the directory."""
        match = re.search(r"chmod\s+([0-7]{3,4})\s+'([^']+)'", command)
        if match:
            path = match.group(2).rstrip("/")
            if path not in self.directories:
                stderr.write(
                    f"chmod: cannot access {path!r}: No such file "
                    "or directory\n".encode()
                )
                return 1
            self.directory_modes[path] = int(match.group(1), 8)
        return 0

    def _mkdir_p(self, command: str) -> int:
        target = re.search(r"mkdir -p\s+'([^']+)'", command)
        if target:
            self.directories.add(target.group(1).rstrip("/"))
        return 0

    def _rm_rf(self, command: str) -> int:
        target = re.search(r"rm -rf\s+'([^']+)'", command)
        if target:
            prefix = target.group(1).rstrip("/") + "/"
            for path in [p for p in self.remote_fs if p.startswith(prefix)]:
                del self.remote_fs[path]
            self.directories.discard(target.group(1).rstrip("/"))
        return 0

    def _rm_f(self, command: str) -> int:
        for target in re.findall(r"rm -f\s+'([^']+)'", command):
            self.remote_fs.pop(target, None)
        return 0

    def _tar_create(self, command: str, stderr: io.BytesIO) -> int:
        quoted = self._quoted(command)
        archive_path = quoted[0]
        if "-C" in command:
            cwd = quoted[1]
            member = quoted[2] if len(quoted) > 2 else "."
        else:
            cwd = posixpath.dirname(archive_path)
            member = "."
        # GNU tar treats options after the member operand as positional:
        # they have no effect and it exits with status 2. Reproduce that
        # so a mis-ordered command fails here exactly as it would on the
        # real host.
        exclude_matches = list(re.finditer(r"--exclude=(\S+)", command))
        if command.rstrip().endswith(" ."):
            member_pos = command.rfind(" .")
        elif quoted:
            member_pos = command.rfind(quoted[-1])
        else:
            member_pos = len(command)
        for match in exclude_matches:
            if match.start() > member_pos:
                stderr.write(
                    "tar: The following options were used after non-option "
                    "arguments. These options are positional and affect "
                    "only arguments that follow them. Please, rearrange "
                    "them properly.\n".encode()
                )
                stderr.write(
                    f"tar: --exclude {match.group(1)} has no effect\n".encode()
                )
                return 2
        # Honour --exclude patterns like GNU tar: a member is left out
        # when its name matches the pattern, or when the pattern names a
        # directory the member lives under.
        excludes = [match.group(1) for match in exclude_matches]

        def excluded(name: str) -> bool:
            for pattern in excludes:
                pat = pattern.lstrip("./").rstrip("/")
                if fnmatch.fnmatch(name, pat) or name.startswith(pat + "/"):
                    return True
            return False

        members = {
            name: data
            for name, data in self._members_for(cwd, member).items()
            if not excluded(name)
        }
        if not members and member != ".":
            stderr.write(f"tar: {member}: not found\n".encode())
            return 1
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        self.remote_fs[archive_path] = buffer.getvalue()
        return 0

    def _members_for(self, cwd: str, member: str) -> dict[str, bytes]:
        prefix = cwd.rstrip("/") + "/"
        if member == ".":
            return {
                path[len(prefix):]: data
                for path, data in self.remote_fs.items()
                if path.startswith(prefix)
            }
        full = posixpath.join(cwd, member)
        if full in self.remote_fs:
            return {member: self.remote_fs[full]}
        return {}

    def _tar_extract(self, command: str, stderr: io.BytesIO) -> int:
        quoted = self._quoted(command)
        archive_path = quoted[0]
        cwd = quoted[1] if "-C" in command else posixpath.dirname(archive_path)
        if archive_path not in self.remote_fs:
            stderr.write(f"tar: {archive_path}: not found\n".encode())
            return 1
        try:
            with tarfile.open(
                fileobj=io.BytesIO(self.remote_fs[archive_path]), mode="r:gz"
            ) as tar:
                for member in tar.getmembers():
                    if member.issym() or member.islnk():
                        # Record the link like the real tar would: the
                        # link name maps to its target.
                        self.remote_fs[
                            posixpath.join(cwd, member.name)
                        ] = f"-> {member.linkname}".encode()
                        continue
                    extracted = tar.extractfile(member)
                    if extracted is not None:
                        # GNU tar strips leading slashes from member
                        # names on extraction.
                        name = member.name.lstrip("/")
                        self.remote_fs[posixpath.join(cwd, name)] = (
                            extracted.read()
                        )
        except (tarfile.TarError, EOFError, OSError) as exc:
            stderr.write(f"tar: {exc}\n".encode())
            return 2
        return 0

    def _tar_list(
        self, command: str, stdout: io.BytesIO, stderr: io.BytesIO,
        verbose: bool,
    ) -> int:
        quoted = self._quoted(command)
        archive_path = quoted[0]
        if archive_path not in self.remote_fs:
            stderr.write(f"tar: {archive_path}: not found\n".encode())
            return 1
        # GNU tar's default -tv format is not machine-readable: names with
        # spaces are split and a name containing ' -> ' can be mistaken
        # for part of a link target. The tool therefore requests
        # --quoting-style=shell-always, which makes every name and target
        # exactly one shell token; reproduce that here.
        shell_quoted = "--quoting-style=shell-always" in command

        def q(text: str) -> str:
            return shlex.quote(text) if shell_quoted else text

        try:
            with tarfile.open(
                fileobj=io.BytesIO(self.remote_fs[archive_path]), mode="r:gz"
            ) as tar:
                for member in tar.getmembers():
                    if verbose:
                        if member.issym():
                            kind = "l"
                            perms = "rwxrwxrwx"
                        elif member.islnk():
                            kind = "h"
                            perms = "rw-r--r--"
                        elif member.type == tarfile.CONTTYPE:
                            kind = self.contiguous_listing_kind
                            perms = "rw-r--r--"
                        elif member.isfile():
                            kind = "-"
                            perms = "rw-r--r--"
                        elif member.isdir():
                            kind = "d"
                            perms = "rwxr-xr-x"
                        elif member.isfifo():
                            kind = "p"
                            perms = "rw-r--r--"
                        elif member.ischr():
                            kind = "c"
                            perms = "rw-r--r--"
                        elif member.isblk():
                            kind = "b"
                            perms = "rw-r--r--"
                        else:
                            kind = "?"
                            perms = "rw-r--r--"
                        line = (
                            f"{kind}{perms} user/group 0 2026-01-01 "
                            f"09:30 {q(member.name)}"
                        )
                        if kind == "l":
                            line += f" -> {q(member.linkname)}"
                        elif kind == "h":
                            line += f" link to {q(member.linkname)}"
                        stdout.write((line + "\n").encode())
                    else:
                        stdout.write(f"{q(member.name)}\n".encode())
        except (tarfile.TarError, EOFError, OSError) as exc:
            stderr.write(f"tar: {exc}\n".encode())
            return 2
        return 0

    def _find_type_l(
        self, command: str, stdout: io.BytesIO, stderr: io.BytesIO
    ) -> int:
        """find <root> -type l -print0: list symlinks under root.

        The fake records symlinks as remote_fs entries whose content is
        b"-> <target>" (see _tar_extract), so a symlink is any entry
        whose data starts with b"-> ". Like real find, links are listed
        WITHOUT following them, and the root itself is never listed.
        """
        match = re.search(r"^find\s+'([^']+)'\s+-type l\s+-print0$", command)
        if not match:
            stderr.write(f"find: unsupported syntax: {command}\n".encode())
            return 1
        root = match.group(1).rstrip("/")
        prefix = root + "/"
        links = [
            path
            for path, data in self.remote_fs.items()
            if path.startswith(prefix) and data.startswith(b"-> ")
        ]
        for path in sorted(links):
            stdout.write(path.encode() + b"\0")
        return 0

    def _resolve(self, name: str, cwd: str | None) -> str:
        """Resolve a possibly-relative remote path against the cd directory."""
        if name in self.remote_fs or posixpath.isabs(name) or cwd is None:
            return name
        return posixpath.join(cwd, name)

    def _sha256sum_generate(
        self,
        command: str,
        stdout: io.BytesIO,
        stderr: io.BytesIO,
        cwd: str | None,
    ) -> int:
        # Two forms (cd prefix already stripped):
        #   sha256sum '<name>' > '<out>'   (checksum generation)
        #   sha256sum '<name>'             (plain hashing, no redirect)
        match = re.search(r"sha256sum\s+'([^']+)'\s*>\s*'([^']+)'", command)
        if match:
            name = self._resolve(match.group(1), cwd)
            out_path = self._resolve(match.group(2), cwd)
            if name not in self.remote_fs:
                stderr.write(f"sha256sum: {name}: not found\n".encode())
                return 1
            digest = hashlib.sha256(self.remote_fs[name]).hexdigest()
            base = posixpath.basename(name)
            self.remote_fs[out_path] = f"{digest}  {base}\n".encode()
            stdout.write(f"{digest}  {base}\n".encode())
            return 0
        match = re.search(r"sha256sum\s+'([^']+)'$", command)
        if match:
            name = self._resolve(match.group(1), cwd)
            if name not in self.remote_fs:
                stderr.write(
                    f"sha256sum: {name}: No such file or directory\n".encode()
                )
                return 1
            digest = hashlib.sha256(self.remote_fs[name]).hexdigest()
            base = posixpath.basename(name)
            stdout.write(f"{digest}  {base}\n".encode())
            return 0
        stderr.write(f"unparsable sha256sum: {command}\n".encode())
        return 2

    def _sha256sum_check(
        self, command: str, stderr: io.BytesIO, cwd: str | None
    ) -> int:
        # Form: sha256sum -c '<checksum_file>'   (cd prefix already stripped)
        match = re.search(r"sha256sum -c\s+'([^']+)'", command)
        if not match:
            stderr.write(f"unparsable sha256sum -c: {command}\n".encode())
            return 2
        checksum_file = self._resolve(match.group(1), cwd)
        if checksum_file not in self.remote_fs:
            stderr.write(f"sha256sum: {checksum_file}: not found\n".encode())
            return 1
        base_dir = posixpath.dirname(checksum_file)
        for line in self.remote_fs[checksum_file].decode().splitlines():
            digest, _, name = line.partition("  ")
            target = posixpath.join(base_dir, name.strip())
            actual = hashlib.sha256(
                self.remote_fs.get(target, b"")
            ).hexdigest()
            if actual != digest.lower():
                stderr.write(f"{name}: FAILED\n".encode())
                return 1
        return 0

    def _mysqldump(self, command: str, stderr: io.BytesIO) -> int:
        cnf = re.search(r"--defaults-extra-file='([^']+)'", command)
        dump = re.search(r">\s*'([^']+)'", command)
        db = re.search(r"defaults-extra-file='[^']+'\s+'([^']+)'", command)
        if not (cnf and dump and db):
            stderr.write(f"unparsable mysqldump: {command}\n".encode())
            return 2
        if cnf.group(1) not in self.remote_fs:
            stderr.write("mysqldump: defaults-extra-file missing\n".encode())
            return 1
        body = self.remote_fs[cnf.group(1)].decode()
        if "password=" not in body:
            stderr.write("mysqldump: cnf missing password\n".encode())
            return 1
        self.remote_fs[dump.group(1)] = (
            f"-- WordPress database dump\n-- db: {db.group(1)}\n"
            f"-- from cnf: {posixpath.basename(cnf.group(1))}\n"
        ).encode()
        return 0

    def _mysql(self, command: str, stderr: io.BytesIO) -> int:
        cnf = re.search(r"--defaults-extra-file='([^']+)'", command)
        source = re.search(r"<\s*'([^']+)'", command)
        if not (cnf and source):
            stderr.write(f"unparsable mysql: {command}\n".encode())
            return 2
        if cnf.group(1) not in self.remote_fs:
            stderr.write("mysql: defaults-extra-file missing\n".encode())
            return 1
        if source.group(1) not in self.remote_fs:
            stderr.write("mysql: dump file missing\n".encode())
            return 1
        return 0

    def _wp_db_export(self, command: str, stderr: io.BytesIO) -> int:
        dump = re.search(r"db export\s+'([^']+)'", command)
        if not dump:
            stderr.write(f"unparsable wp db export: {command}\n".encode())
            return 2
        self.remote_fs[dump.group(1)] = (
            b"-- WordPress database dump (wp-cli)\n"
        )
        return 0


class _ChannelWriter:
    """Minimal stdin stand-in; commands never read stdin."""

    def write(self, data: bytes) -> int:
        return len(data)

    def flush(self) -> None:
        pass


def _split_compound(command: str) -> list[str]:
    """Split a command on top-level ' && ' (outside single quotes)."""
    parts: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False
    i = 0
    while i < len(command):
        ch = command[i]
        if escaped:
            # E.g. the '\'' quote-escape idiom: this char is literal.
            escaped = False
            current.append(ch)
            i += 1
            continue
        if not in_quote and ch == "\\":
            escaped = True
            current.append(ch)
            i += 1
            continue
        if ch == "'":
            in_quote = not in_quote
            current.append(ch)
            i += 1
            continue
        if not in_quote and command[i: i + 4] == " && ":
            parts.append("".join(current))
            current = []
            i += 4
            continue
        current.append(ch)
        i += 1
    parts.append("".join(current))
    return parts


class _Stream:
    """Stand-in for paramiko's stdout/stderr file objects."""

    def __init__(self, buffer: io.BytesIO, exit_code: int) -> None:
        self.buffer = buffer
        self._exit_code = exit_code
        self.channel = self

    def read(self) -> bytes:
        return self.buffer.getvalue()

    def recv_exit_status(self) -> int:
        return self._exit_code
