"""A fake SSH/SFTP layer for orchestration tests.

FakeSSHClient simulates a remote Linux host well enough to exercise the backup
and restore flows: it interprets the specific commands the tool issues (mkdir,
rm, tar, sha256sum, wp/mysqldump/mysql) against an in-memory filesystem, and
FakeSFTPClient moves bytes between that filesystem and local disk.
"""

from __future__ import annotations

import hashlib
import io
import posixpath
import re
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
        return _FakeReadFile(self.remote_fs.get(path))

    def chmod(self, path: str, mode: int) -> None:
        self.modes[path] = mode

    def get(self, remote_path: str, local_path: str) -> None:
        if remote_path not in self.remote_fs:
            raise FileNotFoundError(remote_path)
        from pathlib import Path

        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as handle:
            handle.write(self.remote_fs[remote_path])

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

    # -- paramiko API -------------------------------------------------------

    def open_sftp(self) -> FakeSFTPClient:
        return self.sftp

    def close(self) -> None:
        pass

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

        if command.startswith("mkdir -p "):
            return 0
        if command.startswith("rm -rf "):
            return self._rm_rf(command)
        if command.startswith("rm -f "):
            return self._rm_f(command)
        if command.startswith("test -x "):
            return 0 if self.wp_cli else 1
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

    def _quoted(self, command: str) -> list[str]:
        return re.findall(r"'([^']*)'", command)

    def _rm_rf(self, command: str) -> int:
        target = re.search(r"rm -rf\s+'([^']+)'", command)
        if target:
            prefix = target.group(1).rstrip("/") + "/"
            for path in [p for p in self.remote_fs if p.startswith(prefix)]:
                del self.remote_fs[path]
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
        members = self._members_for(cwd, member)
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
                    extracted = tar.extractfile(member)
                    if extracted is not None:
                        self.remote_fs[posixpath.join(cwd, member.name)] = (
                            extracted.read()
                        )
        except (tarfile.TarError, EOFError, OSError) as exc:
            stderr.write(f"tar: {exc}\n".encode())
            return 2
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
        # Form: sha256sum '<name>' > '<out>'   (cd prefix already stripped)
        match = re.search(r"sha256sum\s+'([^']+)'\s*>\s*'([^']+)'", command)
        if not match:
            stderr.write(f"unparsable sha256sum: {command}\n".encode())
            return 2
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
