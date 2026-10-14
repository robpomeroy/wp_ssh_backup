"""Tests for SSH host-key verification and authorize_host.py."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import paramiko
import pytest

import authorize_host
import common
from common import (
    Config,
    UnknownHostKeyError,
    WPSSHBackupError,
    fingerprint,
    known_hosts_entry,
)
from tests.fakes import FakeSSHClient


def make_key() -> object:
    """Generate a deterministic-ish RSA key for fingerprint tests."""
    import paramiko

    return paramiko.RSAKey.generate(2048)


def make_config(tmp_path: Path, **overrides: str) -> Config:
    values = {
        "ssh_host": "example.com",
        "ssh_port": 22,
        "ssh_user": "user",
        "ssh_key_path": None,
        "ssh_password": None,
        "ssh_known_hosts": None,
        "wp_site_root": "/home/user/public_html",
        "wp_cli_path": None,
        "backup_dir": tmp_path / "backups",
        "retention_days": 30,
    }
    values.update(overrides)
    return Config(**values)


# ---------------------------------------------------------------------------
# Fingerprint and known_hosts entry helpers
# ---------------------------------------------------------------------------


def test_fingerprint_matches_manual_computation() -> None:
    key = make_key()
    expected = (
        "SHA256:"
        + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode()
        .rstrip("=")
    )
    assert fingerprint(key) == expected
    assert fingerprint(key).startswith("SHA256:")
    assert "=" not in fingerprint(key)


def test_known_hosts_entry_standard_port() -> None:
    key = make_key()
    entry = known_hosts_entry("example.com", 22, key)
    parts = entry.strip().split(" ")
    assert parts[0] == "example.com"
    assert parts[1] == key.get_name()
    assert parts[2] == key.get_base64()
    assert entry.endswith("\n")


def test_known_hosts_entry_nonstandard_port() -> None:
    key = make_key()
    entry = known_hosts_entry("example.com", 2222, key)
    assert entry.startswith("[example.com]:2222 ")


# ---------------------------------------------------------------------------
# connect() host-key policy
# ---------------------------------------------------------------------------


def test_connect_rejects_unknown_host_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSSHClient("/home/user/public_html")
    key = make_key()
    fake.server_key = key
    fake.trusted_fingerprints = set()  # nothing trusted

    def fake_connect(self: object, **kwargs: object) -> None:
        FakeSSHClient.connect(fake, **kwargs)

    monkeypatch.setattr(common.paramiko.SSHClient, "connect", fake_connect)

    config = make_config(tmp_path)
    with pytest.raises(UnknownHostKeyError, match="not trusted"):
        common.connect(config)


def test_connect_accepts_trusted_host_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """connect() must load the trusted entry and connect with it."""
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(known_hosts_entry("example.com", 22, key))
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    fake = FakeSSHClient("/home/user/public_html")
    fake.server_key = key
    fake.trusted_fingerprints = {fingerprint(key)}

    seen: dict[str, object] = {}

    def fake_connect(self: object, **kwargs: object) -> None:
        # The client must have loaded our known_hosts entry before
        # connecting, and must use RejectPolicy.
        seen["host_keys"] = dict(self.get_host_keys().lookup("example.com"))
        seen["policy"] = self._policy
        FakeSSHClient.connect(fake, **kwargs)

    monkeypatch.setattr(common.paramiko.SSHClient, "connect", fake_connect)
    monkeypatch.setattr(
        common.paramiko.SSHClient,
        "get_host_keys",
        lambda self: self._host_keys,
    )

    connected = common.connect(config)

    assert connected is not None
    assert isinstance(connected, common.paramiko.SSHClient)
    # The trusted key was loaded for the configured host.
    loaded = seen["host_keys"]
    assert len(loaded) == 1
    assert fingerprint(next(iter(loaded.values()))) == fingerprint(key)
    # Unknown keys are still rejected.
    import paramiko

    assert isinstance(seen["policy"], paramiko.RejectPolicy)
    # The simulated server key passed the trust check.
    assert fake.connect_calls, "connect() was never called"


def test_connect_uses_reject_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        common.paramiko.SSHClient,
        "connect",
        lambda self, **kwargs: None,
    )
    config = make_config(tmp_path)
    client = common.connect(config)
    import paramiko

    assert isinstance(client._policy, paramiko.RejectPolicy)


def test_connect_missing_known_hosts_file_fails_fast(tmp_path: Path) -> None:
    config = make_config(
        tmp_path, ssh_known_hosts=str(tmp_path / "missing" / "known_hosts")
    )
    with pytest.raises(
        WPSSHBackupError, match="SSH_KNOWN_HOSTS file not found"
    ):
        common.connect(config)


def test_connect_with_existing_known_hosts_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))
    monkeypatch.setattr(
        common.paramiko.SSHClient,
        "connect",
        lambda self, **kwargs: None,
    )
    connected = common.connect(config)
    assert connected is not None


def test_connect_unreadable_known_hosts_raises_wpssh_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreadable known_hosts file must raise WPSSHBackupError."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")

    def failing_load(self: object, filename: str) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(
        common.paramiko.SSHClient, "load_host_keys", failing_load
    )
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    with pytest.raises(
        WPSSHBackupError, match="Could not load SSH_KNOWN_HOSTS"
    ):
        common.connect(config)


def test_connect_malformed_known_hosts_raises_wpssh_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A malformed known_hosts file must raise WPSSHBackupError."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("this is not a valid known_hosts line\n")

    def failing_load(self: object, filename: str) -> None:
        raise paramiko.SSHException("Invalid known_hosts entry")

    monkeypatch.setattr(
        common.paramiko.SSHClient, "load_host_keys", failing_load
    )
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    with pytest.raises(
        WPSSHBackupError, match="Could not load SSH_KNOWN_HOSTS"
    ):
        common.connect(config)


def test_connect_undecodable_known_hosts_raises_wpssh_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Undecodable bytes in SSH_KNOWN_HOSTS must not leak a traceback."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_bytes(b"\xff\xfe\x00broken")

    def failing_load(self: object, filename: str) -> None:
        raise UnicodeDecodeError(
            "utf-8", b"\xff\xfe\x00broken", 0, 1, "invalid start byte"
        )

    monkeypatch.setattr(
        common.paramiko.SSHClient, "load_host_keys", failing_load
    )
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    with pytest.raises(
        WPSSHBackupError, match="Could not load SSH_KNOWN_HOSTS"
    ):
        common.connect(config)


def test_connect_malformed_system_host_keys_raises_wpssh_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A malformed default known_hosts file must not escape as a traceback."""

    def failing_system_load(self: object) -> None:
        raise UnicodeDecodeError(
            "utf-8", b"\xff\xfe\x00broken", 0, 1, "invalid start byte"
        )

    monkeypatch.setattr(
        common.paramiko.SSHClient, "load_system_host_keys",
        failing_system_load,
    )
    config = make_config(tmp_path)

    with pytest.raises(
        WPSSHBackupError, match="Could not load the system known_hosts"
    ):
        common.connect(config)


def test_main_reports_unreadable_known_hosts_as_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The CLI must print ERROR: and exit 2, not a traceback."""
    import backup

    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")

    def failing_load(self: object, filename: str) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(
        common.paramiko.SSHClient, "load_host_keys", failing_load
    )
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))
    monkeypatch.setattr(backup, "load_config", lambda: config)

    exit_code = backup.main([])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.err.startswith("ERROR: ")
    assert "Could not load SSH_KNOWN_HOSTS" in captured.err


# ---------------------------------------------------------------------------
# authorize_host.py
# ---------------------------------------------------------------------------


def test_authorize_host_saves_key_after_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    monkeypatch.setattr(authorize_host, "load_config", lambda: config)
    monkeypatch.setattr(authorize_host, "fetch_host_key", lambda cfg: key)
    monkeypatch.setattr(
        authorize_host, "confirm_interactive", lambda *a, **k: True
    )

    exit_code = authorize_host.main([])

    assert exit_code == 0
    content = known_hosts.read_text()
    assert content == known_hosts_entry("example.com", 22, key)
    out = capsys.readouterr().out
    assert "Host key saved" in out


def test_authorize_host_aborts_on_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    monkeypatch.setattr(authorize_host, "load_config", lambda: config)
    monkeypatch.setattr(authorize_host, "fetch_host_key", lambda cfg: key)
    monkeypatch.setattr(
        authorize_host, "confirm_interactive", lambda *a, **k: False
    )

    exit_code = authorize_host.main([])

    assert exit_code == 1
    assert not known_hosts.exists()


def test_authorize_host_fingerprint_pin_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    monkeypatch.setattr(authorize_host, "load_config", lambda: config)
    monkeypatch.setattr(authorize_host, "fetch_host_key", lambda cfg: key)

    exit_code = authorize_host.main(["--fingerprint", fingerprint(key)])

    assert exit_code == 0
    assert known_hosts.read_text() == known_hosts_entry("example.com", 22, key)


def test_authorize_host_unreadable_known_hosts_reports_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """A failing trust check must print ERROR: and exit 1, not traceback."""
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(known_hosts_entry("example.com", 22, key))
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    monkeypatch.setattr(authorize_host, "load_config", lambda: config)
    monkeypatch.setattr(authorize_host, "fetch_host_key", lambda cfg: key)
    monkeypatch.setattr(
        authorize_host, "confirm_interactive", lambda *a, **k: True
    )

    def failing_trust(
        path: object, hostname: str, port: int, k: object
    ) -> bool:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(authorize_host, "is_host_trusted", failing_trust)

    exit_code = authorize_host.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err.startswith("ERROR: could not check ")
    assert "Permission denied" in captured.err
    # Nothing was saved and no success message was printed.
    assert "Host key saved" not in captured.out


def test_authorize_host_malformed_known_hosts_reports_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """A malformed known_hosts file must be reported, not traceback."""
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("garbage line\n")
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    monkeypatch.setattr(authorize_host, "load_config", lambda: config)
    monkeypatch.setattr(authorize_host, "fetch_host_key", lambda cfg: key)
    monkeypatch.setattr(
        authorize_host, "confirm_interactive", lambda *a, **k: True
    )

    def failing_trust(
        path: object, hostname: str, port: int, k: object
    ) -> bool:
        raise paramiko.SSHException("Invalid known_hosts entry")

    monkeypatch.setattr(authorize_host, "is_host_trusted", failing_trust)

    exit_code = authorize_host.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err.startswith("ERROR: could not check ")
    assert "Invalid known_hosts entry" in captured.err


def test_authorize_host_readonly_destination_reports_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """A read-only known_hosts destination must be reported, not saved."""
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    known_hosts.write_text("")
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    monkeypatch.setattr(authorize_host, "load_config", lambda: config)
    monkeypatch.setattr(authorize_host, "fetch_host_key", lambda cfg: key)
    monkeypatch.setattr(
        authorize_host, "confirm_interactive", lambda *a, **k: True
    )

    def failing_append(
        path: object, hostname: str, port: int, k: object
    ) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(
        authorize_host, "append_to_known_hosts", failing_append
    )

    exit_code = authorize_host.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err.startswith("ERROR: could not save the host key to ")
    assert "Permission denied" in captured.err
    # The failure must not claim the host was saved.
    assert "Host key saved" not in captured.out


def test_authorize_host_fingerprint_pin_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    monkeypatch.setattr(authorize_host, "load_config", lambda: config)
    monkeypatch.setattr(authorize_host, "fetch_host_key", lambda cfg: key)

    wrong = "SHA256:" + "A" * 43
    exit_code = authorize_host.main(["--fingerprint", wrong])

    assert exit_code == 1
    assert not known_hosts.exists()
    err = capsys.readouterr().err
    assert "mismatch" in err.lower()


def test_authorize_host_show_does_not_save(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    monkeypatch.setattr(authorize_host, "load_config", lambda: config)
    monkeypatch.setattr(authorize_host, "fetch_host_key", lambda cfg: key)

    exit_code = authorize_host.main(["--show"])

    assert exit_code == 0
    assert not known_hosts.exists()
    out = capsys.readouterr().out
    assert fingerprint(key) in out


def test_authorize_host_skips_already_trusted_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    known_hosts.write_text(known_hosts_entry("example.com", 22, key))
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    monkeypatch.setattr(authorize_host, "load_config", lambda: config)
    monkeypatch.setattr(authorize_host, "fetch_host_key", lambda cfg: key)
    monkeypatch.setattr(
        authorize_host, "confirm_interactive", lambda *a, **k: True
    )

    exit_code = authorize_host.main([])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Already trusted" in out
    # Not duplicated.
    assert len(known_hosts.read_text().strip().splitlines()) == 1


def test_append_to_known_hosts_inserts_missing_newline(
    tmp_path: Path,
) -> None:
    """A file without a trailing newline must not swallow the new entry."""
    key = make_key()
    other = make_key()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    # Existing entry WITHOUT a trailing newline.
    existing = known_hosts_entry("other.example.net", 22, other)
    known_hosts.write_text(existing.rstrip("\n"))

    authorize_host.append_to_known_hosts(
        known_hosts, "example.com", 22, key
    )

    lines = known_hosts.read_text().strip().splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("other.example.net ")
    assert lines[1].startswith("example.com ")
    # Both entries must be parseable by paramiko.
    host_keys = paramiko.HostKeys(str(known_hosts))
    assert host_keys.lookup("example.com") is not None
    assert host_keys.lookup("other.example.net") is not None


def test_append_to_known_hosts_no_newline_for_empty_file(
    tmp_path: Path,
) -> None:
    """An empty file must not gain a leading newline."""
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    known_hosts.write_text("")

    authorize_host.append_to_known_hosts(known_hosts, "example.com", 22, key)

    content = known_hosts.read_text()
    assert content == known_hosts_entry("example.com", 22, key)
    assert not content.startswith("\n")


def test_authorize_host_appends_when_key_saved_under_other_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """A fingerprint match under another host must not skip the append."""
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    # Same key, but recorded for a different host name.
    known_hosts.write_text(known_hosts_entry("other.example.net", 22, key))
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    monkeypatch.setattr(authorize_host, "load_config", lambda: config)
    monkeypatch.setattr(authorize_host, "fetch_host_key", lambda cfg: key)
    monkeypatch.setattr(
        authorize_host, "confirm_interactive", lambda *a, **k: True
    )

    exit_code = authorize_host.main([])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Already trusted" not in out
    assert "Host key saved" in out
    lines = known_hosts.read_text().strip().splitlines()
    assert len(lines) == 2
    assert lines[1].startswith("example.com ")


def test_authorize_host_appends_when_key_saved_under_other_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """A fingerprint match under another port must not skip the append."""
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    # Same key, but recorded for the same host on a different port.
    known_hosts.write_text(known_hosts_entry("example.com", 2222, key))
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    monkeypatch.setattr(authorize_host, "load_config", lambda: config)
    monkeypatch.setattr(authorize_host, "fetch_host_key", lambda cfg: key)
    monkeypatch.setattr(
        authorize_host, "confirm_interactive", lambda *a, **k: True
    )

    exit_code = authorize_host.main([])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Already trusted" not in out
    assert "Host key saved" in out
    lines = known_hosts.read_text().strip().splitlines()
    assert len(lines) == 2
    # The configured port is 22, so the new entry uses the plain form.
    assert lines[1].startswith("example.com ")


def test_is_host_trusted(tmp_path: Path) -> None:
    key = make_key()
    other = make_key()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(known_hosts_entry("example.com", 22, key))

    assert authorize_host.is_host_trusted(
        known_hosts, "example.com", 22, key
    )
    # Wrong key for the right host.
    assert not authorize_host.is_host_trusted(
        known_hosts, "example.com", 22, other
    )
    # Right key under a different host or port.
    assert not authorize_host.is_host_trusted(
        known_hosts, "other.example.net", 22, key
    )
    assert not authorize_host.is_host_trusted(
        known_hosts, "example.com", 2222, key
    )


def test_is_host_trusted_missing_file(tmp_path: Path) -> None:
    key = make_key()
    assert not authorize_host.is_host_trusted(
        tmp_path / "nope", "example.com", 22, key
    )


def test_is_host_trusted_hashed_entry(tmp_path: Path) -> None:
    """OpenSSH hashed hostnames must be recognised as already trusted."""
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    hashed = paramiko.HostKeys.hash_host("example.com")
    known_hosts.write_text(f"{hashed} {key.get_name()} {key.get_base64()}\n")

    assert authorize_host.is_host_trusted(
        known_hosts, "example.com", 22, key
    )
    # A different key under the same hashed name is not trusted.
    assert not authorize_host.is_host_trusted(
        known_hosts, "example.com", 22, make_key()
    )


def test_authorize_host_skips_append_for_hashed_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """A hashed trusted entry must not gain a plaintext duplicate."""
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    hashed = paramiko.HostKeys.hash_host("example.com")
    known_hosts.write_text(f"{hashed} {key.get_name()} {key.get_base64()}\n")
    config = make_config(tmp_path, ssh_known_hosts=str(known_hosts))

    monkeypatch.setattr(authorize_host, "load_config", lambda: config)
    monkeypatch.setattr(authorize_host, "fetch_host_key", lambda cfg: key)
    monkeypatch.setattr(
        authorize_host, "confirm_interactive", lambda *a, **k: True
    )

    exit_code = authorize_host.main([])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Already trusted" in out
    # No plaintext duplicate was appended: still exactly one line, and it
    # remains hashed.
    lines = known_hosts.read_text().strip().splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("|1|")


# ---------------------------------------------------------------------------
# fetch_host_key error handling
# ---------------------------------------------------------------------------


class _FakeTransport:
    """Stand-in for paramiko.Transport taking a pre-opened socket."""

    def __init__(self, sock: object) -> None:
        self.sock = sock
        self.closed = False

    def start_client(self, timeout: float | None = None) -> None:
        pass

    def get_remote_server_key(self) -> object:
        return make_key()

    def close(self) -> None:
        self.closed = True


def test_fetch_host_key_unreachable_host(tmp_path: Path) -> None:
    """A socket-level failure must surface as ERROR:, not a traceback."""
    config = make_config(tmp_path)

    def failing_connect(
        address: object, timeout: float | None = None
    ) -> object:
        raise OSError(65, "No route to host")

    monkey_transport = pytest.MonkeyPatch()
    with monkey_transport.context() as m:
        m.setattr(authorize_host.socket, "create_connection", failing_connect)
        with pytest.raises(WPSSHBackupError, match="Could not reach"):
            authorize_host.fetch_host_key(config)
    monkey_transport.undo()


def test_fetch_host_key_connect_timeout(tmp_path: Path) -> None:
    """The TCP connect must be bounded by an explicit socket timeout."""
    config = make_config(tmp_path)
    timeouts: list[float | None] = []

    def hanging_connect(
        address: object, timeout: float | None = None
    ) -> object:
        timeouts.append(timeout)
        raise OSError("timed out")

    monkey_transport = pytest.MonkeyPatch()
    with monkey_transport.context() as m:
        m.setattr(authorize_host.socket, "create_connection", hanging_connect)
        with pytest.raises(WPSSHBackupError, match="Could not reach"):
            authorize_host.fetch_host_key(config)
    monkey_transport.undo()

    # The connect was attempted with the explicit 30-second timeout.
    assert timeouts == [30]


def test_fetch_host_key_closes_socket_on_transport_failure(
    tmp_path: Path,
) -> None:
    """A Transport failure must not leak the opened socket."""
    config = make_config(tmp_path)
    closed: list[bool] = []

    class _FakeSock:
        def settimeout(self, value: float | None) -> None:
            pass

        def close(self) -> None:
            closed.append(True)

    def failing_transport(sock: object) -> object:
        raise paramiko.SSHException("handshake failed")

    monkey_transport = pytest.MonkeyPatch()
    with monkey_transport.context() as m:
        m.setattr(
            authorize_host.socket,
            "create_connection",
            lambda address, timeout=None: _FakeSock(),
        )
        m.setattr(authorize_host.paramiko, "Transport", failing_transport)
        with pytest.raises(WPSSHBackupError, match="Could not reach"):
            authorize_host.fetch_host_key(config)
    monkey_transport.undo()

    assert closed == [True]


def test_fetch_host_key_success_uses_preopened_socket(
    tmp_path: Path,
) -> None:
    """The happy path passes the socket to Transport and cleans up."""
    config = make_config(tmp_path)
    received: list[object] = []

    class _FakeSock:
        def settimeout(self, value: float | None) -> None:
            pass

        def close(self) -> None:
            pass

    sock = _FakeSock()

    monkey_transport = pytest.MonkeyPatch()
    with monkey_transport.context() as m:
        m.setattr(
            authorize_host.socket,
            "create_connection",
            lambda address, timeout=None: sock,
        )

        def transport_factory(received_sock: object) -> _FakeTransport:
            received.append(received_sock)
            return _FakeTransport(received_sock)

        m.setattr(authorize_host.paramiko, "Transport", transport_factory)
        key = authorize_host.fetch_host_key(config)
    monkey_transport.undo()

    assert received == [sock]
    assert key.get_name() == "ssh-rsa"


def test_main_reports_unreachable_host_as_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """main() must print ERROR: and exit 2 when the host is unreachable."""
    config = make_config(tmp_path)

    def failing_transport(sock: object) -> object:
        raise OSError(65, "No route to host")

    monkey_transport = pytest.MonkeyPatch()
    with monkey_transport.context() as m:
        m.setattr(
            authorize_host.socket,
            "create_connection",
            lambda address, timeout=None: (_ for _ in ()).throw(
                OSError(65, "No route to host")
            ),
        )
        m.setattr(authorize_host, "load_config", lambda: config)
        exit_code = authorize_host.main([])
    monkey_transport.undo()

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.err.startswith("ERROR: ")
    assert "No route to host" in captured.err
