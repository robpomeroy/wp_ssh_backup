"""Tests for SSH host-key verification and authorize_host.py."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

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


# ---------------------------------------------------------------------------
# fetch_host_key error handling
# ---------------------------------------------------------------------------


def test_fetch_host_key_unreachable_host(tmp_path: Path) -> None:
    """A socket-level failure must surface as ERROR:, not a traceback."""
    config = make_config(tmp_path)

    def failing_transport(address: object) -> object:
        raise OSError(65, "No route to host")

    monkey_transport = pytest.MonkeyPatch()
    with monkey_transport.context() as m:
        m.setattr(authorize_host.paramiko, "Transport", failing_transport)
        with pytest.raises(WPSSHBackupError, match="Could not reach"):
            authorize_host.fetch_host_key(config)
    monkey_transport.undo()


def test_main_reports_unreachable_host_as_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """main() must print ERROR: and exit 2 when the host is unreachable."""
    config = make_config(tmp_path)

    def failing_transport(address: object) -> object:
        raise OSError(65, "No route to host")

    monkey_transport = pytest.MonkeyPatch()
    with monkey_transport.context() as m:
        m.setattr(authorize_host.paramiko, "Transport", failing_transport)
        m.setattr(authorize_host, "load_config", lambda: config)
        exit_code = authorize_host.main([])
    monkey_transport.undo()

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.err.startswith("ERROR: ")
    assert "No route to host" in captured.err
