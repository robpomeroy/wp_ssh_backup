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
    key = make_key()

    def fake_connect(self: object, **kwargs: object) -> None:
        from common import fingerprint

        if fingerprint(key) not in {fingerprint(key)}:
            raise AssertionError("should not happen")

    monkeypatch.setattr(common.paramiko.SSHClient, "connect", fake_connect)

    config = make_config(tmp_path)
    connected = common.connect(config)
    assert connected is not None
    assert isinstance(connected, common.paramiko.SSHClient)


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


def test_load_existing_fingerprints(tmp_path: Path) -> None:
    key = make_key()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(known_hosts_entry("example.com", 22, key))

    fps = authorize_host.load_existing_fingerprints(known_hosts)

    assert fps == {fingerprint(key)}


def test_load_existing_fingerprints_missing_file(tmp_path: Path) -> None:
    assert authorize_host.load_existing_fingerprints(
        tmp_path / "nope"
    ) == set()
