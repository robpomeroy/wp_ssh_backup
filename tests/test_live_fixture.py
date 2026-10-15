"""Offline tests for the live-test fixture behaviour.

The live tests in tests/test_live.py are module-marked `live`, so
`pytest -m "not live"` (used by CI) excludes the whole module — including
its offline fixture behaviour. Those tests live here so CI runs them.
"""

from __future__ import annotations

import pytest

from common import WPSSHBackupError
from tests import test_live


def test_acquire_live_config_skips_on_enabled_env_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A configuration error with live testing enabled must skip, not raise."""
    calls: list[object] = []

    def failing_load_config() -> object:
        raise WPSSHBackupError("No .env file found.")

    monkeypatch.setattr(test_live, "load_config", failing_load_config)
    monkeypatch.setattr(test_live, "LIVE_ENABLED", True)

    with pytest.raises(pytest.skip.Exception) as excinfo:
        config = test_live.acquire_live_config()
        calls.append(config)

    # The skip message names the configuration problem, and the caller
    # never received a config object.
    assert "no valid configuration for live tests" in str(excinfo.value)
    assert "No .env file found." in str(excinfo.value)
    assert calls == []


def test_acquire_live_config_skips_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With live testing disabled the helper skips before loading config."""

    def exploding_load_config() -> object:
        raise AssertionError("load_config must not be called")

    monkeypatch.setattr(test_live, "load_config", exploding_load_config)
    monkeypatch.setattr(test_live, "LIVE_ENABLED", False)

    with pytest.raises(pytest.skip.Exception, match="WP_SSH_BACKUP_LIVE_TEST"):
        test_live.acquire_live_config()


def test_acquire_live_config_returns_config_when_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid configuration is returned unchanged for connection."""
    sentinel = object()

    monkeypatch.setattr(test_live, "load_config", lambda: sentinel)
    monkeypatch.setattr(test_live, "LIVE_ENABLED", True)

    assert test_live.acquire_live_config() is sentinel
