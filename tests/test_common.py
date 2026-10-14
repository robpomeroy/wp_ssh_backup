"""Unit tests for the pure helpers in common.py."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from common import (
    ConfigError,
    checksum_name,
    find_backup_sets,
    human_size,
    load_config,
    mysql_client_config,
    parse_sha256sum_output,
    parse_timestamp,
    parse_wp_config,
    prune_local_backups,
    sha256_file,
    shquote,
    split_db_host,
    staging_dir_for,
    timestamp_from_archive_name,
    utc_timestamp,
)


# ---------------------------------------------------------------------------
# wp-config.php parsing
# ---------------------------------------------------------------------------

WP_CONFIG = """
<?php
define( 'DB_NAME', 'wp_database' );
define( 'DB_USER', 'wp_user' );
define( 'DB_PASSWORD', 's3cret"pass\\'with quotes' );
define( 'DB_HOST', 'localhost:3306' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'AUTH_KEY', 'not-a-db-key' );
$table_prefix = 'wp_';
"""


def test_parse_wp_config_extracts_all_db_keys() -> None:
    settings = parse_wp_config(WP_CONFIG)
    assert settings["DB_NAME"] == "wp_database"
    assert settings["DB_USER"] == "wp_user"
    assert settings["DB_HOST"] == "localhost:3306"
    assert "DB_CHARSET" not in settings
    assert "AUTH_KEY" not in settings


def test_parse_wp_config_handles_escaped_quotes() -> None:
    settings = parse_wp_config(WP_CONFIG)
    assert settings["DB_PASSWORD"] == 's3cret"pass\'with quotes'


def test_parse_wp_config_missing_keys() -> None:
    settings = parse_wp_config("define( 'DB_NAME', 'only-name' );")
    assert settings == {"DB_NAME": "only-name"}


def test_parse_wp_config_dynamic_values_ignored() -> None:
    settings = parse_wp_config("define( 'DB_USER', DB_USER_ENV );")
    assert "DB_USER" not in settings


# ---------------------------------------------------------------------------
# MySQL option file
# ---------------------------------------------------------------------------


def test_mysql_client_config_contains_credentials() -> None:
    body = mysql_client_config("localhost", "user", "pass")
    assert "[client]" in body
    assert 'host="localhost"' in body
    assert 'user="user"' in body
    assert 'password="pass"' in body


def test_mysql_client_config_escapes_quotes_and_backslashes() -> None:
    body = mysql_client_config("h", "u", 'p"a\\ss')
    assert 'password="p\\"a\\\\ss"' in body


def test_mysql_client_config_socket_takes_precedence() -> None:
    body = mysql_client_config(
        "h", "u", "p", port="3306", socket="/tmp/mysql.sock"
    )
    assert 'socket="/tmp/mysql.sock"' in body
    assert "host=" not in body
    assert "port=" not in body


def test_split_db_host_variants() -> None:
    assert split_db_host("localhost") == ("localhost", None, None)
    assert split_db_host("db.example.com:3306") == (
        "db.example.com",
        "3306",
        None,
    )
    assert split_db_host("localhost:/tmp/mysql.sock") == (
        "localhost",
        None,
        "/tmp/mysql.sock",
    )
    assert split_db_host(":3306") == ("localhost", "3306", None)


# ---------------------------------------------------------------------------
# Timestamps and naming
# ---------------------------------------------------------------------------


def test_utc_timestamp_format() -> None:
    now = datetime(2026, 10, 14, 9, 30, tzinfo=timezone.utc)
    assert utc_timestamp(now) == "20261014T0930Z"


def test_parse_timestamp_roundtrip() -> None:
    ts = "20261014T0930Z"
    parsed = parse_timestamp(ts)
    assert parsed.year == 2026
    assert parsed.minute == 30
    assert parsed.tzinfo is timezone.utc


def test_staging_dir_is_sibling_of_site_root() -> None:
    staging = staging_dir_for("/home/user/public_html", "20261014T0930Z")
    assert staging == "/home/user/wp-ssh-backup-staging-20261014T0930Z"


def test_staging_dir_for_root_site() -> None:
    staging = staging_dir_for("/", "20261014T0930Z")
    assert staging == "/wp-ssh-backup-staging-20261014T0930Z"


def test_archive_names() -> None:
    ts = "20261014T0930Z"
    assert checksum_name("wp-db-" + ts + ".tar.gz") == (
        "wp-db-" + ts + ".tar.gz.sha256"
    )
    assert timestamp_from_archive_name("wp-files-" + ts + ".tar.gz") == ts
    assert timestamp_from_archive_name(
        "wp-db-" + ts + ".tar.gz.sha256"
    ) is None
    assert timestamp_from_archive_name("random.txt") is None


def test_shquote_escapes_single_quotes() -> None:
    assert shquote("/home/it's") == "'/home/it'\\''s'"


# ---------------------------------------------------------------------------
# Checksums
# ---------------------------------------------------------------------------


def test_sha256_file(tmp_path: Path) -> None:
    import hashlib

    path = tmp_path / "data.bin"
    path.write_bytes(b"hello world")
    # Chunked file hashing must agree with a direct in-memory hash.
    assert sha256_file(path) == hashlib.sha256(b"hello world").hexdigest()


def test_parse_sha256sum_output() -> None:
    digest_a = "a" * 64
    digest_b = "b" * 64
    text = (
        f"{digest_a}  wp-db-20261014T0930Z.tar.gz\n"
        f"{digest_b} *wp-files-20261014T0930Z.tar.gz\n"
    )
    result = parse_sha256sum_output(text)
    assert result == {
        "wp-db-20261014T0930Z.tar.gz": digest_a,
        "wp-files-20261014T0930Z.tar.gz": digest_b,
    }


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def write_env(tmp_path: Path, **overrides: str) -> Path:
    values = {
        "SSH_HOST": "example.com",
        "SSH_PORT": "22",
        "SSH_USER": "myuser",
        "SSH_KEY_PATH": "",
        "SSH_PASSWORD": "",
        "WP_SITE_ROOT": "/home/myuser/public_html",
        "WP_CLI_PATH": "",
        "BACKUP_DIR": str(tmp_path / "backups"),
        "RETENTION_DAYS": "30",
    }
    values.update(overrides)
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(f"{key}={value}" for key, value in values.items()) + "\n"
    )
    return env_path


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove all config keys from the environment before each test."""
    for key in (
        "SSH_HOST",
        "SSH_PORT",
        "SSH_USER",
        "SSH_KEY_PATH",
        "SSH_PASSWORD",
        "WP_SITE_ROOT",
        "WP_CLI_PATH",
        "BACKUP_DIR",
        "RETENTION_DAYS",
    ):
        monkeypatch.delenv(key, raising=False)


def test_load_config_valid(tmp_path: Path) -> None:
    config = load_config(write_env(tmp_path))
    assert config.ssh_host == "example.com"
    assert config.ssh_port == 22
    assert config.wp_site_root == "/home/myuser/public_html"
    assert config.retention_days == 30
    assert config.backup_dir == Path(str(tmp_path / "backups"))


def test_load_config_missing_required_key(tmp_path: Path) -> None:
    env_path = write_env(tmp_path)
    env_path.write_text(env_path.read_text().replace("SSH_USER=myuser", ""))
    with pytest.raises(ConfigError, match="SSH_USER"):
        load_config(env_path)


def test_load_config_relative_site_root_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="absolute"):
        load_config(write_env(tmp_path, WP_SITE_ROOT="public_html"))


def test_load_config_bad_port(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="SSH_PORT"):
        load_config(write_env(tmp_path, SSH_PORT="not-a-number"))


def test_load_config_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.env")


# ---------------------------------------------------------------------------
# Backup sets and retention
# ---------------------------------------------------------------------------


def make_set(
    backup_dir: Path,
    ts: str,
    kinds: tuple[str, ...] = ("db", "files"),
) -> None:
    for kind in kinds:
        (backup_dir / f"wp-{kind}-{ts}.tar.gz").write_bytes(b"x")
        (backup_dir / f"wp-{kind}-{ts}.tar.gz.sha256").write_text("d  f\n")


def test_find_backup_sets_groups_by_timestamp(tmp_path: Path) -> None:
    make_set(tmp_path, "20261014T0930Z")
    make_set(tmp_path, "20261013T0930Z", kinds=("db",))
    sets = find_backup_sets(tmp_path)
    assert set(sets) == {"20261014T0930Z", "20261013T0930Z"}
    assert len(sets["20261014T0930Z"]) == 4
    assert len(sets["20261013T0930Z"]) == 2


def test_find_backup_sets_ignores_other_files(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("keep me")
    (tmp_path / "wp-db-badts.tar.gz").write_bytes(b"x")
    assert find_backup_sets(tmp_path) == {}


def test_prune_removes_only_old_sets(tmp_path: Path) -> None:
    now = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
    # 40 days old -> removed; 29 days old -> kept.
    make_set(tmp_path, "20260904T1200Z")
    make_set(tmp_path, "20260915T1200Z")
    removed = prune_local_backups(tmp_path, 30, now=now)
    assert removed == ["20260904T1200Z"]
    assert not list(tmp_path.glob("wp-db-20260904T1200Z*"))
    assert (tmp_path / "wp-db-20260915T1200Z.tar.gz").exists()


def test_prune_zero_disables(tmp_path: Path) -> None:
    make_set(tmp_path, "20200101T0000Z")
    assert prune_local_backups(tmp_path, 0) == []
    assert len(list(tmp_path.iterdir())) == 4


def test_prune_empty_dir(tmp_path: Path) -> None:
    assert prune_local_backups(tmp_path, 30) == []


def test_human_size() -> None:
    assert human_size(0) == "0 B"
    assert human_size(1023) == "1023 B"
    assert human_size(1024) == "1.0 KiB"
    assert human_size(5 * 1024 * 1024) == "5.0 MiB"
