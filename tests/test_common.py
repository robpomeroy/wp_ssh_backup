"""Unit tests for the pure helpers in common.py."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from common import (
    ChecksumError,
    ConfigError,
    RemoteCommandError,
    _unescape_php,
    backup_id,
    backup_id_from_archive_name,
    checksum_name,
    find_backup_sets,
    human_size,
    load_config,
    mysql_client_config,
    parse_backup_id,
    parse_sha256sum_output,
    parse_timestamp,
    parse_wp_config,
    prune_local_backups,
    sha256_file,
    shquote,
    split_db_host,
    staging_dir_for,
    strip_php_comments,
    trap_rm_action,
    utc_timestamp,
    remove_remote_file,
    remove_remote_staging,
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


def test_parse_wp_config_preserves_unknown_escapes() -> None:
    """Regression: PHP keeps the backslash for unrecognised escapes."""
    lines = [
        "<?php",
        r"define( 'DB_PASSWORD', 'p\q' );",
        r"define( 'DB_NAME', 'db' );",
        r"define( 'DB_USER', 'u' );",
        r"define( 'DB_HOST', 'h' );",
    ]
    settings = parse_wp_config("\n".join(lines) + "\n")
    assert settings["DB_PASSWORD"] == r"p\q"


def test_parse_wp_config_single_quoted_escapes() -> None:
    lines = [
        "<?php",
        r"define( 'DB_PASSWORD', 'a\'b\\c\"d' );",
        r"define( 'DB_NAME', 'db' );",
        r"define( 'DB_USER', 'u' );",
        r"define( 'DB_HOST', 'h' );",
    ]
    settings = parse_wp_config("\n".join(lines) + "\n")
    # \' -> ', \\ -> \\, but \" keeps its backslash in single quotes.
    assert settings["DB_PASSWORD"] == "a'b\\c\\\"d"


def test_parse_wp_config_double_quoted_escapes() -> None:
    lines = [
        "<?php",
        r'define( "DB_PASSWORD", "a\tb\"q\$z\x41" );',
        r'define( "DB_NAME", "db" );',
        r'define( "DB_USER", "u" );',
        r'define( "DB_HOST", "h" );',
    ]
    settings = parse_wp_config("\n".join(lines) + "\n")
    # \t -> tab, \" -> ", \$ -> $, \x41 -> A.
    assert settings["DB_PASSWORD"] == 'a\tb"q$zA'


# ---------------------------------------------------------------------------
# _unescape_php direct tests (escape decoder edge cases)
# ---------------------------------------------------------------------------


def test_unescape_php_octal_escape_advances_index() -> None:
    """Regression: a lost index advance in the octal branch hung forever."""
    # \\101 is octal 65 = 'A'; the digits must all be consumed.
    assert _unescape_php(r"\101", '"') == "A"
    assert _unescape_php(r"\101B", '"') == "AB"
    # Up to three digits total: \\1015 -> chr(0o101) + literal '5'.
    assert _unescape_php(r"\1015", '"') == "A5"
    # Two-digit form: \\12 is octal 10 = newline.
    assert _unescape_php(r"\12x", '"') == "\nx"


def test_unescape_php_octal_no_hang() -> None:
    """The octal branch must always advance i; guard with a timeout."""

    def run() -> None:
        _unescape_php(r"\101\102\7", '"')

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive(), "_unescape_php hung on octal escapes"


def test_unescape_php_trailing_backslash() -> None:
    assert _unescape_php(r"trailing" + "\\", "'") == "trailing\\"


def test_unescape_php_unknown_escapes_keep_backslash() -> None:
    assert _unescape_php(r"p\q", "'") == r"p\q"
    assert _unescape_php(r"\q\w", '"') == r"\q\w"


def test_parse_wp_config_missing_keys() -> None:
    settings = parse_wp_config("define( 'DB_NAME', 'only-name' );")
    assert settings == {"DB_NAME": "only-name"}


def test_parse_wp_config_dynamic_values_ignored() -> None:
    settings = parse_wp_config("define( 'DB_USER', DB_USER_ENV );")
    assert "DB_USER" not in settings


# ---------------------------------------------------------------------------
# PHP comment handling
# ---------------------------------------------------------------------------


def test_parse_wp_config_commented_define_does_not_shadow_real() -> None:
    """Regression: a commented-out define must not win the first-match race."""
    text = (
        "<?php\n"
        "// define( 'DB_PASSWORD', 'old-password' );\n"
        "define( 'DB_NAME', 'wp_database' );\n"
        "define( 'DB_USER', 'wp_user' );\n"
        "define( 'DB_PASSWORD', 'real-password' );\n"
        "define( 'DB_HOST', 'localhost' );\n"
    )
    settings = parse_wp_config(text)
    assert settings["DB_PASSWORD"] == "real-password"


def test_parse_wp_config_block_commented_define_ignored() -> None:
    text = (
        "<?php\n"
        "/*\n"
        " * define( 'DB_PASSWORD', 'old-password' );\n"
        " */\n"
        "define( 'DB_PASSWORD', 'real-password' );\n"
    )
    settings = parse_wp_config(text)
    assert settings["DB_PASSWORD"] == "real-password"


def test_parse_wp_config_hash_commented_define_ignored() -> None:
    text = (
        "<?php\n"
        "# define( 'DB_PASSWORD', 'old-password' );\n"
        "define( 'DB_PASSWORD', 'real-password' );\n"
    )
    settings = parse_wp_config(text)
    assert settings["DB_PASSWORD"] == "real-password"


def test_parse_wp_config_value_containing_slashes_preserved() -> None:
    """Comment-like text inside string literals must survive."""
    text = (
        "<?php\n"
        "define( 'DB_PASSWORD', 'p//ss/*word' );\n"
        "define( 'DB_NAME', 'db' );\n"
        "define( 'DB_USER', 'u' );\n"
        "define( 'DB_HOST', 'h' );\n"
    )
    settings = parse_wp_config(text)
    assert settings["DB_PASSWORD"] == "p//ss/*word"


def test_parse_wp_config_define_inside_string_ignored() -> None:
    text = (
        "<?php\n"
        "$note = \"define( 'DB_PASSWORD', 'fake' );\";\n"
        "define( 'DB_PASSWORD', 'real-password' );\n"
    )
    settings = parse_wp_config(text)
    assert settings["DB_PASSWORD"] == "real-password"


def test_strip_php_comments_preserves_strings_and_code() -> None:
    source = (
        "$a = 'keep // this';\n"
        "// remove this\n"
        "$b = \"keep /* this */ too\";\n"
        "/* remove\nthis */ $c = 1;\n"
    )
    stripped, in_string = strip_php_comments(source)
    assert "'keep // this'" in stripped
    assert '"keep /* this */ too"' in stripped
    assert "remove this" not in stripped
    assert "remove\nthis" not in stripped
    assert "$c = 1;" in stripped
    # Positions of surviving string content are marked as in-string.
    assert in_string[stripped.index("keep // this")] is True


def test_strip_php_comments_escaped_quote_does_not_end_string() -> None:
    source = r"$a = 'it\'s // not a comment';"
    stripped, _ = strip_php_comments(source)
    assert "not a comment" in stripped
    assert "//" not in stripped.replace("'it\\'s // not a comment'", "")


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


def test_backup_id_format_and_uniqueness() -> None:
    now = datetime(2026, 10, 14, 9, 30, tzinfo=timezone.utc)
    first = backup_id(now)
    second = backup_id(now)
    assert first.startswith("20261014T0930Z-")
    assert len(first) == len("20261014T0930Z-") + 6
    # Same minute, different runs -> different ids.
    assert first != second
    int(first.rsplit("-", 1)[1], 16)  # suffix is hex


def test_parse_backup_id_with_and_without_suffix() -> None:
    parsed = parse_backup_id("20261014T0930Z-a1b2c3")
    assert parsed == datetime(2026, 10, 14, 9, 30, tzinfo=timezone.utc)
    assert parse_backup_id("20261014T0930Z") == parsed


def test_parse_timestamp_roundtrip() -> None:
    ts = "20261014T0930Z"
    parsed = parse_timestamp(ts)
    assert parsed.year == 2026
    assert parsed.minute == 30
    assert parsed.tzinfo is timezone.utc


def test_staging_dir_is_sibling_of_site_root() -> None:
    staging = staging_dir_for(
        "/home/user/public_html", "20261014T0930Z-a1b2c3"
    )
    assert staging == (
        "/home/user/wp-ssh-backup-staging-20261014T0930Z-a1b2c3"
    )


def test_staging_dir_for_root_site() -> None:
    staging = staging_dir_for("/", "20261014T0930Z")
    assert staging == "/wp-ssh-backup-staging-20261014T0930Z"


def test_archive_names() -> None:
    bid = "20261014T0930Z-a1b2c3"
    assert checksum_name("wp-db-" + bid + ".tar.gz") == (
        "wp-db-" + bid + ".tar.gz.sha256"
    )
    assert backup_id_from_archive_name("wp-files-" + bid + ".tar.gz") == bid
    assert (
        backup_id_from_archive_name("wp-db-" + bid + ".tar.gz.sha256")
        is None
    )
    assert backup_id_from_archive_name("random.txt") is None
    # Legacy names without a run suffix still parse.
    assert (
        backup_id_from_archive_name("wp-db-20261014T0930Z.tar.gz")
        == "20261014T0930Z"
    )


def test_shquote_escapes_single_quotes() -> None:
    assert shquote("/home/it's") == "'/home/it'\\''s'"


def test_trap_rm_action_is_single_shell_word() -> None:
    """'trap <action> EXIT' must parse as exactly three shell words."""
    import shlex

    action = trap_rm_action("/home/user/my cnf.cnf")
    words = shlex.split(f"trap {action} EXIT")
    assert len(words) == 3
    assert words[0] == "trap"
    assert words[2] == "EXIT"
    # When the trap fires, the shell re-evaluates the action string; the
    # path with its space must come out as ONE rm argument.
    rm_words = shlex.split(words[1])
    assert rm_words == ["rm", "-f", "/home/user/my cnf.cnf"]


def test_trap_rm_action_escapes_quotes_in_path() -> None:
    """A single quote in the path must survive both quoting layers."""
    import shlex

    action = trap_rm_action("/home/it's/my cnf")
    words = shlex.split(f"trap {action} EXIT")
    assert len(words) == 3
    rm_words = shlex.split(words[1])
    assert rm_words == ["rm", "-f", "/home/it's/my cnf"]


def test_trap_rm_action_simple_path() -> None:
    import shlex

    action = trap_rm_action("/tmp/simple.cnf")
    words = shlex.split(f"trap {action} EXIT")
    assert shlex.split(words[1]) == ["rm", "-f", "/tmp/simple.cnf"]


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


def test_find_backup_sets_ignores_checksum_only_group(
    tmp_path: Path,
) -> None:
    """An orphaned .sha256 group must not shadow a valid older set."""
    make_set(tmp_path, "20261013T0000Z")
    # A newer checksum-only group: no archive, just an orphaned checksum.
    (tmp_path / "wp-db-20261014T0930Z.tar.gz.sha256").write_text("d  f\n")
    (tmp_path / "wp-files-20261014T0930Z.tar.gz.sha256").write_text("d  f\n")
    sets = find_backup_sets(tmp_path)

    assert set(sets) == {"20261013T0000Z"}


def test_find_backup_sets_keeps_checksums_with_archives(
    tmp_path: Path,
) -> None:
    """Checksums belonging to a real archive stay in the set."""
    make_set(tmp_path, "20261014T0930Z", kinds=("db",))
    sets = find_backup_sets(tmp_path)

    assert set(sets) == {"20261014T0930Z"}
    assert len(sets["20261014T0930Z"]) == 2


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


# ---------------------------------------------------------------------------
# remove_remote_staging (best-effort cleanup)
# ---------------------------------------------------------------------------


class _RaisingClient:
    """Stand-in whose exec_command raises the given exception."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def exec_command(self, command: str, timeout: float | None = None):
        raise self._exc


def test_remove_remote_staging_swallows_command_failure(
    capsys: pytest.CaptureFixture,
) -> None:
    """A failing rm command is reported as a warning, not raised."""
    import common as _common

    original = _common.run_remote_cmd_checked

    def failing_checked(
        cl: object, command: str, timeout: object = None
    ) -> str:
        raise RemoteCommandError(command, 1, "permission denied")

    _common.run_remote_cmd_checked = failing_checked  # type: ignore
    try:
        client = _RaisingClient(RuntimeError("unused"))
        remove_remote_staging(client, "/tmp/s")  # type: ignore[arg-type]
    finally:
        _common.run_remote_cmd_checked = original  # type: ignore
    err = capsys.readouterr().err
    assert "WARNING: could not remove remote staging" in err
    assert "permission denied" in err


def test_remove_remote_staging_swallows_transport_failure(
    capsys: pytest.CaptureFixture,
) -> None:
    """A dropped SSH connection must not raise from the cleanup path."""
    import paramiko

    client = _RaisingClient(paramiko.SSHException("connection dropped"))
    remove_remote_staging(client, "/tmp/staging")  # type: ignore[arg-type]
    err = capsys.readouterr().err
    assert "WARNING: could not remove remote staging" in err
    assert "connection dropped" in err


def test_remove_remote_staging_swallows_oserror(
    capsys: pytest.CaptureFixture,
) -> None:
    client = _RaisingClient(OSError("socket closed"))
    remove_remote_staging(client, "/tmp/staging")  # type: ignore[arg-type]
    err = capsys.readouterr().err
    assert "WARNING: could not remove remote staging" in err
    assert "socket closed" in err


def test_original_error_survives_failed_cleanup(
    capsys: pytest.CaptureFixture,
) -> None:
    """The masking scenario: cleanup failure must not replace the error."""
    import paramiko

    client = _RaisingClient(paramiko.SSHException("connection dropped"))
    try:
        try:
            raise ChecksumError("checksum mismatch for backup.tar.gz")
        except ChecksumError:
            # This is what run_backup's handler does on cleanup.
            remove_remote_staging(
                client, "/tmp/staging"  # type: ignore[arg-type]
            )
            raise
    except ChecksumError as exc:
        assert "checksum mismatch" in str(exc)
        assert "connection dropped" not in str(exc)
    else:
        pytest.fail("original error was lost")
    err = capsys.readouterr().err
    assert "WARNING" in err


# ---------------------------------------------------------------------------
# remove_remote_file (best-effort credential-file cleanup)
# ---------------------------------------------------------------------------


def test_remove_remote_file_swallows_transport_failure(
    capsys: pytest.CaptureFixture,
) -> None:
    """A dropped connection during cnf cleanup must not raise."""
    import paramiko

    client = _RaisingClient(paramiko.SSHException("connection dropped"))
    remove_remote_file(client, "/tmp/staging/my.cnf")  # type: ignore[arg-type]
    err = capsys.readouterr().err
    assert "WARNING: could not remove remote file" in err
    assert "connection dropped" in err


def test_remove_remote_file_swallows_oserror(
    capsys: pytest.CaptureFixture,
) -> None:
    client = _RaisingClient(OSError("socket closed"))
    remove_remote_file(client, "/tmp/staging/my.cnf")  # type: ignore[arg-type]
    err = capsys.readouterr().err
    assert "WARNING: could not remove remote file" in err
    assert "socket closed" in err


def test_remove_remote_file_swallows_command_failure(
    capsys: pytest.CaptureFixture,
) -> None:
    """A failing rm command is reported as a warning, not raised."""
    import common as _common

    original = _common.run_remote_cmd_checked

    def failing_checked(
        cl: object, command: str, timeout: object = None
    ) -> str:
        raise RemoteCommandError(command, 1, "permission denied")

    _common.run_remote_cmd_checked = failing_checked  # type: ignore
    try:
        client = _RaisingClient(RuntimeError("unused"))
        # type: ignore[arg-type]
        remove_remote_file(client, "/tmp/staging/my.cnf")
    finally:
        _common.run_remote_cmd_checked = original  # type: ignore
    err = capsys.readouterr().err
    assert "WARNING: could not remove remote file" in err
    assert "permission denied" in err
