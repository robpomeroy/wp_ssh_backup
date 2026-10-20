"""One-off helper: point test_common.py at the new module homes.

The wp-config helpers now live in wp_config.py, and the timing and
size helpers in cli.py. The test imports them from their real homes
rather than through the common.py facade, so the facade is only
exercised where it is actually the public surface.
"""

PATH = "tests/test_common.py"

OLD = """from common import (
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
"""

NEW = """from cli import human_size
from common import (
    ChecksumError,
    ConfigError,
    RemoteCommandError,
    backup_id,
    backup_id_from_archive_name,
    checksum_name,
    find_backup_sets,
    load_config,
    parse_backup_id,
    parse_sha256sum_output,
    parse_timestamp,
    prune_local_backups,
    remove_remote_file,
    remove_remote_staging,
    sha256_file,
    shquote,
    split_db_host,
    staging_dir_for,
    trap_rm_action,
    utc_timestamp,
)
from wp_config import _unescape_php, parse_wp_config, strip_php_comments
"""

with open(PATH, "rb") as handle:
    raw = handle.read()

text = raw.decode("utf-8")
crlf = "\r\n" in text
source = text.replace("\r\n", "\n")

if OLD not in source:
    raise SystemExit("block not found")

source = source.replace(OLD, NEW, 1)

if crlf:
    source = source.replace("\n", "\r\n")

with open(PATH, "wb") as handle:
    handle.write(source.encode("utf-8"))

print("done")
