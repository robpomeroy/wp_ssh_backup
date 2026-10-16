"""Backup a WordPress site over SSH.

Creates gzip tarballs of the WordPress database and/or site root on the remote
host, downloads them via SFTP, verifies SHA-256 checksums locally, removes the
remote staging directory and prunes old local backups.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import os
import posixpath
import sys
import time

import paramiko

from common import (
    ChecksumError,
    Config,
    MissingArtifactError,
    WPSSHBackupError,
    backup_id,
    checksum_name,
    connect,
    db_archive_name,
    detect_wp_cli,
    files_archive_name,
    human_size,
    load_config,
    mysql_client_config,
    parse_sha256sum_output,
    prune_local_backups,
    read_wp_db_settings,
    remove_remote_file,
    remove_remote_staging,
    run_remote_cmd,
    run_remote_cmd_checked,
    shquote,
    sftp_download,
    split_db_host,
    staging_dir_for,
    trap_rm_action,
    write_remote_file,
    verify_local_checksum,
)


# ---------------------------------------------------------------------------
# Remote artifact creation
# ---------------------------------------------------------------------------


def tar_db_dump(
    client: paramiko.SSHClient,
    staging: str,
    dump_name: str,
    ts: str,
) -> str:
    """
    Tar the SQL dump in the staging dir; return the tarball filename.

    Args:
        client: An active SSH client connected to the remote host.
        staging: The remote staging directory containing the SQL dump.
        dump_name: The filename of the SQL dump within the staging directory.
        ts: A timestamp string used to generate the archive name.

    Returns:
        The filename of the created tarball.
    """
    archive_name = db_archive_name(ts)
    archive_path = posixpath.join(staging, archive_name)
    tar_command = (
        f"tar czf {shquote(archive_path)} -C {shquote(staging)} "
        f"{shquote(dump_name)}"
    )
    run_remote_cmd_checked(client, tar_command, timeout=1800)
    return archive_name


def create_db_dump(
    client: paramiko.SSHClient,
    config: Config,
    staging: str,
    ts: str,
) -> str:
    """
    Create a tarball of a SQL dump in the staging dir.

    Args:
        client: An active SSH client connected to the remote host.
        config: The configuration object containing site and database details.
        staging: The remote staging directory where the SQL dump will be
            created.
        ts: A timestamp string used to generate the archive name.

    Returns:
        The filename of the created tarball.
    """
    dump_name = f"wp-db-{ts}.sql"
    dump_path = posixpath.join(staging, dump_name)
    wp_cli = detect_wp_cli(client, config)

    if wp_cli:
        command = (
            f"cd {shquote(config.wp_site_root)} && "
            f"{shquote(wp_cli)} db export {shquote(dump_path)} "
            f"--add-drop-table"
        )
        run_remote_cmd_checked(client, command, timeout=1800)
        return tar_db_dump(client, staging, dump_name, ts)

    # Fallback: parse wp-config.php and run mysqldump with a temporary
    # defaults-extra-file so the password never appears on a command line.
    sftp = client.open_sftp()
    try:
        settings = read_wp_db_settings(sftp, config.wp_site_root)
    finally:
        sftp.close()

    host, port, socket_path = split_db_host(settings["DB_HOST"])
    cnf_name = f"my-{ts}.cnf"
    cnf_path = posixpath.join(staging, cnf_name)
    cnf_body = mysql_client_config(
        host=host,
        user=settings["DB_USER"],
        password=settings["DB_PASSWORD"],
        port=port,
        socket=socket_path,
    )

    sftp = client.open_sftp()
    try:
        write_remote_file(sftp, cnf_path, cnf_body, mode=0o600)
    finally:
        sftp.close()

    # trap guarantees the credentials file is removed even if mysqldump fails.
    command = (
        f"cd {shquote(staging)} && "
        f"trap {trap_rm_action(cnf_path)} EXIT && "
        f"mysqldump --defaults-extra-file={shquote(cnf_path)} "
        f"{shquote(settings['DB_NAME'])} > {shquote(dump_path)}"
    )
    try:
        run_remote_cmd_checked(client, command, timeout=1800)
    finally:
        # Belt and braces: remove the cnf even if the shell above died
        # oddly. Best-effort: if the connection dropped, the removal must
        # not mask the original mysqldump failure.
        remove_remote_file(client, cnf_path)

    return tar_db_dump(client, staging, dump_name, ts)


def create_files_archive(
    client: paramiko.SSHClient,
    config: Config,
    staging: str,
    ts: str,
) -> str:
    """
    Create a tarball of the site root in the staging dir.

    Args:
        client: An active SSH client connected to the remote host.
        config: The configuration object containing site and database details.
        staging: The remote staging directory where the tarball will be
            created.
        ts: A timestamp string used to generate the archive name.

    Returns:
        The filename of the created tarball.
    """
    archive_name = files_archive_name(ts)
    archive_path = posixpath.join(staging, archive_name)
    # The staging dir is a sibling of the site root, so it is never included
    # in a tar of the site root's contents; only cache dirs need excluding.
    # GNU tar treats options after the member operand as positional: they
    # have no effect and it exits with status 2, so --exclude must come
    # before the "." member.
    command = (
        f"tar czf {shquote(archive_path)} "
        f"--exclude=./wp-content/cache "
        f"-C {shquote(config.wp_site_root)} ."
    )
    run_remote_cmd_checked(client, command, timeout=3600)
    return archive_name


def generate_remote_checksums(
    client: paramiko.SSHClient,
    staging: str,
    archive_names: list[str],
) -> None:
    """
    Write a .sha256 file next to each archive on the remote host.

    Args:
        client: An active SSH client connected to the remote host.
        staging: The remote staging directory containing the archives.
        archive_names: A list of archive filenames for which to generate
            checksums.

    Returns:
        None. The function writes .sha256 files next to each archive on the
        remote host.
    """
    for name in archive_names:
        command = (
            f"cd {shquote(staging)} && "
            f"sha256sum {shquote(name)} > {shquote(checksum_name(name))}"
        )
        run_remote_cmd_checked(client, command)


# ---------------------------------------------------------------------------
# Download and verification
# ---------------------------------------------------------------------------


def _temp_download_name(name: str) -> str:
    """Temporary name used until a download has been verified."""
    return name + ".part"


def _discard_temp_downloads(created_paths: list[Path]) -> None:
    """Remove only owned temporary files without masking the original error."""
    for path in created_paths:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            print(
                f"WARNING: could not remove temporary download {path}: {exc}",
                file=sys.stderr,
            )


def download_artifacts(
    sftp: paramiko.SFTPClient,
    staging: str,
    archive_names: list[str],
    backup_dir: Path,
    *,
    created_paths: list[Path] | None = None,
) -> dict[str, Path]:
    """
    Download each archive and its .sha256 file into backup_dir.

    Files land under temporary names (the final name plus a ".part"
    suffix) so a failed or interrupted transfer can never be mistaken for
    a backup set: the suffix does not match the backup filename pattern,
    and publish_downloads() renames the files only after checksum
    verification has passed.

    Args:
        sftp: An active SFTP client connected to the remote host.
        staging: The remote staging directory containing the archives.
        archive_names: A list of archive filenames to download.
        backup_dir: The local directory where the files will be stored.
        created_paths: If supplied, records files created by this run, even
            if a transfer fails before this function returns.

    Returns:
        A dictionary mapping each archive's final name (and its checksum
        filename) to the temporary local Path it was downloaded to.
    """
    local_paths: dict[str, Path] = {}
    for name in archive_names:
        local_paths[name] = sftp_download(
            sftp,
            posixpath.join(staging, name),
            backup_dir / _temp_download_name(name),
            created_paths=created_paths,
        )
        local_paths[checksum_name(name)] = sftp_download(
            sftp,
            posixpath.join(staging, checksum_name(name)),
            backup_dir / _temp_download_name(checksum_name(name)),
            created_paths=created_paths,
        )
    return local_paths


def _publish_no_replace(temp_path: Path, final_path: Path) -> None:
    """Publish temp_path at final_path atomically, never replacing.

    Uses os.link() so the publication either happens or fails with
    FileExistsError: there is no window in which another process can
    create final_path and have it silently overwritten. On filesystems
    without hard-link support (some Windows volumes), falls back to
    os.rename(), which on Windows also refuses to replace an existing
    destination.
    """
    try:
        os.link(temp_path, final_path)
    except FileExistsError as exc:
        raise FileExistsError(
            f"Refusing to overwrite existing backup file: {final_path}"
        ) from exc
    except OSError:
        if os.name != "nt":
            raise
        # Windows fallback: rename is atomic and refuses to replace an
        # existing destination (it fails instead of overwriting).
        try:
            os.rename(temp_path, final_path)
        except FileExistsError as exc:
            raise FileExistsError(
                f"Refusing to overwrite existing backup file: {final_path}"
            ) from exc


def publish_downloads(
    temp_paths: dict[str, Path],
    archive_names: list[str],
    backup_dir: Path,
) -> dict[str, Path]:
    """
    Publish verified temporary downloads under their final names.

    Only called after verify_downloads() has accepted every file, so a
    file that reaches BACKUP_DIR under its final name is always a
    checksum-verified artifact.

    Publication is transactional and atomic: each final path is created
    with a no-replace operation (hard link, or a no-replace rename on
    filesystems without hard-link support), so a file that appears at a
    final name after the pre-check — from another backup process or a
    local attacker who can write BACKUP_DIR — can never be silently
    overwritten. If publication fails part-way, the final paths this run
    created are removed so the caller's cleanup can discard the still
    intact temporary downloads. A failed run therefore never leaves a
    partial final-name set in BACKUP_DIR.

    Args:
        temp_paths: Mapping from final names to the temporary paths
            returned by download_artifacts().
        archive_names: The archive filenames that were downloaded.
        backup_dir: The local directory that receives the final names.

    Returns:
        A dictionary mapping each archive and its checksum filename to
        the final local Path object.

    Raises:
        FileExistsError: If any final path already exists, including one
            created between the pre-check and publication.
    """
    finals: list[str] = []
    for name in archive_names:
        finals.extend((name, checksum_name(name)))

    # Pre-check: refuse to overwrite anything that already exists under
    # a final name (e.g. a file from another run) BEFORE publishing the
    # first file, so the common conflict case fails fast with a friendly
    # error and no half-done publication. This check alone is not the
    # guarantee — the no-replace publication below is: it fails if a
    # path appears here between the check and the publication. Symlinks
    # are rejected too, including dangling ones: Path.exists() is False
    # for a broken link, but publication would silently replace it,
    # breaking the preservation promise.
    for final in finals:
        final_path = backup_dir / final
        if final_path.exists() or final_path.is_symlink():
            raise FileExistsError(
                f"Refusing to overwrite existing backup file: {final_path}"
            )

    published: list[Path] = []
    try:
        for final in finals:
            final_path = backup_dir / final
            _publish_no_replace(temp_paths[final], final_path)
            published.append(final_path)
    except BaseException:
        # Roll back the final paths this run created. They were made by
        # this run's no-replace publications, so unlinking them can
        # never remove a pre-existing file. The temporary downloads were
        # not unlinked, so the caller's _discard_temp_downloads()
        # cleanup — which must never touch final paths it did not
        # create — discards them.
        for final_path in reversed(published):
            try:
                final_path.unlink(missing_ok=True)
            except OSError as exc:
                print(
                    "WARNING: could not roll back published backup file "
                    f"{final_path}: {exc}",
                    file=sys.stderr,
                )
        raise
    # Publication succeeded: remove the temporary downloads. A leftover
    # temp is only a warning — the finals are complete and verified, so
    # publication is not undone over a cleanup failure.
    for final in finals:
        temp_path = temp_paths[final]
        try:
            temp_path.unlink(missing_ok=True)
        except OSError as exc:
            print(
                f"WARNING: could not remove temporary download {temp_path}: "
                f"{exc}",
                file=sys.stderr,
            )
    return {final: backup_dir / final for final in finals}


def verify_downloads(
    local_paths: dict[str, Path],
    archive_names: list[str],
) -> None:
    """
    Recompute SHA-256 locally using the downloaded .sha256 files.

    Args:
        local_paths: A dictionary mapping each archive and its checksum
            filename to the corresponding local Path object.
        archive_names: A list of archive filenames to verify.
    """
    for name in archive_names:
        local_path = local_paths[name]
        if not local_path.is_file():
            raise MissingArtifactError(
                f"Downloaded file missing: {local_path}"
            )
        checksum_file = local_paths[checksum_name(name)]
        try:
            text = checksum_file.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            # An undecodable manifest is a checksum failure, not a crash:
            # raising ChecksumError keeps the remote staging dir for retry
            # and reports the problem through the normal error path.
            raise ChecksumError(
                f"{checksum_file} is not valid UTF-8 and cannot be parsed "
                f"as a checksum manifest: {exc}"
            ) from exc
        digests = parse_sha256sum_output(text)
        if name not in digests:
            raise ChecksumError(
                f"{checksum_file} contains no digest for {name}"
            )
        verify_local_checksum(local_path, digests[name])


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def create_staging_dir(
    client: paramiko.SSHClient, config: Config, bid: str
) -> str:
    """
    Create this run's exclusive remote staging directory.

    Uses a bare mkdir (no -p) so the command fails if the directory already
    exists: two concurrent runs in the same minute have different backup ids
    and therefore different directories, and a collision (astronomically
    unlikely) aborts instead of sharing artifacts.

    The directory is created with -m 700 so a permissive umask (e.g. a
    shared-group 0002) never leaves it writable by other accounts between
    creation and the later 0700 chmod.

    The 0700 chmod is issued separately by the caller (inside its cleanup
    scope): mkdir and chmod chained with && would leave an orphaned
    directory on the host if mkdir succeeded but chmod failed, before
    run_backup's cleanup block was entered.

    Args:
        client: An active SSH client connected to the remote host.
        config: The backup configuration.
        bid: This run's backup identifier.

    Returns:
        The staging directory path.

    Raises:
        WPSSHBackupError: If the staging directory already exists.
    """
    staging = staging_dir_for(config.wp_site_root, bid)
    code, _, err = run_remote_cmd(
        client, f"mkdir -m 700 {shquote(staging)}"
    )
    if code != 0:
        raise WPSSHBackupError(
            f"Could not create staging directory {staging}: "
            f"{err.strip() or 'already exists?'}"
        )
    return staging


def run_backup(
    client: paramiko.SSHClient,
    config: Config,
    include_files: bool,
    include_database: bool,
    bid: str,
) -> dict[str, Path]:
    """
    Run the full backup flow; return local artifact paths by name.

    Args:
        client: An active SSH client connected to the remote host.
        config: The backup configuration.
        include_files: Whether to include the WordPress files in the backup.
        include_database: Whether to include the WordPress database in the
            backup.
        bid: This run's unique backup identifier.

    Returns:
        A dictionary mapping each archive and its checksum filename to the
        corresponding local Path object.
    """
    staging = create_staging_dir(client, config, bid)
    backup_dir = config.backup_dir
    print(f"Remote staging directory: {staging}")

    archive_names: list[str] = []
    try:
        # Mode 0700 keeps other host users out of the directory that will
        # hold the database credentials file and the archives. It runs
        # INSIDE the cleanup block: if it fails, the directory this run
        # just created is removed instead of being orphaned on the host.
        run_remote_cmd_checked(
            client, f"chmod 700 {shquote(staging)}"
        )

        if include_database:
            started = time.monotonic()
            db_archive = create_db_dump(client, config, staging, bid)
            archive_names.append(db_archive)
            elapsed = time.monotonic() - started
            print(f"Database archive created ({elapsed:.1f}s)")

        if include_files:
            started = time.monotonic()
            files_archive = create_files_archive(client, config, staging, bid)
            archive_names.append(files_archive)
            elapsed = time.monotonic() - started
            print(f"Files archive created ({elapsed:.1f}s)")

        generate_remote_checksums(client, staging, archive_names)

        # Download under temporary names and publish only verified files:
        # a bad pair left in BACKUP_DIR under its final name would be
        # advertised by find_backup_sets() as a complete set, and a
        # default restore could then select the corrupt newest backup
        # instead of a valid older one.
        published = False
        created_paths: list[Path] = []
        try:
            with client.open_sftp() as sftp:
                temp_paths = download_artifacts(
                    sftp, staging, archive_names, backup_dir,
                    created_paths=created_paths,
                )
            verify_downloads(temp_paths, archive_names)
            local_paths = publish_downloads(
                temp_paths, archive_names, backup_dir
            )
            published = True
        finally:
            if not published:
                # Remove every file this run downloaded, whether the
                # failure was a checksum mismatch or a dropped transfer.
                # The remote staging decision is made by the handlers
                # below (kept for a checksum retry, removed otherwise).
                _discard_temp_downloads(created_paths)
        print("Local checksum verification passed.")
    except ChecksumError:
        # Keep the remote staging dir so the transfer can be retried.
        print(
            "ERROR: checksum verification failed. The remote staging "
            f"directory {staging} has been kept for retry.",
            file=sys.stderr,
        )
        raise
    except (
        WPSSHBackupError,
        OSError,
        paramiko.SSHException,
    ):
        # Any other failure — including base WPSSHBackupError raised by, for
        # example, an invalid WP_CLI_PATH — must not leave staging behind.
        # ChecksumError is handled above and keeps staging for retry.
        remove_remote_staging(client, staging)
        raise

    remove_remote_staging(client, staging)
    return local_paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Back up a WordPress site over SSH."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--files",
        action="store_true",
        help="Back up only the WordPress files.",
    )
    group.add_argument(
        "--database",
        action="store_true",
        help="Back up only the WordPress database.",
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="Back up both files and database (the default).",
    )
    args = parser.parse_args(argv)

    neither = not (args.files or args.database)
    include_files = args.files or args.all or neither
    include_database = args.database or args.all or neither

    try:
        config = load_config()
        bid = backup_id()
        client = connect(config)
    except WPSSHBackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        local_paths = run_backup(
            client, config, include_files, include_database, bid
        )
    except (WPSSHBackupError, OSError, paramiko.SSHException) as exc:
        # run_backup cleans up staging and re-raises transport/SFTP failures;
        # report them here rather than letting them escape as a traceback.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()

    try:
        removed = prune_local_backups(config.backup_dir, config.retention_days)
        if removed:
            print(f"Pruned local backup sets: {', '.join(removed)}")

        total = sum(p.stat().st_size for p in local_paths.values())
    except OSError as exc:
        print(
            f"ERROR: Backup {bid} was downloaded and verified in "
            f"{config.backup_dir}, but local post-processing failed: {exc}",
            file=sys.stderr,
        )
        return 1
    print(f"Backup complete: {bid} ({human_size(total)} downloaded).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
