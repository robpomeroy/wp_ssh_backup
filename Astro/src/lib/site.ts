/** Static site metadata and outbound links. */

export const site = {
  name: 'WP SSH Backup',
  tagline: 'Automated, secure, and reliable backups for your WordPress site.',
  description:
    'WP SSH Backup takes full WordPress backups — files and database — over SSH, verifies every byte with SHA-256, and restores with one command. Free and open source.',
  url: 'https://wpsshbackup.pomeroy.me',
  repo: 'https://github.com/robpomeroy/wp_ssh_backup',
  releases: 'https://github.com/robpomeroy/wp_ssh_backup/releases',
  latestRelease: 'https://github.com/robpomeroy/wp_ssh_backup/releases/latest',
  changelog: 'https://github.com/robpomeroy/wp_ssh_backup/blob/main/CHANGELOG.md',
  licence: 'https://github.com/robpomeroy/wp_ssh_backup/blob/main/LICENCE',
  issues: 'https://github.com/robpomeroy/wp_ssh_backup/issues',
  docs: 'https://github.com/robpomeroy/wp_ssh_backup#readme',
  author: 'Rob Pomeroy',
  authorUrl: 'https://pomeroy.me',
} as const;

export const nav = [
  { label: 'Features', href: '#features' },
  { label: 'How it works', href: '#how-it-works' },
  { label: 'Quick start', href: '#quick-start' },
  { label: 'FAQ', href: '#faq' },
] as const;

export type Feature = {
  title: string;
  body: string;
  icon: 'ssh' | 'shield' | 'check' | 'lock' | 'clock' | 'restore';
};

export const features: Feature[] = [
  {
    title: 'Files and database, over SSH',
    body: 'One run packs your WordPress root into a gzip tarball and dumps the database — with WP-CLI when it is available, otherwise mysqldump.',
    icon: 'ssh',
  },
  {
    title: 'Verified, not just downloaded',
    body: 'SHA-256 checksums are generated on the server and re-verified locally. A transfer that fails verification is never published as a backup.',
    icon: 'check',
  },
  {
    title: 'Host keys are pinned',
    body: 'Servers whose host key is not already trusted are rejected outright. No silent first-use acceptance, so a man-in-the-middle cannot harvest your credentials.',
    icon: 'shield',
  },
  {
    title: 'Atomic publication',
    body: 'Verified downloads are published under their final names with a no-replace operation, so a concurrent run can never overwrite a good backup.',
    icon: 'lock',
  },
  {
    title: 'Retention that prunes itself',
    body: 'Set RETENTION_DAYS and old backup sets are removed after each successful run. Set it to 0 to keep everything.',
    icon: 'clock',
  },
  {
    title: 'Restore in one command',
    body: 'Pick the newest set containing what you need, or name a specific backup id. Archives are validated member by member before anything is extracted.',
    icon: 'restore',
  },
];

export const steps = [
  {
    title: 'Stage on the server',
    body: 'A uniquely named staging directory is created as a sibling of your site root, so concurrent runs never collide.',
  },
  {
    title: 'Dump and pack',
    body: 'The database is exported and the site root is tarred, excluding the staging directory and wp-content/cache.',
  },
  {
    title: 'Verify checksums',
    body: 'SHA-256 manifests are produced remotely, the artifacts are downloaded as .part files, and every digest is re-checked locally.',
  },
  {
    title: 'Publish atomically',
    body: 'Only verified files are linked into place under their final names. Staging is cleaned up; retention then prunes old sets.',
  },
] as const;

export const configRows = [
  ['SSH_HOST', 'Hostname or IP address of the hosting server.'],
  ['SSH_PORT', 'SSH port (usually 22).'],
  ['SSH_USER', 'SSH user to log in as.'],
  ['SSH_KEY_PATH', 'Path to a private key. Leave empty to use your SSH agent.'],
  ['SSH_PASSWORD', 'Optional password authentication. Prefer keys.'],
  ['SSH_KNOWN_HOSTS', 'Optional known_hosts file. Defaults to ~/.ssh/known_hosts.'],
  ['WP_SITE_ROOT', 'Absolute path to the WordPress root on the server.'],
  ['WP_CLI_PATH', 'Optional explicit path to wp if it is not on the remote PATH.'],
  ['BACKUP_DIR', 'Local directory where backups are stored.'],
  ['RETENTION_DAYS', 'Delete local sets older than this many days (0 disables).'],
] as const;

export const faqs = [
  {
    q: 'Do I need Python installed?',
    a: 'No. Every release ships standalone executables for Linux x86-64, Windows x86-64, macOS Apple silicon and macOS Intel. Download the file for your platform, make it executable and run it. If you prefer, you can still run it from a source checkout with Python 3.10 or later.',
  },
  {
    q: 'Which hosts does it work with?',
    a: 'Any host that gives you SSH access and has GNU tar, gzip and sha256sum — which is virtually every Linux host. For database backups you also need WP-CLI or mysqldump. Restore specifically requires GNU tar, because it validates archive members with tar --quoting-style=shell-always.',
  },
  {
    q: 'Why does macOS say the app cannot be opened?',
    a: 'The macOS binaries are not signed or notarised, because the project has no Apple Developer account. Gatekeeper blocks them on first run. Right-click the file in Finder and choose Open, or run xattr -d com.apple.quarantine on it. The binary itself is an unmodified PyInstaller build.',
  },
  {
    q: 'What exactly does restore overwrite?',
    a: 'Restoring replaces the current site files and imports the database. Take a fresh backup immediately beforehand if you might need to roll back. Before extracting, restore audits the existing tree for symlinks and hard links that extraction would traverse or replace, and refuses rather than writing outside the site root.',
  },
  {
    q: 'Is there a web interface?',
    a: 'No. WP SSH Backup is a command-line tool, designed to be scheduled with cron or Task Scheduler. That keeps it small, auditable and easy to run on a server with no extra services to maintain.',
  },
  {
    q: 'How is it licensed?',
    a: 'GNU General Public License v3. You are free to use, study, modify and redistribute it. Contributions are welcome via pull request.',
  },
] as const;
