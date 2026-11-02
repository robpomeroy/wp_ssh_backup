/**
 * Resolves the current release at build time.
 *
 * The GitHub API is queried once during `astro build`. Any failure — offline
 * build, rate limit, renamed asset — degrades to the hardcoded fallback so a
 * build never breaks because GitHub was unreachable.
 */

const OWNER = 'robpomeroy';
const REPO = 'wp_ssh_backup';
const API = `https://api.github.com/repos/${OWNER}/${REPO}/releases/latest`;

/** Bump this when a release is cut and the site has not been rebuilt against the API. */
const FALLBACK_VERSION = '1.0.0';

export type Platform = {
  id: string;
  label: string;
  arch: string;
  /** Asset filename prefix, as attached to the release. */
  asset: string;
  requirement: string;
  /** Command shown next to the download button. */
  note?: string;
};

export const platforms: Platform[] = [
  {
    id: 'linux-x64',
    label: 'Linux',
    arch: 'x86-64',
    asset: 'wp-ssh-backup-linux-x64',
    requirement: 'glibc 2.28+ (Debian 10, Ubuntu 20.04 or later)',
    note: 'chmod +x wp-ssh-backup-linux-x64',
  },
  {
    id: 'windows-x64',
    label: 'Windows',
    arch: 'x86-64',
    asset: 'wp-ssh-backup-windows-x64.exe',
    requirement: 'Windows 10 or later',
  },
  {
    id: 'macos-arm64',
    label: 'macOS',
    arch: 'Apple silicon',
    asset: 'wp-ssh-backup-macos-arm64',
    requirement: 'macOS 11 or later',
    note: 'chmod +x wp-ssh-backup-macos-arm64',
  },
  {
    id: 'macos-x64',
    label: 'macOS',
    arch: 'Intel',
    asset: 'wp-ssh-backup-macos-x64',
    requirement: 'macOS 10.15 or later',
    note: 'chmod +x wp-ssh-backup-macos-x64',
  },
];

export type ReleaseAsset = { name: string; url: string; size: number };

export type Release = {
  version: string;
  tag: string;
  publishedAt: string | null;
  htmlUrl: string;
  /** True when the data came from the GitHub API rather than the fallback. */
  live: boolean;
  assets: ReleaseAsset[];
};

type GitHubRelease = {
  tag_name?: string;
  name?: string;
  html_url?: string;
  published_at?: string;
  assets?: { name?: string; browser_download_url?: string; size?: number }[];
};

function fallback(): Release {
  return {
    version: FALLBACK_VERSION,
    tag: `v${FALLBACK_VERSION}`,
    publishedAt: null,
    htmlUrl: `https://github.com/${OWNER}/${REPO}/releases/latest`,
    live: false,
    assets: [],
  };
}

export async function getRelease(): Promise<Release> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'wp-ssh-backup-site',
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;

  try {
    const res = await fetch(API, { headers, signal: AbortSignal.timeout(5000) });
    if (!res.ok) {
      console.warn(`[releases] GitHub API returned ${res.status}; using fallback.`);
      return fallback();
    }

    const data = (await res.json()) as GitHubRelease;
    const tag = data.tag_name ?? `v${FALLBACK_VERSION}`;
    const version = tag.replace(/^v/, '');

    const assets = (data.assets ?? [])
      .filter((a): a is { name: string; browser_download_url: string; size?: number } =>
        Boolean(a.name && a.browser_download_url),
      )
      .map((a) => ({ name: a.name, url: a.browser_download_url, size: a.size ?? 0 }));

    return {
      version,
      tag,
      publishedAt: data.published_at ?? null,
      htmlUrl: data.html_url ?? fallback().htmlUrl,
      live: true,
      assets,
    };
  } catch (error) {
    console.warn(`[releases] Could not reach GitHub (${String(error)}); using fallback.`);
    return fallback();
  }
}

/** Download URL for a platform, falling back to the releases page. */
export function downloadUrl(release: Release, platform: Platform): string {
  const match = release.assets.find((a) => a.name === platform.asset);
  return match?.url ?? release.htmlUrl;
}

/** Checksum file for a platform, if the release published one. */
export function checksumUrl(release: Release, platform: Platform): string | null {
  const match = release.assets.find((a) => a.name === `${platform.asset}.sha256`);
  return match?.url ?? null;
}

export function formatDate(iso: string | null): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    timeZone: 'UTC',
  });
}
