# WP SSH Backup — website

The promotional single-page site for [WP SSH Backup](https://github.com/robpomeroy/wp_ssh_backup),
served at <https://wpsshbackup.pomeroy.me>.

Built with [Astro](https://astro.build) and [Tailwind CSS v4](https://tailwindcss.com).
The output is fully static: no server, no runtime JavaScript framework.

## Requirements

- Node.js 20 or later
- npm 10 or later

## Development

```bash
cd Astro
npm install
npm run dev          # http://localhost:4321
```

## Build

```bash
npm run build        # writes dist/
npm run preview      # serve dist/ locally
```

`dist/` is the deployable root. Upload its contents to any static host; the
`site` value in `astro.config.mjs` is already set to
`https://wpsshbackup.pomeroy.me`, so canonical URLs, the sitemap and the
Open Graph tags are correct without further configuration.

## Release data

`src/lib/releases.ts` queries the GitHub releases API once, at build time, to
populate the version badge and the per-platform download links. If the API is
unreachable, rate-limited or returns an unexpected shape, the build falls back
to the hardcoded version and links to the releases page — a build never fails
because GitHub was down.

To avoid the anonymous rate limit in CI, export a token before building:

```bash
GITHUB_TOKEN=ghp_xxx npm run build
```

When a new release is cut, rebuild and redeploy the site to pick up the new
version. If you would rather not rebuild, bump `FALLBACK_VERSION` in
`src/lib/releases.ts`.

## Structure

```
src/
├─ assets/          hero illustration (cropped from ../images/banner.jpg)
├─ components/      one component per page section, plus ui/ primitives
├─ layouts/         Base.astro — head, SEO, JSON-LD, theme bootstrap
├─ lib/             site.ts (copy and links), releases.ts (build-time API)
├─ pages/           index.astro — the single page
└─ styles/          global.css — Tailwind import, theme tokens, components
public/             favicon, Open Graph image, robots.txt
```

## Editing content

Almost all copy lives in `src/lib/site.ts` — features, the four-step
explanation, the configuration table and the FAQ. Section components read from
it, so text changes rarely require touching markup.

## Theme

Dark is the default. The light theme is applied by setting `data-theme="light"`
on `<html>`; the toggle persists the choice in `localStorage` and an inline
script in `<head>` applies it before first paint, so there is no flash.

Colour tokens are defined once in `src/styles/global.css` under `@theme` and
consumed as Tailwind utilities (`bg-brand`, `text-accent-2`) or CSS variables
(`var(--surface)`, `var(--border)`).

## Analytics

The site uses a self-hosted Plausible instance at `plausible.pomeroy.me`. The
snippet in `src/layouts/Base.astro` is the one Plausible generates for this
site, with the script ID `pa-3N6bc0ZmkV6gEsAQ4JMV4`:

```html
<script async src="https://plausible.pomeroy.me/js/pa-3N6bc0ZmkV6gEsAQ4JMV4.js"></script>
<script>
  window.plausible = window.plausible || function () { (plausible.q = plausible.q || []).push(arguments) };
  plausible.init = plausible.init || function (i) { plausible.o = i || {} };
  plausible.init();
</script>
```

Both tags are `is:inline` so Astro emits them verbatim in `<head>` rather than
bundling them. Optional measurements (outbound links, file downloads, form
submissions) are toggled in the Plausible site settings, not in code — the
script picks them up automatically.

If you move to a different Plausible instance or site, replace the script URL
with the one from **Site settings → General → Site installation**. Remove both
tags if you do not want analytics.

## Licence

The site content describes a GPLv3 project; the site source itself is part of
that repository and carries the same licence.
