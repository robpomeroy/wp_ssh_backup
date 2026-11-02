// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import tailwindcss from '@tailwindcss/vite';

// @tailwindcss/vite resolves its own Vite copy, so its plugin type does not
// match Astro's bundled Vite type. The runtime plugin is compatible.
/** @type {any} */
const tailwind = tailwindcss();

export default defineConfig({
  site: 'https://wpsshbackup.pomeroy.me',
  output: 'static',
  compressHTML: true,
  prefetch: { prefetchAll: true, defaultStrategy: 'viewport' },
  integrations: [sitemap()],
  vite: {
    plugins: [tailwind],
  },
});
