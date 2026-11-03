/**
 * The platform administration console: its own Next.js app (RFC-022
 * revision 21), built from this directory (`npm run build:console`) into its
 * own image (openctem-console). It shares the web app's installed packages
 * and imports the shared code (UI components, i18n, API helpers) from
 * ../src through the `@/` alias; the tenant app never imports anything from
 * here. It serves only the console, at the root of its own site.
 */
import { existsSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { NextConfig } from 'next'

/** web/: the root that holds node_modules and the shared source. */
const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

const OVERLAY_ROOT = '../src/ee'
const STUB_ROOT = '../src/extension-default'
const OVERLAY_DIR = path.join(webRoot, 'src', 'ee')

/**
 * Edition switch (api/docs/development/editions.md, "Web"). The `@extension/*`
 * modules resolve to the empty stub in src/extension-default, or with EDITION=ee to
 * the overlay mounted at src/ee. A default production build refuses to run
 * while an overlay is mounted, so a Community image can never carry
 * overlay pages; an EDITION=ee build without the overlay fails to resolve.
 */
const EDITION = (process.env.EDITION || '').trim()
if (EDITION !== '' && EDITION !== 'ee') {
  throw new Error(`EDITION must be unset or "ee", got "${EDITION}"`)
}
if (EDITION !== 'ee' && process.env.NODE_ENV === 'production' && existsSync(OVERLAY_DIR)) {
  throw new Error(`${OVERLAY_DIR} is mounted: build with EDITION=ee, or remove the overlay`)
}
const EDITION_ALIASES = {
  '@extension/*': EDITION === 'ee' ? `${OVERLAY_ROOT}/*` : `${STUB_ROOT}/*`,
}

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  devIndicators: false,
  output: 'standalone',
  // Trace and bundle from web/, so the shared source and packages resolve.
  outputFileTracingRoot: webRoot,
  turbopack: { root: webRoot, resolveAlias: EDITION_ALIASES },

  /**
   * Response headers of every console response. The per-request nonce CSP is
   * set by src/proxy.ts. Together they keep a page of another origin (the
   * tenant site included) from framing the console, holding a window handle
   * on it, embedding its resources or reading its responses.
   */
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          // HTTPS only from the first visit on: in host mode (its own host
          // name) nothing else sets it. Browsers ignore it over plain HTTP.
          { key: 'Strict-Transport-Security', value: 'max-age=31536000' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
          { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
          { key: 'Origin-Agent-Cluster', value: '?1' },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
          },
        ],
      },
      {
        // Pages and API responses are never cached; hashed static assets are.
        source: '/((?!_next/static/).*)',
        headers: [{ key: 'Cache-Control', value: 'no-store' }],
      },
    ]
  },

  allowedDevOrigins: (process.env.NEXT_ALLOWED_DEV_ORIGINS ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean),
}

export default nextConfig
