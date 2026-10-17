/**
 * The platform administration console: its own Next.js app (RFC-022
 * revision 21), built from this directory (`npm run build:console`) into its
 * own image (openctem-console). It shares the web app's installed packages
 * and imports the shared code (UI components, i18n, API helpers) from
 * ../src through the `@/` alias; the tenant app never imports anything from
 * here. It serves only the console, at the root of its own site.
 */
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { NextConfig } from 'next'

/** web/: the root that holds node_modules and the shared source. */
const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  devIndicators: false,
  output: 'standalone',
  // Trace and bundle from web/, so the shared source and packages resolve.
  outputFileTracingRoot: webRoot,
  turbopack: { root: webRoot },

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
