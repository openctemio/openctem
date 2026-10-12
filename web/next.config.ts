import { createRequire } from 'node:module'

import type { NextConfig } from 'next'
import { validateEnv } from './src/lib/env'
import { LEGACY_ROUTE_REDIRECTS } from './src/config/legacy-routes'

// Optional bundle analyzer - only used when ANALYZE=true
let withBundleAnalyzer = (config: NextConfig) => config
if (process.env.ANALYZE === 'true') {
  try {
    // createRequire rather than a bare require(): this file is an ES module, and
    // the analyzer is an optional devDependency that must stay behind a
    // try/catch, so a static import is not an option either.
    const bundleAnalyzer = createRequire(import.meta.url)('@next/bundle-analyzer')
    withBundleAnalyzer = bundleAnalyzer({ enabled: true })
  } catch {
    console.warn(
      'Bundle analyzer not available - install @next/bundle-analyzer to use ANALYZE=true'
    )
  }
}

// Validate environment variables at build time
// This will throw an error if required vars are missing or invalid
if (process.env.NODE_ENV !== 'test') {
  validateEnv()
}

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // No `X-Powered-By: Next.js` on every response: it only tells a scanner
  // which framework (and so which advisories) to try.
  poweredByHeader: false,
  // The dev-only "N" badge sat over the sidebar's last rows on phones. The
  // local stack runs `next dev`, so it showed there too.
  devIndicators: false,
  // Note: reactCompiler requires babel-plugin-react-compiler package
  // Disabled until package is added to dependencies

  /**
   * Output Configuration for Docker
   *
   * 'standalone' mode creates a minimal production build with only required dependencies
   * This significantly reduces Docker image size
   * @see https://nextjs.org/docs/app/api-reference/next-config-js/output
   */
  output: 'standalone',

  /**
   * Renamed routes. Bookmarks keep working: /agents 308s to /sensors, and moved
   * settings pages 308 to their new home, path and query kept.
   * @see src/config/legacy-routes.ts
   */
  async redirects() {
    return LEGACY_ROUTE_REDIRECTS
  },

  /**
   * WebSocket on the UI's own origin (/api/v1/ws). In `next dev` this rewrite
   * proxies the upgrade to the API; it is read when the dev server starts.
   * Production builds leave it out: rewrites are frozen into the build, so the
   * production entry (server-with-ws.mjs) forwards the upgrade instead, to the
   * BACKEND_API_URL of the running deployment.
   */
  async rewrites() {
    if (process.env.NODE_ENV === 'production')
      return { beforeFiles: [], afterFiles: [], fallback: [] }
    const backend = (process.env.BACKEND_API_URL || 'http://localhost:8080').replace(/\/+$/, '')
    return {
      // Before the /api/v1/[...path] route handler, which cannot proxy upgrades.
      beforeFiles: [
        { source: '/api/v1/ws', destination: `${backend}/api/v1/ws` },
        // The API's OAuth metadata and endpoints for MCP clients (RFC-062); in
        // production the gateway sends these paths straight to the API.
        {
          source: '/.well-known/oauth-protected-resource/:path*',
          destination: `${backend}/.well-known/oauth-protected-resource/:path*`,
        },
        {
          source: '/.well-known/oauth-authorization-server',
          destination: `${backend}/.well-known/oauth-authorization-server`,
        },
        { source: '/oauth/authorize', destination: `${backend}/oauth/authorize` },
        { source: '/oauth/token', destination: `${backend}/oauth/token` },
        { source: '/oauth/revoke', destination: `${backend}/oauth/revoke` },
        { source: '/oauth/register', destination: `${backend}/oauth/register` },
      ],
      afterFiles: [],
      fallback: [],
    }
  },

  /**
   * Security Headers
   *
   * Implements security best practices to protect against common vulnerabilities
   * @see https://nextjs.org/docs/app/api-reference/next-config-js/headers
   */
  async headers() {
    return [
      {
        // Apply security headers to all routes
        source: '/:path*',
        headers: [
          // Prevent clickjacking attacks
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          // Prevent MIME type sniffing
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          // Control referrer information
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          // Control which features and APIs can be used
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=()',
          },
          // Content-Security-Policy is set per request by proxy.ts, with a
          // fresh script nonce (src/lib/middleware/csp.ts). A static policy
          // here could only allow inline scripts with 'unsafe-inline'.
        ],
      },
    ]
  },
  // Allowed dev origins for HMR/dev assets. Next.js 16 blocks cross-origin dev
  // requests by default (including HMR WebSockets from LAN IPs), so each developer
  // can add their IPs via NEXT_ALLOWED_DEV_ORIGINS=ip1,ip2 in .env.local.
  // Wildcards are not supported — you must enumerate IPs/hostnames.
  allowedDevOrigins: (process.env.NEXT_ALLOWED_DEV_ORIGINS ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean),
}

export default withBundleAnalyzer(nextConfig)
