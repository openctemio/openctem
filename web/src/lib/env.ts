/**
 * Environment Variables Configuration
 *
 * This file provides type-safe access to environment variables.
 *
 * Variable naming conventions:
 * - NEXT_PUBLIC_* : Accessible in both client and server code
 * - No prefix     : Server-only (API routes, Server Actions, Server Components)
 */

/**
 * Check if we're in Docker build mode (skip validation)
 */
const isDockerBuild = process.env.DOCKER_BUILD === 'true' || process.env.CI === 'true'

/**
 * Gets an environment variable with optional default
 * @param key - Environment variable name
 * @param defaultValue - Optional default value
 */
function getEnvVar(key: string, defaultValue?: string): string {
  const value = process.env[key]

  // During Docker build or CI, return default or empty
  if (isDockerBuild) {
    return value || defaultValue || ''
  }

  // Return value or default (no warnings for optional vars)
  return value || defaultValue || ''
}

/**
 * Resolves the backend API URL for server-side fetch.
 * Replaces "localhost" with "127.0.0.1" to avoid Node.js IPv6 resolution
 * issues where localhost may resolve to ::1 and the backend isn't listening on IPv6.
 */
function resolveBackendApiUrl(): string {
  const url = getEnvVar('BACKEND_API_URL', 'http://localhost:8080')
  return url.replace('localhost', '127.0.0.1')
}

/**
 * The API's console listener (ADMIN_API_URL, e.g. http://api:8081) for the
 * platform console's proxy; the main API URL when unset (the console then
 * shares the API's main listener).
 */
function resolveAdminApiUrl(): string {
  const url = getEnvVar('ADMIN_API_URL', '')
  return url ? url.replace('localhost', '127.0.0.1') : resolveBackendApiUrl()
}

// ============================================
// PUBLIC ENVIRONMENT VARIABLES
// (Accessible from both client and server)
// ============================================

export const env = {
  // API Configuration - Single source of truth for backend API URL
  api: {
    /** Backend API URL for server-side fetch (e.g., http://api:8080) - Single source of truth */
    url: resolveBackendApiUrl(),
    /** The API's console listener, for /api/v1/admin (ADMIN_API_URL). */
    adminUrl: resolveAdminApiUrl(),
    /**
     * WebSocket base URL for direct backend connection.
     * WebSocket cannot go through Next.js proxy due to HTTP upgrade requirements.
     * In development: Set to backend URL (e.g., http://localhost:8080)
     * In production: Usually same as app URL if nginx routes /api/v1/ws to backend
     */
    wsBaseUrl: getEnvVar('NEXT_PUBLIC_WS_BASE_URL', ''),
  },

  // Cookie names. Fixed: the API, this console and the gateway must agree on
  // them, and a NEXT_PUBLIC_* value read through process.env[key] is not
  // inlined into the browser bundle, so an override applied on the server only.
  auth: {
    cookieName: 'auth_token',
    refreshCookieName: 'refresh_token',
  },
  cookies: {
    tenant: 'app_tenant',
    userInfo: 'app_user_info',
    pendingTenants: 'app_pending_tenants',
  },

  // Application
  app: {
    url: getEnvVar('NEXT_PUBLIC_APP_URL', 'http://localhost:3000'),
    env: getEnvVar('NODE_ENV', 'development') as 'development' | 'production' | 'test',
  },

  // Feature Flags
  features: {
    /**
     * Enable dynamic sidebar badges (shows counts from API)
     * Set to 'true' to enable. Disabled by default to reduce API calls on page load.
     * Affected badges: Findings, Credential Leaks, Asset Groups
     */
    sidebarBadges: getEnvVar('NEXT_PUBLIC_ENABLE_SIDEBAR_BADGES', 'false') === 'true',

    /**
     * Use real API data instead of mock data
     * Default: true (use real API)
     * Set to 'false' to use mock data for development without backend
     */
    useRealApi: getEnvVar('NEXT_PUBLIC_USE_REAL_API', 'true') !== 'false',
  },
} as const

// ============================================
// SERVER-ONLY ENVIRONMENT VARIABLES
// (Only accessible on server side)
// ============================================

export const serverEnv = {
  // Security
  security: {
    // Secure cookies are ON by default; production MUST be served over HTTPS.
    // Disable explicitly (SECURE_COOKIES=false) only for local http development.
    secureCookies: getEnvVar('SECURE_COOKIES', 'true') !== 'false',
  },

  // Token management
  token: {
    cookieMaxAge: parseInt(getEnvVar('COOKIE_MAX_AGE', '604800'), 10),
  },
} as const

// ============================================
// VALIDATION
// ============================================

/**
 * Validates environment variables
 * Call this in next.config.ts to fail fast on missing vars
 */
export function validateEnv() {
  // Skip validation during Docker build or CI
  if (isDockerBuild) {
    console.log('⏭️  Skipping env validation (Docker/CI build)')
    return
  }

  const warnings: string[] = []

  // Always required: Backend API URL (server-side only)
  if (!process.env.BACKEND_API_URL) {
    warnings.push('BACKEND_API_URL is not set (using default: http://localhost:8080)')
  }

  // CSRF needs no secret: the API and the web use the double-submit cookie
  // (a random csrf_token cookie echoed in X-CSRF-Token), so there is none to
  // configure.

  // Log warnings
  if (warnings.length > 0) {
    console.warn(
      `\n${'─'.repeat(60)}\n` +
        `⚠️  Environment Configuration Warnings\n` +
        `${'─'.repeat(60)}\n\n` +
        warnings.map((w, i) => `${i + 1}. ${w}`).join('\n\n') +
        `\n\n${'─'.repeat(60)}\n`
    )
  } else {
    console.log('✅ Environment variables validated successfully')
  }
}

// ============================================
// HELPER FUNCTIONS
// ============================================

/** Check if running in production */
export const isProduction = () => env.app.env === 'production'

/** Check if running in development */
export const isDevelopment = () => env.app.env === 'development'

/** Check if running on server side */
export const isServer = () => typeof window === 'undefined'

/** Check if running on client side */
export const isClient = () => typeof window !== 'undefined'

/** Check if local auth is enabled (always true for OSS) */
export const isLocalAuthEnabled = () => true

/** Check if only local auth is enabled (always true for OSS) */
export const isLocalAuthOnly = () => true

// ============================================
// TYPE EXPORTS
// ============================================

export type Env = typeof env
export type ServerEnv = typeof serverEnv
