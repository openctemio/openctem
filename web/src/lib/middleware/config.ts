/**
 * Route classes for the proxy (src/proxy.ts).
 *
 * Every page route requires a tenant session unless it is listed here. A
 * prefix matches on a path-segment boundary: `/login` covers `/login` and
 * `/login/x`, not `/loginx`.
 */

/** Pages that open without any session. */
export const PUBLIC_ROUTES = [
  '/login',
  '/register',
  '/forgot-password',
  '/reset-password',
  // One-time setup link for an account an administrator created (the user has
  // no session yet). Same token mechanism as /reset-password.
  '/set-password',
  // Invitation preview: an invited person without an account must be able to
  // see it and choose "Sign in" or "Create your account". The page only calls
  // the public preview endpoint until they act.
  '/invitations',
  '/verify-email',
  // OAuth / SSO provider callbacks: the session cookie is set by these pages.
  '/auth/callback',
  '/auth/sso/callback',
  '/auth/error',
  // Platform admin console sign-in (RFC-022): the TOTP step and the platform
  // IdP callback. The rest of /admin is ADMIN_CONSOLE_ROOT.
  '/admin/login',
  // Metadata routes (app/icon.tsx, app/apple-icon.tsx): the sign-in page's
  // favicon must load without a session.
  '/icon',
  '/apple-icon',
  // The operator's legal documents (built-in templates when
  // LEGAL_PAGES_ENABLED=true, 404 otherwise): linked from the sign-in page.
  '/terms',
  '/privacy',
] as const

export type PublicRoute = (typeof PUBLIC_ROUTES)[number]

/**
 * The platform admin console (RFC-022). It has its own session, separate from
 * the tenant session, so it gets its own rule and its own sign-in page.
 */
export const ADMIN_CONSOLE_ROOT = '/admin'
export const ADMIN_CONSOLE_LOGIN = '/admin/login'

/** The tenant app's sign-in page. */
export const LOGIN_PATH = '/login'

/** API routes (the /api/v1 BFF, /api/auth/*, /api/health) handle their own auth. */
export const API_PREFIX = '/api'

/**
 * The query parameter that carries the page to return to after sign-in. The
 * /login page also accepts the older `redirect` and `returnTo`.
 */
export const NEXT_PARAM = 'next'
