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
  // Where a refused sign-up lands (no session): the same page for everyone.
  '/not-set-up',
  // Request access when sign-up is closed, and its emailed confirmation link.
  '/request-access',
  // OAuth / SSO provider callbacks: the session cookie is set by these pages.
  '/auth/callback',
  '/auth/sso/callback',
  // After a sign-in: decides the landing from the memberships (it sends a
  // visitor without a session to /login itself).
  '/auth/continue',
  // Metadata routes (app/icon.tsx, app/apple-icon.tsx, app/opengraph-image.tsx):
  // the sign-in page's favicon and a shared link's preview image must load
  // without a session. They render the instance brand only.
  '/icon',
  '/apple-icon',
  '/opengraph-image',
  // The legal documents (built-in templates when LEGAL_PAGES_ENABLED=true,
  // 404 otherwise): linked from the sign-in page and from each other.
  '/terms',
  '/acceptable-use',
  '/privacy',
  '/dpa',
  '/subprocessors',
] as const

export type PublicRoute = (typeof PUBLIC_ROUTES)[number]

/**
 * The pages a session without an organization (account-only) may open, besides
 * the public ones: the account hub and the personal account pages. Anything
 * else redirects to /welcome. The API enforces the same boundary with its own
 * allow-list of routes; this list only keeps the person off pages that would
 * show errors. Exact paths: `/account/activity` and the other tenant-data
 * account pages are not on it.
 */
export const ACCOUNT_ONLY_PAGES = [
  '/welcome',
  '/account',
  '/account/security',
  '/account/preferences',
  // The second-factor step an organization asks for before it admits the
  // session: a member without it holds only an account session.
  '/two-factor-setup',
] as const

/**
 * Pages a signed-in person opens before an organization is selected (besides
 * ACCOUNT_ONLY_PAGES): the organization picker, organization creation, the
 * ownership invitation and the sign-in consent pages. Every other page works
 * inside an organization: a session that has none selected goes to
 * CONTINUE_PATH first, which picks it from the memberships.
 */
export const NO_ORGANIZATION_PAGES = [
  '/select-tenant',
  '/onboarding',
  '/ownership-invitations',
  '/oauth',
  '/mcp',
] as const

/** Decides the landing of a session that has no organization selected. */
export const CONTINUE_PATH = '/auth/continue'

/** Where an account-only session lands. */
export const WELCOME_PATH = '/welcome'

/** The tenant app's sign-in page. */
export const LOGIN_PATH = '/login'

/** API routes (the /api/v1 BFF, /api/auth/*, /api/health) handle their own auth. */
export const API_PREFIX = '/api'

/**
 * The query parameter that carries the page to return to after sign-in. The
 * /login page also accepts the older `redirect` and `returnTo`.
 */
export const NEXT_PARAM = 'next'
