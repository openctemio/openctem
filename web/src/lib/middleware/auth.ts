/**
 * Server-side route protection for the proxy (src/proxy.ts).
 *
 * The proxy decides from cookies alone: is a session cookie present and does
 * it have the right shape. It never calls the API and never verifies a
 * signature or an expiry; the API does that on every call. So:
 *
 * - no session cookie (or a malformed one) on a protected page: redirect to
 *   /login?next=<the page>, and clear the tenant-selection cookies;
 * - a session cookie that LOOKS valid but is stale or revoked: the page loads,
 *   its first API call gets 401, and the client clears the cookies and goes to
 *   /login once (src/lib/auth/session-expired.ts). The proxy never redirects a
 *   signed-in-looking request, and never sends anyone away from /login, so the
 *   two cannot bounce a browser between them.
 *
 * The /login page uses hasSessionCookie() too, so the proxy and the page agree
 * on what "has a session" means.
 */

import { NextRequest, NextResponse } from 'next/server'

import { env } from '@/lib/env'
import { safeInternalHref } from '@/lib/safe-href'
import {
  ADMIN_CONSOLE_LOGIN,
  ADMIN_CONSOLE_ROOT,
  API_PREFIX,
  LOGIN_PATH,
  NEXT_PARAM,
  PUBLIC_ROUTES,
} from './config'

/** Reads one cookie's value. */
export type CookieReader = (name: string) => string | undefined

// ============================================
// ROUTE CLASSES
// ============================================

/** `path` is `prefix` or below it (segment boundary). */
function underPrefix(path: string, prefix: string): boolean {
  return path === prefix || path.startsWith(`${prefix}/`)
}

/** A page that opens without a session. */
export function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTES.some((route) => underPrefix(pathname, route))
}

export function isApiRoute(pathname: string): boolean {
  return underPrefix(pathname, API_PREFIX)
}

export function isAdminConsoleRoute(pathname: string): boolean {
  return underPrefix(pathname, ADMIN_CONSOLE_ROOT) && !isPublicRoute(pathname)
}

/** A page that needs the tenant session. Default: every page not listed public. */
export function requiresAuth(pathname: string): boolean {
  return !isApiRoute(pathname) && !isPublicRoute(pathname) && !isAdminConsoleRoute(pathname)
}

// ============================================
// COOKIE SHAPE
// ============================================

/** Longest cookie value we accept as a token (browsers cap a cookie at 4 KB). */
const MAX_TOKEN_LENGTH = 4096

/** header.payload.signature, base64url. Access and refresh tokens are JWTs. */
const JWT_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/

/** The admin console CSRF nonce: 32 random bytes, base64 (URL alphabet). */
const ADMIN_NONCE_SHAPE = /^[A-Za-z0-9_-]{32,}={0,2}$/

export function looksLikeJwt(value: string | undefined): boolean {
  return !!value && value.length <= MAX_TOKEN_LENGTH && JWT_SHAPE.test(value)
}

/** Cookie names of the tenant session (configurable, like the rest of the app). */
export function sessionCookieNames() {
  return {
    access: env.auth.cookieName,
    refresh: env.auth.refreshCookieName,
    tenant: env.cookies.tenant,
    pendingTenants: env.cookies.pendingTenants,
  }
}

/**
 * The browser holds a tenant session: an access or refresh token cookie
 * shaped like a JWT. Presence and shape only; the API validates it.
 */
export function hasSessionCookie(read: CookieReader): boolean {
  const names = sessionCookieNames()
  if (looksLikeJwt(read(names.access)) || looksLikeJwt(read(names.refresh))) return true
  // Local development sign-in (never in a production build).
  return process.env.NODE_ENV === 'development' && !!read('dev_auth_token')
}

/**
 * The admin console cookie the page request can see. The console session
 * itself (`admin_session`) is scoped to /api/v1/admin, so a page request never
 * carries it; `admin_csrf` is issued and cleared with it, on path `/`, with the
 * same lifetime. It is a hint for the redirect only; the console API checks
 * the real session.
 */
export const ADMIN_CONSOLE_COOKIE = 'admin_csrf'

export function hasAdminConsoleCookie(read: CookieReader): boolean {
  const value = read(ADMIN_CONSOLE_COOKIE)
  return !!value && value.length <= MAX_TOKEN_LENGTH && ADMIN_NONCE_SHAPE.test(value)
}

/** Request helper kept for route handlers (GET /api/version). */
export function isAuthenticated(req: NextRequest): boolean {
  return hasSessionCookie((name) => req.cookies.get(name)?.value)
}

// ============================================
// DECISION
// ============================================

export type AuthDecision =
  | { type: 'allow' }
  | {
      type: 'redirect'
      /** Same-origin path and query of the sign-in page. */
      location: string
      /** Cookies to expire on the redirect response. */
      clearCookies: string[]
    }

export interface AuthRequest {
  pathname: string
  /** The query string with its leading `?`, or ''. */
  search: string
  cookie: CookieReader
}

/**
 * The page to come back to after sign-in, as a same-origin path, or
 * undefined when there is none worth keeping (`/`) or it is not safe.
 */
export function returnPath(pathname: string, search: string): string | undefined {
  // `_rsc` is Next.js's cache-busting parameter on client navigations.
  const params = new URLSearchParams(search)
  params.delete('_rsc')
  const query = params.toString()
  const path = safeInternalHref(query ? `${pathname}?${query}` : pathname)
  if (!path || !path.startsWith('/') || path === '/') return undefined
  return path
}

function withNext(page: string, next: string | undefined): string {
  return next ? `${page}?${NEXT_PARAM}=${encodeURIComponent(next)}` : page
}

/**
 * What the proxy does with a page request. Pure: routes x cookies in, a
 * decision out (unit-tested in __tests__/route-protection.test.ts).
 */
export function decideAuth({ pathname, search, cookie }: AuthRequest): AuthDecision {
  if (isApiRoute(pathname) || isPublicRoute(pathname)) return { type: 'allow' }

  if (isAdminConsoleRoute(pathname)) {
    if (hasAdminConsoleCookie(cookie)) return { type: 'allow' }
    // The console's sign-in page; it sends a browser without a tenant session
    // on to /login itself. Only console paths are carried over.
    return {
      type: 'redirect',
      location: withNext(ADMIN_CONSOLE_LOGIN, returnPath(pathname, search)),
      clearCookies: [],
    }
  }

  if (hasSessionCookie(cookie)) return { type: 'allow' }

  const names = sessionCookieNames()
  // A tenant cookie without a session is stale (the next sign-in picks the
  // team again); a malformed token cookie would only be sent again.
  const clearCookies = [names.tenant, names.pendingTenants, names.access, names.refresh].filter(
    (name) => cookie(name) !== undefined
  )
  return {
    type: 'redirect',
    location: withNext(LOGIN_PATH, returnPath(pathname, search)),
    clearCookies,
  }
}

/**
 * Run decideAuth on a request. Returns the redirect response, or null to let
 * the request through.
 */
export function handleAuth(req: NextRequest): NextResponse | null {
  // Page loads only. A POST to a page path is a Server Action (sign-out among
  // them), which answers for itself; redirecting it would turn the action
  // into a page load of /login and drop what it was doing.
  if (req.method !== 'GET' && req.method !== 'HEAD') return null

  const decision = decideAuth({
    pathname: req.nextUrl.pathname,
    search: req.nextUrl.search,
    cookie: (name) => req.cookies.get(name)?.value,
  })
  if (decision.type === 'allow') return null

  const target = req.nextUrl.clone()
  const [path, query = ''] = decision.location.split('?')
  target.pathname = path
  target.search = query ? `?${query}` : ''
  const response = NextResponse.redirect(target)
  for (const name of decision.clearCookies) {
    response.cookies.set(name, '', { maxAge: 0, path: '/' })
  }
  return response
}
