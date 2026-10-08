/**
 * Server-side helpers for the session cookies the Next routes manage.
 *
 * CSRF. Every state-changing request (POST, PUT, PATCH, DELETE) that reaches
 * the web server, signed in or not, must pass `csrfRejection`:
 *
 * 1. Same origin. `Sec-Fetch-Site`, when the browser sends it, must be
 *    `same-origin` (or `none`). `Origin` (else `Referer`) must name this host;
 *    a request with neither is refused. A cross-site page cannot forge either.
 * 2. Double submit. The JS-readable `csrf_token` cookie must be present and
 *    the `X-CSRF-Token` header must equal it (constant-time compare). A
 *    missing cookie is a refusal, not a pass.
 *
 * The cookie exists before sign-in: `src/proxy.ts` sets it on every page
 * response that lacks one. So the pre-session steps (sign-in, registration,
 * password reset, invitation, second factor, SSO start: Server Actions, which
 * `src/proxy.ts` checks) are covered like the signed-in calls (login CSRF).
 * Browser code echoes the cookie in `X-CSRF-Token` on every same-origin
 * state-changing fetch (`src/lib/csrf-client.ts`, installed by
 * `src/instrumentation-client.ts`, so Next's Server Action requests carry it
 * too). Route handlers call `csrfRejection` themselves (`src/app/api/**`;
 * `csrf-route-guard.test.ts` fails on one that does not). The `/api/v1` proxy
 * forwards the pair to the API, which checks it again. A cross-site page can
 * make the browser attach cookies to a request but cannot read the cookie to
 * set the header.
 *
 * Rotation: the API returns a rotated refresh token only in `Set-Cookie`
 * (S-3), never in the JSON body. A route that keeps the old cookie leaves the
 * browser with a revoked token, and the next refresh signs the user out.
 */
import { NextRequest, NextResponse } from 'next/server'

import { env } from '@/lib/env'

export const CSRF_COOKIE = 'csrf_token'
export const CSRF_HEADER = 'X-CSRF-Token'

const secure = () => process.env.SECURE_COOKIES !== 'false'

/** A new random double-submit token (256 bits, hex). */
export function newCsrfToken(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** Cookie options for the JS-readable CSRF cookie. */
export function csrfCookieOptions() {
  return {
    httpOnly: false, // read by browser code to fill X-CSRF-Token
    secure: secure(),
    sameSite: 'lax' as const,
    path: '/',
    maxAge: 7 * 24 * 60 * 60,
  }
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

/** True for the methods the CSRF check applies to (all but GET, HEAD, OPTIONS). */
export function isStateChangingMethod(method: string): boolean {
  return !SAFE_METHODS.has(method.toUpperCase())
}

/**
 * The hosts this request was addressed to: the first `X-Forwarded-Host` (set
 * by the gateway), the `Host` header, and the host of the URL Next.js built.
 * A browser sets these itself; a cross-site page cannot choose them.
 */
function ownHosts(request: NextRequest): Set<string> {
  const hosts = new Set<string>()
  const forwarded = request.headers.get('x-forwarded-host')?.split(',')[0]?.trim()
  if (forwarded) hosts.add(forwarded.toLowerCase())
  const host = request.headers.get('host')?.trim()
  if (host) hosts.add(host.toLowerCase())
  if (request.nextUrl?.host) hosts.add(request.nextUrl.host.toLowerCase())
  return hosts
}

/** True when the browser says the request comes from this origin. */
function isSameOrigin(request: NextRequest): boolean {
  const site = request.headers.get('sec-fetch-site')
  if (site && site !== 'same-origin' && site !== 'none') return false
  const origin = request.headers.get('origin')
  if (origin === 'null') return false // sandboxed frame, data: URL, cross-origin redirect
  const source = origin || request.headers.get('referer')
  if (!source) return false
  try {
    return ownHosts(request).has(new URL(source).host.toLowerCase())
  } catch {
    return false
  }
}

function forbidden(message: string): NextResponse {
  return NextResponse.json(
    { success: false, error: { code: 'CSRF_INVALID', message } },
    { status: 403 }
  )
}

/**
 * Checks a request for CSRF (see the file comment). Returns the 403 to send,
 * or null when the request may proceed. Safe methods always pass.
 *
 * `extraCookies` names further double-submit cookies the header may match
 * (the admin console's `admin_csrf`); `csrf_token` is always accepted.
 */
export function csrfRejection(
  request: NextRequest,
  extraCookies: readonly string[] = []
): NextResponse | null {
  if (!isStateChangingMethod(request.method)) return null
  if (!isSameOrigin(request)) return forbidden('Cross-origin request refused')

  const header = request.headers.get(CSRF_HEADER) ?? ''
  const values = [CSRF_COOKIE, ...extraCookies]
    .map((name) => request.cookies.get(name)?.value)
    .filter((v): v is string => !!v)
  if (!header || values.length === 0) return forbidden('Missing or invalid CSRF token')
  // Compare with every candidate, so the time taken does not tell which matched.
  let ok = false
  for (const value of values) ok = constantTimeEqual(header, value) || ok
  return ok ? null : forbidden('Missing or invalid CSRF token')
}

/**
 * Sets a fresh CSRF cookie on a page response when the request carried none,
 * so the pre-session forms on that page have a token to echo.
 */
export function ensureCsrfCookie(request: NextRequest, response: NextResponse): void {
  if (!request.cookies.get(CSRF_COOKIE)?.value) {
    response.cookies.set(CSRF_COOKIE, newCsrfToken(), csrfCookieOptions())
  }
}

/** The value of cookie `name` in a backend response's Set-Cookie headers. */
export function setCookieValue(response: Response, name: string): string | undefined {
  const headers = response.headers as Headers & { getSetCookie?: () => string[] }
  const all =
    typeof headers.getSetCookie === 'function'
      ? headers.getSetCookie()
      : (headers.get('set-cookie')?.split(/,(?=[^;]+?=)/) ?? [])
  for (const raw of all) {
    const pair = raw.split(';', 1)[0] ?? ''
    const eq = pair.indexOf('=')
    if (eq === -1 || pair.slice(0, eq).trim() !== name) continue
    const value = pair.slice(eq + 1).trim()
    if (!value) return undefined
    try {
      return decodeURIComponent(value)
    } catch {
      return value
    }
  }
  return undefined
}

/** The rotated refresh token of a backend refresh/token-exchange response. */
export function rotatedRefreshToken(
  response: Response,
  body?: { refresh_token?: string }
): string | undefined {
  return body?.refresh_token || setCookieValue(response, env.auth.refreshCookieName)
}
