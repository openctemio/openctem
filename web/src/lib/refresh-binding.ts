/**
 * The refresh client binding: a random per-browser secret that ties the API's
 * refresh-token rotation grace to this browser (server/docs/architecture/session-refresh.md).
 *
 * `src/proxy.ts` sets it on the first page response that lacks it, in its own
 * HttpOnly cookie. `browserContextHeaders` forwards it to the API as
 * `X-Refresh-Client-Binding` on the server-to-server calls (`/auth/refresh`,
 * `/auth/token`). It never travels with the refresh token, so a copy of the
 * refresh token alone cannot collect a rotated successor inside the grace.
 * It grants nothing on its own: without a valid refresh token it is useless.
 */
import type { NextRequest, NextResponse } from 'next/server'

export const REFRESH_BINDING_COOKIE = 'refresh_bind'
export const REFRESH_BINDING_HEADER = 'X-Refresh-Client-Binding'

const BINDING_RE = /^[0-9a-f]{64}$/

/** A new random binding (256 bits, hex). */
export function newRefreshBinding(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** True when `value` is a binding this server issued (64 hex characters). */
export function isRefreshBinding(value: string | undefined | null): value is string {
  return typeof value === 'string' && BINDING_RE.test(value)
}

/** The binding in a raw `Cookie` request header, if it is well formed. */
export function refreshBindingFromCookieHeader(cookieHeader: string | null): string | undefined {
  if (!cookieHeader) return undefined
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1 || part.slice(0, eq).trim() !== REFRESH_BINDING_COOKIE) continue
    const value = part.slice(eq + 1).trim()
    return isRefreshBinding(value) ? value : undefined
  }
  return undefined
}

/** Cookie options: HttpOnly (browser code never reads it), whole site. */
export function refreshBindingCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.SECURE_COOKIES !== 'false',
    sameSite: 'lax' as const,
    path: '/',
    maxAge: 400 * 24 * 60 * 60,
  }
}

/** Sets a new binding on a page response when the request carried no valid one. */
export function ensureRefreshBindingCookie(request: NextRequest, response: NextResponse): void {
  if (!isRefreshBinding(request.cookies.get(REFRESH_BINDING_COOKIE)?.value)) {
    response.cookies.set(REFRESH_BINDING_COOKIE, newRefreshBinding(), refreshBindingCookieOptions())
  }
}
