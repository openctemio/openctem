/**
 * The account-only session: an access token without an organization, for a
 * signed-in person who has none they can open (api RFC-141). Server only:
 * called from Server Actions and the refresh route, never from the browser.
 *
 * The token reaches only the account routes (profile, security, sessions,
 * sign-in methods, preferences, invitations); the API refuses every other
 * route with 401 TENANT_REQUIRED. The `app_account_only` cookie is a routing
 * hint for the proxy and the layout, not a credential.
 */

import { cookies } from 'next/headers'

import { authEndpoints } from '@/lib/api/endpoints'
import { browserContextHeaders } from '@/lib/api/browser-context-headers'
import { env } from '@/lib/env'
import { rotatedRefreshToken } from '@/lib/server-auth-cookies'

export type AccountSessionResult =
  | { ok: true; accessToken: string; refreshToken?: string; expiresIn: number }
  | { ok: false; code: 'HAS_ORGANIZATION' | 'SESSION' | 'ERROR' }

const WEEK = 7 * 24 * 60 * 60

/** Asks the API for the account-only token; rotates the refresh token. */
export async function requestAccountToken(refreshToken: string): Promise<AccountSessionResult> {
  let response: Response
  try {
    response = await fetch(`${env.api.url}${authEndpoints.accountToken()}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(await browserContextHeaders()) },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
  } catch {
    return { ok: false, code: 'ERROR' }
  }
  if (response.status === 409) return { ok: false, code: 'HAS_ORGANIZATION' }
  if (response.status === 401) return { ok: false, code: 'SESSION' }
  if (!response.ok) return { ok: false, code: 'ERROR' }
  const body = (await response.json().catch(() => null)) as {
    access_token?: string
    refresh_token?: string
    expires_in?: number
  } | null
  if (!body?.access_token) return { ok: false, code: 'ERROR' }
  return {
    ok: true,
    accessToken: body.access_token,
    refreshToken: rotatedRefreshToken(response, body),
    expiresIn: body.expires_in || 900,
  }
}

/**
 * Stores an account-only session in the cookies of the current request
 * (Server Action or route handler context): access token, rotated refresh
 * token, and the marker. The tenant cookie is never set.
 */
export async function storeAccountSession(
  result: Extract<AccountSessionResult, { ok: true }>
): Promise<void> {
  const jar = await cookies()
  const base = {
    secure: process.env.SECURE_COOKIES !== 'false',
    sameSite: 'lax' as const,
    path: '/',
  }
  jar.set(env.auth.cookieName, result.accessToken, {
    ...base,
    httpOnly: true,
    maxAge: result.expiresIn,
  })
  if (result.refreshToken) {
    jar.set(env.auth.refreshCookieName, result.refreshToken, {
      ...base,
      httpOnly: true,
      maxAge: WEEK,
    })
  }
  jar.set(env.cookies.accountOnly, '1', { ...base, httpOnly: true, maxAge: WEEK })
}

/** Ends the account-only marker (the person opened an organization or signed out). */
export async function clearAccountOnlyMarker(): Promise<void> {
  const jar = await cookies()
  jar.delete(env.cookies.accountOnly)
}
