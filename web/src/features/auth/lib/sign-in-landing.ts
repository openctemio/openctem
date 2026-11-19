/**
 * Where a person lands right after a social sign-in (and whenever the web has
 * a session but no organization selected). Server only.
 *
 * The decision comes from the person's memberships, never from a refusal:
 *
 * - no organization they can open: the account space (`/welcome`, or the page
 *   they came for when an account session may open it, such as an
 *   invitation), with an account-only token;
 * - exactly one: that organization's token. When the organization does not
 *   admit this session yet (it requires two-factor authentication), the
 *   person keeps the account-only token and goes to the two-factor setup,
 *   which opens the organization afterwards. When it refuses the session for
 *   a reason the console cannot fix in place (its identity provider, the
 *   account's own sign-in, a verified address, ...), the account space opens
 *   with that reason and its one next step;
 * - several: the organization picker.
 *
 * Every token request is checked by the API (membership, the organization's
 * sign-in rules); the ids here are never trusted on their own.
 */

import { cookies } from 'next/headers'

import { authEndpoints, userEndpoints } from '@/lib/api/endpoints'
import { browserContextHeaders } from '@/lib/api/browser-context-headers'
import { env } from '@/lib/env'
import { rotatedRefreshToken } from '@/lib/server-auth-cookies'

import { requestAccountToken, storeAccountSession } from './account-session'

/** One row of GET /users/me/tenants (the fields the landing reads). */
export interface MembershipRow {
  id: string
  slug: string
  name: string
  role: string
  /** Set when the organization cannot be opened (suspended, expired, ...). */
  blocked_reason?: string
  /**
   * What the organization answers this session (account token only): `open`,
   * or the code its token request would refuse with. Read-only on the API.
   */
  admission?: string
}

export type Landing =
  | { kind: 'organization'; tenantId: string }
  | { kind: 'choose' }
  | { kind: 'two_factor'; tenantId: string }
  | {
      kind: 'account'
      /**
       * The one organization refused this session: the API's code and the
       * organization's slug (from the person's own membership list), so the
       * account space names the reason and its next step.
       */
      refusal?: { code: string; slug: string }
    }
  | { kind: 'unavailable' }
  | { kind: 'signed_out' }

/** The first decision, from the memberships alone (pure, unit-tested). */
export function landingFor(
  rows: MembershipRow[]
):
  | { kind: 'one'; row: MembershipRow }
  | { kind: 'choose'; open: MembershipRow[] }
  | { kind: 'account' } {
  const open = rows.filter((r) => !r.blocked_reason)
  if (open.length === 1) return { kind: 'one', row: open[0] }
  if (open.length > 1) return { kind: 'choose', open }
  return { kind: 'account' }
}

/** The admission of an organization that opens for this session. */
const ADMISSION_OPEN = 'open'

/** Codes of an organization that wants this session's second factor. */
const TWO_FACTOR_CODES = new Set(['MFA_ENROLLMENT_REQUIRED'])

const WEEK = 7 * 24 * 60 * 60

function cookieBase() {
  return {
    secure: process.env.SECURE_COOKIES !== 'false',
    sameSite: 'lax' as const,
    path: '/',
  }
}

async function listMemberships(accessToken: string): Promise<MembershipRow[] | null> {
  try {
    const response = await fetch(`${env.api.url}${userEndpoints.myTenants()}`, {
      headers: { Authorization: `Bearer ${accessToken}`, ...(await browserContextHeaders()) },
      cache: 'no-store',
    })
    if (!response.ok) return null
    const body = (await response.json()) as unknown
    return Array.isArray(body) ? (body as MembershipRow[]) : null
  } catch {
    return null
  }
}

type Exchange = { ok: true } | { ok: false; code?: string; status: number }

/** Exchanges the refresh token for the organization's token and stores it. */
async function openOrganization(row: MembershipRow, refreshToken: string): Promise<Exchange> {
  let response: Response
  try {
    response = await fetch(`${env.api.url}${authEndpoints.token()}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(await browserContextHeaders()) },
      body: JSON.stringify({ refresh_token: refreshToken, tenant_id: row.id }),
    })
  } catch {
    return { ok: false, status: 0 }
  }
  const body = (await response.json().catch(() => ({}))) as {
    access_token?: string
    refresh_token?: string
    expires_in?: number
    tenant_id?: string
    tenant_slug?: string
    role?: string
    code?: string
  }
  if (!response.ok || !body.access_token) {
    return { ok: false, code: body.code, status: response.status }
  }
  const jar = await cookies()
  const base = cookieBase()
  jar.set(env.auth.cookieName, body.access_token, {
    ...base,
    httpOnly: true,
    maxAge: body.expires_in || 900,
  })
  const rotated = rotatedRefreshToken(response, body)
  if (rotated) {
    jar.set(env.auth.refreshCookieName, rotated, { ...base, httpOnly: true, maxAge: WEEK })
  }
  jar.set(
    env.cookies.tenant,
    JSON.stringify({
      id: body.tenant_id,
      slug: body.tenant_slug,
      name: row.name || body.tenant_slug,
      role: body.role,
    }),
    { ...base, httpOnly: false, maxAge: WEEK }
  )
  jar.delete(env.cookies.accountOnly)
  jar.delete(env.cookies.pendingTenants)
  return { ok: true }
}

/**
 * Decides and prepares the landing for the session in the request's cookies.
 * It starts from an account-only token (any signed-in person can have one),
 * reads the memberships with it, then opens the one organization when there
 * is exactly one.
 */
export async function prepareLanding(): Promise<Landing> {
  const jar = await cookies()
  const refreshToken = jar.get(env.auth.refreshCookieName)?.value
  if (!refreshToken) return { kind: 'signed_out' }

  const account = await requestAccountToken(refreshToken)
  if (!account.ok) {
    return account.code === 'SESSION' ? { kind: 'signed_out' } : { kind: 'unavailable' }
  }
  await storeAccountSession(account)
  // An organization selected by an earlier session never carries over.
  jar.delete(env.cookies.tenant)

  const rows = await listMemberships(account.accessToken)
  if (!rows) return { kind: 'account' }
  const first = landingFor(rows)
  if (first.kind === 'account') return { kind: 'account' }
  if (first.kind === 'choose') {
    // The picker is an organization page: not an account-only session.
    jar.delete(env.cookies.accountOnly)
    jar.set(
      env.cookies.pendingTenants,
      JSON.stringify(first.open.map(({ id, slug, name, role }) => ({ id, slug, name, role }))),
      { ...cookieBase(), httpOnly: false, maxAge: 60 * 60 }
    )
    return { kind: 'choose' }
  }

  // The listing already says this organization refuses the session for a
  // reason the console cannot fix in place: no token request (the API would
  // refuse it the same way), the account space names it.
  const admission = first.row.admission
  if (admission && admission !== ADMISSION_OPEN && !TWO_FACTOR_CODES.has(admission)) {
    return { kind: 'account', refusal: { code: admission, slug: first.row.slug } }
  }

  // The account token rotated the refresh token: only the new one is valid
  // (presenting the spent one would end the session as a replay).
  if (!account.refreshToken) return { kind: 'account' }
  const opened = await openOrganization(first.row, account.refreshToken)
  if (opened.ok) return { kind: 'organization', tenantId: first.row.id }
  if (opened.status === 401) return { kind: 'signed_out' }
  // No answer, too many requests or a server failure decides nothing about
  // the organization: say the landing could not start (never a plain account
  // space that reads as "no organization").
  if (opened.status === 0 || opened.status === 429 || opened.status >= 500) {
    return { kind: 'unavailable' }
  }
  if (opened.code && TWO_FACTOR_CODES.has(opened.code)) {
    return { kind: 'two_factor', tenantId: first.row.id }
  }
  // The organization does not admit this session for another reason: the
  // account space says what is missing, and what to do about it.
  return opened.code
    ? { kind: 'account', refusal: { code: opened.code, slug: first.row.slug } }
    : { kind: 'account' }
}
