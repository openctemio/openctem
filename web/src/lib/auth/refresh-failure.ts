/**
 * What the browser does when the session could not be refreshed.
 *
 * Only a dead session ends it: the refresh itself answered 401 (an unknown,
 * spent, revoked or expired refresh token, an expired session, a blocked
 * account), or the session came from another organization's identity
 * provider and must sign in with the account's own sign-in. Everything else
 * keeps the person signed in:
 *
 * - an organization that requires two-factor authentication this session has
 *   not proven: the setup page, which enrolls (or asks for the code) and
 *   opens the organization;
 * - an organization that does not admit this session for another reason
 *   (suspended, its identity provider required): the account space, which
 *   says what is missing; the account settings stay reachable;
 * - a server or network failure: the request fails, nothing is cleared.
 *
 * A 401 from an ordinary API route is never a reason on its own: the client
 * refreshes first and decides from the refresh's answer, and a route that
 * needs an organization (401 TENANT_REQUIRED) sends the person to the account
 * space instead (tenant-required.ts).
 */

export type RefreshFailureAction = 'sign_out' | 'two_factor_setup' | 'account_space' | 'keep'

const SIGN_OUT_CODES = new Set([
  'NO_REFRESH_TOKEN',
  'REFRESH_TOKEN_REUSED',
  'REFRESH_TOKEN_EXPIRED',
  'REFRESH_TOKEN_REVOKED',
  'REFRESH_TOKEN_INVALID',
  'SESSION_EXPIRED',
  'ACCOUNT_SESSION',
  'OWN_SIGN_IN_REQUIRED',
])

const TWO_FACTOR_CODES = new Set(['MFA_ENROLLMENT_REQUIRED'])

// The organization wants its own identity provider (or that provider's proof
// of a second factor): our setup cannot help; the account space says what to do.
const ACCOUNT_SPACE_CODES = new Set([
  'ORGANIZATION_SUSPENDED',
  'SSO_REQUIRED',
  'MFA_IDP_EVIDENCE_REQUIRED',
])

export function refreshFailureAction(status: number, code?: string): RefreshFailureAction {
  if (status === 401) return 'sign_out'
  if (code && SIGN_OUT_CODES.has(code)) return 'sign_out'
  if (code && TWO_FACTOR_CODES.has(code)) return 'two_factor_setup'
  if (code && ACCOUNT_SPACE_CODES.has(code)) return 'account_space'
  return 'keep'
}

/** The two-factor setup page, coming back to the page the person was on. */
export const TWO_FACTOR_SETUP_PATH = '/two-factor-setup'

export function twoFactorSetupHref(back: string, tenantId?: string): string {
  const params = new URLSearchParams({ next: back })
  if (tenantId) params.set('org', tenantId)
  return `${TWO_FACTOR_SETUP_PATH}?${params.toString()}`
}
