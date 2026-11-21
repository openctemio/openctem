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
 *   (suspended, its identity provider required, its identity provider's
 *   proof of a second factor, a verified address, a work account): the
 *   account space, which names the reason and its one next step
 *   (welcomeNoticeHref); the account settings stay reachable;
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

// The organization does not admit this session for a reason our setup cannot
// fix in place: the account space names it with its one next step.
//
// ORGANIZATION_ACCESS_DENIED: the person is no longer a member of the
// organization the tenant cookie names (removed, or left). The refresh route
// clears that cookie, so the next refresh renews the account token and the
// account space lists the organizations they still belong to.
const ACCOUNT_SPACE_CODES = new Set([
  'ORGANIZATION_ACCESS_DENIED',
  'ORGANIZATION_SUSPENDED',
  'SSO_REQUIRED',
  'MFA_IDP_EVIDENCE_REQUIRED',
  'EMAIL_NOT_VERIFIED',
  'PERSONAL_ACCOUNTS_BLOCKED',
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

/**
 * Why the account space was opened, shown there with its one next step. Only
 * these values show anything (a crafted link cannot put text on the page).
 */
export type WelcomeNotice =
  | 'sso_required'
  | 'idp_mfa_required'
  | 'organization_suspended'
  | 'email_not_verified'
  | 'personal_accounts_blocked'
  | 'own_sign_in_required'

const NOTICE_FOR_CODE: Record<string, WelcomeNotice> = {
  SSO_REQUIRED: 'sso_required',
  MFA_IDP_EVIDENCE_REQUIRED: 'idp_mfa_required',
  ORGANIZATION_SUSPENDED: 'organization_suspended',
  EMAIL_NOT_VERIFIED: 'email_not_verified',
  PERSONAL_ACCOUNTS_BLOCKED: 'personal_accounts_blocked',
  // Only the sign-in landing (no organization open yet) shows it: a refresh
  // refused with it still ends the session (SIGN_OUT_CODES), as before.
  OWN_SIGN_IN_REQUIRED: 'own_sign_in_required',
}

const NOTICES: ReadonlySet<string> = new Set(Object.values(NOTICE_FOR_CODE))

// An organization slug as the API issues them; anything else is dropped.
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/

/** The account space for a refusal code, naming the organization that refused. */
export function welcomeNoticeHref(code: string | undefined, orgSlug?: string): string {
  const notice = code ? NOTICE_FOR_CODE[code] : undefined
  if (!notice) return '/welcome'
  const params = new URLSearchParams({ notice })
  if (orgSlug && SLUG.test(orgSlug)) params.set('org', orgSlug)
  return `/welcome?${params.toString()}`
}

/** Reads a notice from the account space's URL: a known value and a valid slug, or nothing. */
export function readWelcomeNotice(
  notice: string | null | undefined,
  org: string | null | undefined
): { notice: WelcomeNotice; org?: string } | undefined {
  if (!notice || !NOTICES.has(notice)) return undefined
  return { notice: notice as WelcomeNotice, org: org && SLUG.test(org) ? org : undefined }
}
