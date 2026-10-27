/**
 * The words for the API's sign-in, SSO, SAML, social-login and invitation
 * refusals. The API answers each with a stable `code` (api/internal/infra/http/
 * handler/auth_error_codes.go) and an English sentence for API clients; the
 * console shows its own text from `errors.auth.<CODE>` in the person's
 * language and never the server's sentence when the code is known.
 */

import type { Translate } from '@/lib/api/error-message'

import type { LoginErrorCode } from './login-error'

/** Every code the sign-in API can answer with. Kept in step with the API table by a test. */
export const AUTH_ERROR_CODES = [
  'INVALID_CREDENTIALS',
  'ACCOUNT_LOCKED',
  'ACCOUNT_SUSPENDED',
  'EMAIL_NOT_VERIFIED',
  'SIGNUP_NOT_AVAILABLE',
  'SSO_REQUIRED',
  'ORGANIZATION_CREATION_DISABLED',
  'PLATFORM_ADMIN_MEMBERSHIP',
  'EMAIL_ALREADY_EXISTS',
  'INVALID_RESET_TOKEN',
  'INVALID_VERIFICATION_TOKEN',
  'PASSWORD_MISMATCH',
  'SESSION_LIMIT_REACHED',
  'ORGANIZATION_SUSPENDED',
  'ORGANIZATION_ACCESS_DENIED',
  'ORGANIZATION_REQUIRED',
  'MEMBERSHIP_SUSPENDED',
  'MFA_CHALLENGE_INVALID',
  'MFA_CODE_INVALID',
  'MFA_ENROLLMENT_REQUIRED',
  'MFA_IDP_EVIDENCE_REQUIRED',
  'MFA_NOT_SUPPORTED',
  'MFA_ALREADY_ENABLED',
  'MFA_NOT_ENABLED',
  'MFA_NO_PENDING_SETUP',
  'MFA_UNAVAILABLE',
  'TOKEN_INVALID',
  'REFRESH_TOKEN_INVALID',
  'REFRESH_TOKEN_EXPIRED',
  'REFRESH_TOKEN_REUSED',
  'REFRESH_TOKEN_REVOKED',
  'SESSION_EXPIRED',
  'SESSION_REVOKED',
  'SESSION_NOT_FOUND',
  'TOKEN_FAMILY_MISMATCH',
  'SSO_NOT_CONFIGURED',
  'SSO_PROVIDER_INACTIVE',
  'SSO_INVALID_STATE',
  'SSO_INVALID_REDIRECT',
  'SSO_EXCHANGE_FAILED',
  'SSO_USERINFO_FAILED',
  'SSO_INVALID_ID_TOKEN',
  'SSO_NO_EMAIL',
  'SSO_REGISTRATION_DISABLED',
  'SSO_DOMAIN_NOT_ALLOWED',
  'SSO_AWAITING_APPROVAL',
  'SSO_NOT_A_MEMBER',
  'ACCOUNT_LINK_REQUIRED',
  'SSO_DIFFERENT_METHOD',
  'EMAIL_UNVERIFIED_AT_IDP',
  'USE_ADMIN_CONSOLE',
  'SAML_FAILED',
  'LIMIT_REACHED',
  'OAUTH_DISABLED',
  'OAUTH_PROVIDER_DISABLED',
  'OAUTH_INVALID_PROVIDER',
  'OAUTH_INVALID_STATE',
  'OAUTH_EXCHANGE_FAILED',
  'OAUTH_USERINFO_FAILED',
  'OAUTH_ACCOUNT_EXISTS',
  'OAUTH_NO_EMAIL',
  'IDENTITY_LINKED_ELSEWHERE',
  'PROVIDER_ALREADY_LINKED',
  'LAST_SIGN_IN_METHOD',
  'IDENTITY_MANAGED_BY_ORGANIZATION',
  'IDENTITY_NOT_FOUND',
  'INVITATION_ALREADY_MEMBER',
  'INVITATION_MEMBERSHIP_SUSPENDED',
  'MEMBERSHIP_SUSPENDED_REACTIVATE',
  'INVITEE_NOT_ON_VERIFIED_DOMAIN',
  'INVITEE_DOMAIN_NOT_ALLOWED',
  'INVITATION_NO_LONGER_VALID',
  'PERSONAL_ACCOUNTS_BLOCKED',
  'INVITATION_RESEND_TOO_SOON',
  'INVITATIONS_RATE_LIMITED',
  'PASSWORD_TOO_SHORT',
  'PASSWORD_TOO_LONG',
  'PASSWORD_BREACHED',
  'PASSWORD_NO_UPPERCASE',
  'PASSWORD_NO_LOWERCASE',
  'PASSWORD_NO_NUMBER',
  'PASSWORD_NO_SPECIAL',
  'CAPTCHA_REQUIRED',
] as const

export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[number]

const KNOWN: ReadonlySet<string> = new Set(AUTH_ERROR_CODES)

/** The console's text for a sign-in code; undefined for any other value. */
export function describeAuthCode(
  code: string | undefined | null,
  t: Translate,
  vars?: Parameters<Translate>[2]
): string | undefined {
  if (!code || !KNOWN.has(code)) return undefined
  return t(`errors.auth.${code}`, undefined, vars)
}

/**
 * What to show for a failed sign-in step: the coded text when the code is
 * known, else the caller's own sentence. The server's sentence is never shown.
 */
export function authErrorText(
  code: string | undefined | null,
  t: Translate,
  fallback: string,
  vars?: Parameters<Translate>[2]
): string {
  return describeAuthCode(code, t, vars) ?? fallback
}

/**
 * The `/login?error=` code for a failed callback, from the API's error code.
 * Anything not listed is the generic callback failure, so the page never shows
 * more than the person can act on.
 */
const LOGIN_CODE_FOR_API_CODE: Readonly<Record<string, LoginErrorCode>> = {
  SSO_AWAITING_APPROVAL: 'awaiting_approval',
  SSO_NOT_A_MEMBER: 'not_member',
  LIMIT_REACHED: 'no_seat',
  SSO_DOMAIN_NOT_ALLOWED: 'domain_not_allowed',
  ACCOUNT_LINK_REQUIRED: 'link_required',
  SSO_REQUIRED: 'sso_required',
  SSO_DIFFERENT_METHOD: 'different_method',
  USE_ADMIN_CONSOLE: 'use_console',
  EMAIL_UNVERIFIED_AT_IDP: 'email_unverified_at_idp',
  SAML_FAILED: 'saml_failed',
  ACCOUNT_SUSPENDED: 'account_suspended',
  ORGANIZATION_SUSPENDED: 'organization_unavailable',
  ORGANIZATION_ACCESS_DENIED: 'not_member',
  EMAIL_NOT_VERIFIED: 'email_not_verified',
  OAUTH_ACCOUNT_EXISTS: 'account_exists',
}

export function loginErrorCodeFor(code: string | undefined | null): LoginErrorCode {
  if (!code || !Object.prototype.hasOwnProperty.call(LOGIN_CODE_FOR_API_CODE, code)) {
    return 'callback_failed'
  }
  return LOGIN_CODE_FOR_API_CODE[code]
}
