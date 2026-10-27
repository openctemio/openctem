/**
 * Error codes carried to the sign-in page as `/login?error=<code>`.
 *
 * The page shows the message for a known code and a generic message for
 * anything else. It used to show the raw parameter, so a crafted link such
 * as `/login?error=Your account is locked, call +1...` put any text an
 * attacker chose on the sign-in page. Redirects that land on /login send one
 * of these codes, never free text (an identity provider's error_description
 * included).
 */
export const LOGIN_ERROR_CODES = [
  /** The provider in the callback URL is not one this app supports. */
  'invalid_provider',
  /** The identity provider returned an error or the user cancelled there. */
  'provider_error',
  /** The callback arrived without its code or state. */
  'missing_params',
  /** The sign-in could not be started (no authorization URL). */
  'start_failed',
  /** The callback could not be completed (state mismatch, exchange refused). */
  'callback_failed',
  /** A just-in-time sign-up is held for an administrator's approval. */
  'awaiting_approval',
  /** The organization's single sign-on does not admit this person. */
  'not_member',
  /** The organization has no free seat for a new member. */
  'no_seat',
  /** The email domain is not allowed for the organization. */
  'domain_not_allowed',
  /** An account with this email exists: sign in first, then link. */
  'link_required',
  /** The organization (or address) requires its single sign-on. */
  'sso_required',
  /** The email belongs to an account that signs in another way. */
  'different_method',
  /** A platform administrator signs in on the admin console. */
  'use_console',
  /** The identity provider did not verify the email address. */
  'email_unverified_at_idp',
  /** The single sign-on response was refused. */
  'saml_failed',
  'account_suspended',
  'membership_suspended',
  'organization_unavailable',
  'email_not_verified',
  /**
   * The provider's email names an account that signs in another way: sign in
   * with it, then link the provider in Account > Security.
   */
  'account_exists',
] as const

export type LoginErrorCode = (typeof LOGIN_ERROR_CODES)[number]

const KNOWN: ReadonlySet<string> = new Set(LOGIN_ERROR_CODES)

/** Catalog key and English fallback for the message of a ?error= value. */
export function loginErrorMessage(param: string | null | undefined): {
  key: string
  fallback: string
} {
  const code = param && KNOWN.has(param) ? (param as LoginErrorCode) : 'generic'
  return { key: `auth.loginError.${code}`, fallback: FALLBACKS[code] }
}

const FALLBACKS: Record<LoginErrorCode | 'generic', string> = {
  invalid_provider: 'This sign-in provider is not supported.',
  provider_error: 'The identity provider did not complete the sign-in. Try again.',
  missing_params: 'The sign-in response was incomplete. Try again.',
  start_failed: 'Sign-in could not be started. Try again, or contact your administrator.',
  callback_failed: 'Sign-in could not be completed. Try again, or contact your administrator.',
  awaiting_approval:
    "Your access is waiting for an administrator's approval. You can sign in once it is approved.",
  not_member: 'You do not have access to this organization. Contact your administrator.',
  no_seat: 'This organization has no free seat for you. Contact your administrator.',
  domain_not_allowed: 'Your email domain is not allowed for this organization.',
  link_required:
    'An account with this email already exists. Sign in with your existing credentials first, then link this identity provider.',
  sso_required:
    'Your organization requires single sign-on. Sign in through your identity provider.',
  different_method:
    'This email is registered with a different sign-in method. Use the method you signed up with.',
  use_console: 'This account signs in on the admin console.',
  email_unverified_at_idp:
    'Your identity provider has not verified your email address. Verify it there, then try again.',
  saml_failed: 'Single sign-on could not be completed. Try again, or contact your administrator.',
  account_suspended: 'This account is suspended. Contact your administrator.',
  membership_suspended:
    'Your access to this organization is suspended. Contact an administrator to be reactivated.',
  organization_unavailable: 'This organization is suspended. Contact support.',
  email_not_verified:
    'Verify your email address before signing in. Check your inbox for the verification link.',
  account_exists:
    'An account with this email already exists. Sign in with your password, then link this provider in Account > Security.',
  generic: 'Sign-in failed. Try again.',
}

/** `/login?error=<code>`, plus any extra query parameters (e.g. org). */
export function loginErrorHref(code: LoginErrorCode, extra?: Record<string, string>): string {
  const params = new URLSearchParams({ error: code, ...extra })
  return `/login?${params.toString()}`
}
