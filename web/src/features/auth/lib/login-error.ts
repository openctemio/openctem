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
  generic: 'Sign-in failed. Try again.',
}

/** `/login?error=<code>`, plus any extra query parameters (e.g. org). */
export function loginErrorHref(code: LoginErrorCode, extra?: Record<string, string>): string {
  const params = new URLSearchParams({ error: code, ...extra })
  return `/login?${params.toString()}`
}
