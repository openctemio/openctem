/**
 * The API refuses every sign-up its sign-up policy does not admit (email
 * sign-up, Google/Microsoft/GitHub sign-in) with one error code. The UI sends
 * the person to one page for it, whatever the reason.
 */
export const SIGNUP_NOT_AVAILABLE = 'SIGNUP_NOT_AVAILABLE'

/** The page a refused sign-up lands on. */
export const NOT_SET_UP_PATH = '/not-set-up'

/**
 * The address is on a domain whose organization requires its single sign-on
 * (api RFC-104): the person signs in there instead. The answer names no
 * organization; email-first sign-in finds it.
 */
export const SSO_REQUIRED = 'SSO_REQUIRED'

/** True when an API error code is the sign-up refusal. */
export function isSignupNotAvailable(code: unknown): boolean {
  return code === SIGNUP_NOT_AVAILABLE
}
