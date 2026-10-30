/**
 * Cookie names shared by the sign-in server actions and the OAuth callback.
 * Kept out of the 'use server' modules, which may export only async
 * functions.
 */

/** The second-factor challenge of a sign-in (httpOnly, never read by script). */
export const MFA_CHALLENGE_COOKIE = 'mfa_challenge'

/**
 * Set when the provider round trip links a provider to the signed-in account
 * (Account > Security) instead of signing in. Its value is the provider. The
 * API still refuses a link state on the sign-in callback and a sign-in state
 * on the link callback, so a wrong value only fails the round trip.
 */
export const OAUTH_LINK_INTENT_COOKIE = 'oauth_link_intent'

/** The second steps the sign-in page knows; anything else is ignored. */
export const MFA_PURPOSES = ['verify', 'enroll'] as const

/**
 * The pending link a refused social sign-in left (409 OAUTH_ACCOUNT_EXISTS):
 * a secret the API stored only the hash of, for 10 minutes. HttpOnly, never
 * read by script; the `__Host-` prefix pins it to this origin so no subdomain
 * can plant one. After the person signs in to the account, the app asks them
 * to confirm the link; the API accepts it only for that account.
 */
export function pendingLinkCookieName(): string {
  return process.env.SECURE_COOKIES !== 'false' ? '__Host-oauth_pending_link' : 'oauth_pending_link'
}

/** Longest pending-link secret accepted from the API or a cookie. */
export const MAX_PENDING_LINK_LENGTH = 128
