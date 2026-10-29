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
