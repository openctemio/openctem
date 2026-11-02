/**
 * Why a session ended, carried to the sign-in page as `?reason=` so it can say
 * so instead of silently showing the form. Only these known values show a
 * message: a crafted link cannot put arbitrary text on the page.
 *
 * Design: api/docs/architecture/session-refresh.md
 */

export type SessionEndReason = 'session_reused' | 'session_expired' | 'session_revoked'

/** Maps the API's refusal code of a failed refresh to a reason. */
export function sessionEndReason(code: string | undefined): SessionEndReason | undefined {
  switch (code) {
    case 'REFRESH_TOKEN_REUSED':
      return 'session_reused'
    case 'REFRESH_TOKEN_EXPIRED':
    case 'SESSION_EXPIRED':
      return 'session_expired'
    case 'REFRESH_TOKEN_REVOKED':
    case 'REFRESH_TOKEN_INVALID':
      return 'session_revoked'
    default:
      return undefined
  }
}

/** The message key and English fallback for a `?reason=` value, if known. */
export function sessionEndedMessage(
  reason: string | null | undefined
): { key: string; fallback: string } | undefined {
  switch (reason) {
    case 'session_reused':
      return {
        key: 'auth.login.sessionEndedReused',
        fallback:
          'Your session was ended for your safety: the same sign-in was used from two places. Sign in again.',
      }
    case 'session_expired':
      return {
        key: 'auth.login.sessionExpired',
        fallback: 'Your session expired. Sign in again.',
      }
    case 'session_revoked':
      return {
        key: 'auth.login.sessionEndedRevoked',
        fallback:
          'Your session was ended: you signed out on another device, or an administrator ended it. Sign in again.',
      }
    default:
      return undefined
  }
}
