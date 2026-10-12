/**
 * Cross-tab lock for session refreshes.
 *
 * The refresh token rotates on every use and the API treats a reused refresh
 * token as theft: it revokes the whole token family, which signs the user out
 * everywhere. Every tab shares the same cookies, so two tabs refreshing at the
 * same moment (both sockets closed at the shared access token's expiry, or two
 * REST calls answered 401) send the same refresh token twice and trip that
 * detection. Serializing refreshes across tabs makes the second one run after
 * the first has stored the rotated cookie, so it sends the new token.
 *
 * Uses the Web Locks API (https://developer.mozilla.org/docs/Web/API/Web_Locks_API).
 * Where it is unavailable (an insecure context, old browsers) the refresh runs
 * unlocked, as before.
 *
 * Design: api/docs/rfcs/RFC-045-websocket-auth.md (§5.5).
 */

export const AUTH_REFRESH_LOCK = 'openctem:auth-refresh'

interface LockManagerLike {
  request<T>(name: string, callback: () => Promise<T>): Promise<T>
}

function lockManager(): LockManagerLike | null {
  if (typeof navigator === 'undefined') return null
  const locks = (navigator as Navigator & { locks?: LockManagerLike }).locks
  return locks && typeof locks.request === 'function' ? locks : null
}

/** Runs fn while holding the cross-tab refresh lock. */
export function withAuthRefreshLock<T>(fn: () => Promise<T>): Promise<T> {
  const locks = lockManager()
  if (!locks) return fn()
  return locks.request(AUTH_REFRESH_LOCK, fn)
}
