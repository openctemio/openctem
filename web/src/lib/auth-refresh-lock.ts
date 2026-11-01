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

/** Outcome of a browser session refresh (POST /api/auth/refresh). */
export interface BrowserRefreshOutcome {
  ok: boolean
  status: number
  /** API error code on a refusal (REFRESH_TOKEN_REUSED, SESSION_EXPIRED, ...). */
  code?: string
  /** The new access token; absent when another tab's refresh was reused. */
  accessToken?: string
}

/** localStorage key holding when any tab last refreshed successfully (ms). */
export const AUTH_REFRESH_AT_KEY = 'openctem:auth-refresh-at'
/** A refresh another tab finished this recently is reused, not repeated. */
export const RECENT_REFRESH_MS = 10_000

/** BroadcastChannel on which a tab announces the access token it refreshed. */
export const AUTH_REFRESH_CHANNEL = 'openctem:auth-refresh'

let inFlight: Promise<BrowserRefreshOutcome> | null = null
let deadSession: BrowserRefreshOutcome | null = null

function readRefreshedAt(): number {
  try {
    return Number(window.localStorage.getItem(AUTH_REFRESH_AT_KEY)) || 0
  } catch {
    return 0
  }
}

function writeRefreshedAt(at: number): void {
  try {
    window.localStorage.setItem(AUTH_REFRESH_AT_KEY, String(at))
  } catch {
    // Storage blocked: tabs still take turns through the lock.
  }
}

function channel(): BroadcastChannel | null {
  if (typeof BroadcastChannel === 'undefined') return null
  try {
    return new BroadcastChannel(AUTH_REFRESH_CHANNEL)
  } catch {
    return null
  }
}

function announceRefresh(accessToken: string): void {
  const ch = channel()
  if (!ch) return
  try {
    ch.postMessage({ type: 'refreshed', accessToken })
  } finally {
    ch.close()
  }
}

/**
 * Calls cb with the access token another tab of this origin refreshed, so
 * every tab's store follows one refresh. Returns false where BroadcastChannel
 * is unavailable. Same-origin only: any same-origin script can already read
 * an access token from /api/auth/refresh.
 */
export function onRefreshedElsewhere(cb: (accessToken: string) => void): boolean {
  const ch = channel()
  if (!ch) return false
  ch.onmessage = (event: MessageEvent) => {
    const data = event.data as { type?: unknown; accessToken?: unknown } | null
    if (data?.type === 'refreshed' && typeof data.accessToken === 'string') cb(data.accessToken)
  }
  return true
}

/** Forgets the in-flight refresh and a dead session (tests, sign-in). */
export function resetBrowserRefreshState(): void {
  inFlight = null
  deadSession = null
}

/**
 * Refreshes the session once for the whole browser:
 *
 * - concurrent callers in a tab share one request;
 * - tabs take turns (withAuthRefreshLock), and a tab that waited while
 *   another tab refreshed reuses that refresh instead of sending a second one
 *   (both share the cookies, so the session is already current);
 * - after a 401 the session is gone: later calls get the same answer without
 *   presenting the dead refresh token again, until the page reloads.
 *
 * `force` skips the reuse of another tab's recent refresh (a caller that
 * needs claims minted after a change, such as a new role).
 */
export function refreshSessionShared(
  doFetch: () => Promise<Response>,
  options?: { force?: boolean }
): Promise<BrowserRefreshOutcome> {
  if (deadSession) return Promise.resolve(deadSession)
  if (inFlight) return inFlight
  const requestedAt = Date.now()
  const run = withAuthRefreshLock(async (): Promise<BrowserRefreshOutcome> => {
    if (!options?.force) {
      const at = readRefreshedAt()
      // Another tab refreshed while this one waited for the lock, or moments
      // ago: its rotated cookies are already ours.
      if (at > 0 && (at >= requestedAt || Date.now() - at < RECENT_REFRESH_MS)) {
        return { ok: true, status: 200 }
      }
    }
    let response: Response
    try {
      response = await doFetch()
    } catch {
      return { ok: false, status: 0 }
    }
    const body = (await response.json().catch(() => ({}))) as {
      success?: boolean
      data?: { access_token?: string }
      error?: { code?: string }
    }
    if (response.ok && body.success && body.data?.access_token) {
      writeRefreshedAt(Date.now())
      announceRefresh(body.data.access_token)
      return { ok: true, status: response.status, accessToken: body.data.access_token }
    }
    const outcome: BrowserRefreshOutcome = {
      ok: false,
      status: response.status,
      code: body.error?.code,
    }
    if (response.status === 401) deadSession = outcome
    return outcome
  })
  inFlight = run
  run.then(
    () => {
      if (inFlight === run) inFlight = null
    },
    () => {
      if (inFlight === run) inFlight = null
    }
  )
  return run
}
