/**
 * One network request per in-flight GET, and a development warning when the
 * page asks for the same thing twice.
 *
 * SWR already deduplicates requests that share a key. Two hooks that read the
 * same URL under different keys (a string here, `[url, tenantId]` there), or a
 * plain `get()` racing a hook, still sent the request twice. Coalescing at the
 * client makes the second caller share the first caller's promise, so the
 * same GET is never on the wire twice at once, whatever the caller.
 *
 * Browser only. On the server this module is shared by every user's request,
 * and the headers (and so the identity) differ per request: coalescing there
 * could hand one user's response to another, so `coalesceGet` runs the
 * request directly when `window` is undefined.
 *
 * In development, a GET that is in flight twice, or that is sent again within
 * REPEAT_WINDOW_MS of the previous answer, logs a `[request-budget]` warning
 * naming the URL. That is the signal of a duplicate key or a refetch loop.
 */

/** A repeat of the same GET within this window is reported in development. */
export const REPEAT_WINDOW_MS = 1000

const inflight = new Map<string, Promise<unknown>>()
const settledAt = new Map<string, number>()

function isBrowser(): boolean {
  return typeof window !== 'undefined'
}

function isDevelopment(): boolean {
  return process.env.NODE_ENV === 'development'
}

function warn(message: string, url: string): void {
  if (!isDevelopment()) return
  console.warn(`[request-budget] ${message}: ${url}`)
}

/**
 * Runs `run` for `url`, or returns the promise of the identical GET already in
 * flight. Only for idempotent requests whose result depends on nothing but the
 * URL and the browser's own cookies.
 */
export function coalesceGet<T>(url: string, run: () => Promise<T>): Promise<T> {
  if (!isBrowser()) return run()

  const pending = inflight.get(url)
  if (pending) {
    warn('the same GET is already in flight (two keys or callers for one URL)', url)
    return pending as Promise<T>
  }

  if (isDevelopment()) {
    const last = settledAt.get(url)
    if (last !== undefined && Date.now() - last < REPEAT_WINDOW_MS) {
      warn(`the same GET was answered less than ${REPEAT_WINDOW_MS} ms ago`, url)
    }
  }

  const promise = run().finally(() => {
    inflight.delete(url)
    if (isDevelopment()) settledAt.set(url, Date.now())
  })
  inflight.set(url, promise)
  return promise
}

/** Test helper: forget every in-flight and settled request. */
export function resetRequestDedupe(): void {
  inflight.clear()
  settledAt.clear()
}
