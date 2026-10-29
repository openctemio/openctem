/**
 * Rate-limit backoff shared by the browser.
 *
 * When the API answers 429, the client records how long the server asked us
 * to wait (`Retry-After`, seconds or an HTTP date). Search-as-you-type
 * (`useSearchQuery`) holds new queries until that time has passed, so a user
 * who keeps typing after a 429 does not keep the server busy with more
 * refused requests. Explicit actions (saves, clicks) are not held: the
 * server answers them itself.
 */

/** Wait used when a 429 carries no usable Retry-After. */
export const DEFAULT_RATE_LIMIT_WAIT_MS = 2_000
/** Never hold searches longer than this, whatever the header says. */
export const MAX_RATE_LIMIT_WAIT_MS = 60_000

let blockedUntil = 0

/** Parses a Retry-After value (delta seconds or HTTP date) into milliseconds. */
export function parseRetryAfter(value: string | null | undefined, now = Date.now()): number {
  if (!value) return DEFAULT_RATE_LIMIT_WAIT_MS
  const trimmed = value.trim()
  let ms: number
  if (/^\d+(\.\d+)?$/.test(trimmed)) {
    ms = Number(trimmed) * 1000
  } else {
    const at = Date.parse(trimmed)
    if (Number.isNaN(at)) return DEFAULT_RATE_LIMIT_WAIT_MS
    ms = at - now
  }
  if (!Number.isFinite(ms) || ms <= 0) return DEFAULT_RATE_LIMIT_WAIT_MS
  return Math.min(ms, MAX_RATE_LIMIT_WAIT_MS)
}

/** Longest wait before the one automatic retry of a refused read. */
export const MAX_READ_RETRY_WAIT_MS = 5_000

/**
 * How long the API client waits before retrying a read the server refused
 * with 429: the server's Retry-After (at most MAX_READ_RETRY_WAIT_MS), plus up
 * to 250 ms of jitter so the panels of one page do not all come back in the
 * same instant and spend the refilled budget together.
 */
export function rateLimitRetryDelayMs(
  retryAfter: string | null | undefined,
  now = Date.now(),
  random = Math.random
): number {
  return (
    Math.min(parseRetryAfter(retryAfter, now), MAX_READ_RETRY_WAIT_MS) + Math.floor(random() * 250)
  )
}

/** Records a 429 answer. */
export function noteRateLimited(retryAfter: string | null | undefined, now = Date.now()): void {
  blockedUntil = Math.max(blockedUntil, now + parseRetryAfter(retryAfter, now))
}

/** Milliseconds left before searches may be sent again (0 when free). */
export function rateLimitRemainingMs(now = Date.now()): number {
  return Math.max(0, blockedUntil - now)
}

/** Test helper. */
export function resetRateLimitBackoff(): void {
  blockedUntil = 0
}
