/**
 * Client error reporting for operator alerting.
 *
 * When the console hits an error (a code chunk that fails to load after a
 * deploy, a render error caught by an error boundary, an uncaught error or
 * rejection) it tells the API the error KIND, nothing else: no message,
 * stack, URL or user detail leaves the browser, so a report cannot carry
 * personal or organization data. The API counts the kinds and the operator
 * is alerted when they spike (api/docs/operations/monitoring.md,
 * WebClientErrors).
 *
 * Reports are throttled per page load (one per kind a minute, ten in all) and
 * sent with a keepalive fetch so they survive a reload; reporting never
 * throws. Not sendBeacon: a beacon cannot carry the CSRF header every write
 * to the web server needs (src/lib/server-auth-cookies.ts).
 */

import { csrfHeaders } from '@/lib/csrf-client'

export type ClientErrorKind = 'chunk_load' | 'render' | 'unhandled' | 'other'

export const CLIENT_ERRORS_ENDPOINT = '/api/v1/client-errors'

const PER_KIND_INTERVAL_MS = 60_000
const MAX_REPORTS_PER_PAGE = 10

const lastSent = new Map<ClientErrorKind, number>()
let sentThisPage = 0

const CHUNK_LOAD_PATTERNS = [
  /ChunkLoadError/i,
  /Loading (CSS )?chunk [\w-]+ failed/i,
  /Failed to fetch dynamically imported module/i,
  /Importing a module script failed/i,
  /module factory is not available/i,
  /error loading dynamically imported module/i,
]

/** classifyError tells a chunk-load failure from any other error. */
export function classifyError(error: unknown, fallback: ClientErrorKind): ClientErrorKind {
  const name = error instanceof Error ? error.name : ''
  const message = error instanceof Error ? error.message : typeof error === 'string' ? error : ''
  const text = `${name} ${message}`
  return CHUNK_LOAD_PATTERNS.some((re) => re.test(text)) ? 'chunk_load' : fallback
}

/** reportClientError sends one error kind to the API, throttled. */
export function reportClientError(kind: ClientErrorKind, now: number = Date.now()): boolean {
  if (typeof window === 'undefined') return false
  if (sentThisPage >= MAX_REPORTS_PER_PAGE) return false
  const last = lastSent.get(kind)
  if (last !== undefined && now - last < PER_KIND_INTERVAL_MS) return false
  lastSent.set(kind, now)
  sentThisPage++

  try {
    void fetch(CLIENT_ERRORS_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...csrfHeaders() },
      body: JSON.stringify({ kind }),
      keepalive: true,
      credentials: 'same-origin',
    }).catch(() => {})
  } catch {
    // Reporting must never break the page.
  }
  return true
}

/**
 * installClientErrorListeners reports uncaught errors and unhandled
 * rejections. Returns the function that removes the listeners.
 */
export function installClientErrorListeners(): () => void {
  if (typeof window === 'undefined') return () => {}
  const onError = (event: ErrorEvent) => {
    reportClientError(classifyError(event.error ?? event.message, 'unhandled'))
  }
  const onRejection = (event: PromiseRejectionEvent) => {
    reportClientError(classifyError(event.reason, 'unhandled'))
  }
  window.addEventListener('error', onError)
  window.addEventListener('unhandledrejection', onRejection)
  return () => {
    window.removeEventListener('error', onError)
    window.removeEventListener('unhandledrejection', onRejection)
  }
}

/** Test hook: forget the throttle state. */
export function resetClientErrorThrottle(): void {
  lastSent.clear()
  sentThisPage = 0
}
