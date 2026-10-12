/**
 * Browser side of the CSRF double submit (server side and design:
 * `src/lib/server-auth-cookies.ts`).
 *
 * The web server sets a JS-readable `csrf_token` cookie on every page, before
 * sign-in too. Every same-origin state-changing request must echo it in the
 * `X-CSRF-Token` header, or the web server answers 403. `installCsrfFetch`
 * (run once from `src/instrumentation-client.ts`, before the app hydrates)
 * wraps `window.fetch` so every caller gets the header: the shared API client,
 * raw `fetch` calls, and Next's own Server Action requests, which the sign-in,
 * registration, password-reset, invitation and second-factor forms use and
 * which cannot be given headers any other way. Cross-origin requests never get
 * the token. Standalone (no imports) so stores and providers can use it
 * without the API client.
 */

export const CSRF_COOKIE = 'csrf_token'
export const CSRF_HEADER = 'X-CSRF-Token'

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

/** The `csrf_token` cookie, or '' outside a browser or when it is absent. */
export function readCsrfCookie(): string {
  if (typeof document === 'undefined') return ''
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/)
  if (!match) return ''
  try {
    return decodeURIComponent(match[1])
  } catch {
    return match[1]
  }
}

/** `{ 'X-CSRF-Token': <cookie> }`, or `{}` when there is no cookie. */
export function csrfHeaders(): Record<string, string> {
  const token = readCsrfCookie()
  return token ? { [CSRF_HEADER]: token } : {}
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.href
  return input.url
}

/** True when `input` resolves to this page's origin. */
function isSameOrigin(input: RequestInfo | URL, origin: string): boolean {
  try {
    return new URL(requestUrl(input), origin).origin === origin
  } catch {
    return false
  }
}

/**
 * The `init` to send so the request carries the CSRF header, or the original
 * `init` when none is needed (safe method, cross-origin, header already set,
 * no cookie).
 */
export function withCsrfHeader(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  origin: string
): RequestInit | undefined {
  const request = input instanceof Request ? input : undefined
  const method = (init?.method ?? request?.method ?? 'GET').toUpperCase()
  if (SAFE_METHODS.has(method) || !isSameOrigin(input, origin)) return init

  const headers = new Headers(init?.headers ?? request?.headers)
  if (headers.has(CSRF_HEADER)) return init
  const token = readCsrfCookie()
  if (!token) return init
  headers.set(CSRF_HEADER, token)
  return { ...init, headers }
}

const INSTALLED = Symbol.for('openctem.csrfFetch')

/** Wraps `win.fetch` once so same-origin writes carry `X-CSRF-Token`. */
export function installCsrfFetch(win: Window & typeof globalThis = window): void {
  const current = win.fetch as typeof fetch & { [INSTALLED]?: true }
  if (current[INSTALLED]) return
  const original = current.bind(win)
  const wrapped = ((input: RequestInfo | URL, init?: RequestInit) =>
    original(input, withCsrfHeader(input, init, win.location.origin))) as typeof fetch & {
    [INSTALLED]?: true
  }
  wrapped[INSTALLED] = true
  win.fetch = wrapped
}
