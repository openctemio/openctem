/**
 * Answers from a page view, served to the page's own reads (research/335).
 *
 * A view endpoint (GET /api/v1/findings/{id}/view) returns the reads a page
 * shows on load in one response: each part keyed by the exact URL the page's
 * panels ask for, with that endpoint's status and body. `primeView` keeps
 * those answers for a few seconds; the browser's `fetch` (installed below)
 * answers a same-origin GET for one of those URLs from them, once, instead of
 * sending it. The panels and their SWR hooks stay as they are: they still ask
 * for their own URL and get exactly what their endpoint answered.
 *
 * - Each answer is used once and expires after PRIME_TTL_MS, so a later read
 *   (a refresh after a save) always goes to the server.
 * - Only 200, 403 and 404 are kept: a 401 must reach the client's token
 *   refresh, and a server failure is retried by the client as usual.
 * - The cache lives in this tab's memory only, and `clearPrimedViews` drops
 *   it when the session changes (organization switch, sign-out).
 */

/** How long a primed answer may be served. */
export const PRIME_TTL_MS = 10_000

const KEPT_STATUSES = new Set([200, 403, 404])

type Primed = { status: number; body: string; at: number }

const primed = new Map<string, Primed>()

export type ViewPart = { status: number; body?: unknown }
export type ViewResponse = { parts?: Record<string, ViewPart> }

/** Keeps the parts of a view response for the page's reads. */
export function primeView(view: ViewResponse | null | undefined, now = Date.now()): void {
  if (!view?.parts) return
  for (const [url, part] of Object.entries(view.parts)) {
    if (!url.startsWith('/api/v1/') || !KEPT_STATUSES.has(part.status)) continue
    primed.set(url, {
      status: part.status,
      body: part.body === undefined ? '' : JSON.stringify(part.body),
      at: now,
    })
  }
}

/**
 * The primed answer for a same-origin GET of `url` (path and query), as a
 * Response, or undefined. Takes the answer: it is served once.
 */
export function takePrimed(url: string, now = Date.now()): Response | undefined {
  const entry = primed.get(url)
  if (!entry) return undefined
  primed.delete(url)
  if (now - entry.at > PRIME_TTL_MS) return undefined
  return new Response(entry.body || null, {
    status: entry.status,
    headers: entry.body ? { 'content-type': 'application/json' } : undefined,
  })
}

/** Drops every primed answer (session change). */
export function clearPrimedViews(): void {
  primed.clear()
}

/** Test helper. */
export function primedCount(): number {
  return primed.size
}

/** The path and query of a same-origin GET, else undefined. */
function primableUrl(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  origin: string
): string | undefined {
  const request = input instanceof Request ? input : undefined
  const method = (init?.method ?? request?.method ?? 'GET').toUpperCase()
  if (method !== 'GET') return undefined
  const raw = request ? request.url : input instanceof URL ? input.href : String(input)
  let url: URL
  try {
    url = new URL(raw, origin)
  } catch {
    return undefined
  }
  if (url.origin !== origin) return undefined
  return url.pathname + url.search
}

const INSTALLED = Symbol.for('openctem.primedFetch')

/** Wraps `win.fetch` once so a primed same-origin GET is answered locally. */
export function installPrimedFetch(win: Window & typeof globalThis = window): void {
  const current = win.fetch as typeof fetch & { [INSTALLED]?: true }
  if (current[INSTALLED]) return
  const original = current.bind(win)
  const wrapped = ((input: RequestInfo | URL, init?: RequestInit) => {
    if (primed.size > 0) {
      const url = primableUrl(input, init, win.location.origin)
      const hit = url ? takePrimed(url) : undefined
      if (hit) return Promise.resolve(hit)
    }
    return original(input, init)
  }) as typeof fetch & { [INSTALLED]?: true }
  wrapped[INSTALLED] = true
  win.fetch = wrapped
}
