/**
 * Request body limits of the /api/v1/[...path] proxy.
 *
 * Most requests are small and are read into memory before they are sent to
 * the API (DEFAULT_PROXY_BODY_LIMIT, the attachment limit plus the form). The
 * import routes accept larger files: their bodies are streamed to the API
 * instead, never held in memory, and are cut at the same limit the API route
 * declares (api: routes/finding_import.go, routes/assets.go,
 * routes/pentest.go). The API stays authoritative; this only stops a body the
 * API would refuse before it is forwarded.
 */

const MiB = 1024 * 1024

/** Bodies of every other route: read into memory, at most 12 MiB. */
export const DEFAULT_PROXY_BODY_LIMIT = 12 * MiB

interface StreamedRoute {
  /** Matches the backend path (after /api/v1/, without the query). */
  pattern: RegExp
  /** The API route's body limit in bytes. */
  limit: number
}

const UUID = '[0-9a-fA-F-]{36}'

/** POST routes whose bodies are streamed, with the API's limit for each. */
const STREAMED_ROUTES: readonly StreamedRoute[] = [
  // handler.MaxFindingImportBody
  { pattern: /^findings\/imports\/?$/, limit: 110 * MiB },
  // handler.MaxSBOMImportBody (the 50 MiB SBOM limit plus one byte)
  { pattern: /^components\/import\/?$/, limit: 50 * MiB + 1 },
  // handler.MaxAssetCSVImportBody
  { pattern: /^assets\/import\/csv\/?$/, limit: 50 * MiB },
  // handler.MaxPentestImportBody (a 50 MiB file plus the form)
  { pattern: new RegExp(`^pentest/campaigns/${UUID}/findings/import/?$`), limit: 51 * MiB },
]

export interface ProxyBodyPolicy {
  /** Largest body forwarded, in bytes. */
  limit: number
  /** True: stream the body to the API instead of reading it into memory. */
  stream: boolean
}

/** The body policy for a request to the backend path (after /api/v1/). */
export function proxyBodyPolicy(method: string, backendPath: string): ProxyBodyPolicy {
  if (method.toUpperCase() === 'POST') {
    for (const route of STREAMED_ROUTES) {
      if (route.pattern.test(backendPath)) return { limit: route.limit, stream: true }
    }
  }
  return { limit: DEFAULT_PROXY_BODY_LIMIT, stream: false }
}

/** Raised (as the stream's error) when a streamed body passes its limit. */
export class ProxyBodyTooLargeError extends Error {
  constructor(limit: number) {
    super(`request body larger than ${limit} bytes`)
    this.name = 'ProxyBodyTooLargeError'
  }
}

/**
 * Passes a body through, counting bytes, and errors the stream once more than
 * limit bytes went by, so a body without (or with a false) Content-Length is
 * cut as well.
 */
export function limitBodyStream(
  body: ReadableStream<Uint8Array>,
  limit: number
): ReadableStream<Uint8Array> {
  let seen = 0
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        seen += chunk.byteLength
        if (seen > limit) {
          controller.error(new ProxyBodyTooLargeError(limit))
          return
        }
        controller.enqueue(chunk)
      },
    })
  )
}

/**
 * True when the access token expires within skewSeconds (or cannot be read).
 * Only decides whether to refresh before a streamed upload, which cannot be
 * sent a second time after a 401; the API verifies the token.
 */
export function accessTokenExpiresSoon(token: string, skewSeconds = 60, now = Date.now()): boolean {
  const parts = token.split('.')
  if (parts.length !== 3) return true
  try {
    const json = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString(
      'utf8'
    )
    const exp = (JSON.parse(json) as { exp?: unknown }).exp
    if (typeof exp !== 'number') return true
    return exp * 1000 - now < skewSeconds * 1000
  } catch {
    return true
  }
}
