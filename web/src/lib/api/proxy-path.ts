/**
 * Builds the backend path for the /api/v1/[...path] proxy.
 *
 * Next.js decodes each catch-all segment, so a request for
 * `/api/v1/x/..%2F..%2F..%2Fhealth` arrives as the single segment
 * `../../../health`. Joined back into a URL, fetch() resolves the dot segments
 * and the request leaves /api/v1 and reaches any path on the API host (with the
 * caller's session attached). Any segment that decodes to a dot segment, or
 * that carries a path separator, is refused.
 *
 * The decoded segments are re-encoded where a character would change the
 * URL's structure: a decoded `?` or `#` would start a query or fragment on
 * the backend URL, and a decoded `%` would be decoded a second time by the
 * API. Only these three are encoded, the same way the API's router encodes
 * them itself, so every other value (`lodash@4.17.21`, `a:b`) reaches the API
 * exactly as before.
 *
 * @returns the path to append after `/api/v1/`, or null to refuse the request.
 */
export function proxyBackendPath(segments: readonly string[]): string | null {
  for (const segment of segments) {
    if (segment.includes('\\')) return null
    for (const part of segment.split('/')) {
      if (part === '.' || part === '..') return null
    }
  }
  return segments.map(encodeStructural).join('/')
}

/** Percent-encode `%`, `?` and `#`, the characters that change a URL's structure. */
function encodeStructural(segment: string): string {
  return segment.replace(/[%?#]/g, (c) => encodeURIComponent(c))
}

/**
 * Whether the path names the platform console's API (`admin/...`). The
 * console is a separate site with its own proxy (RFC-022 revision 21); this
 * app never forwards to it, however the path is spelled (empty or `.`
 * segments, a decoded separator, another letter case).
 */
export function isConsoleApiPath(segments: readonly string[]): boolean {
  const parts = segments
    .join('/')
    .split(/[/\\]/)
    .filter((p) => p !== '' && p !== '.')
  return (parts[0] ?? '').toLowerCase() === 'admin'
}
