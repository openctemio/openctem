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
 * @returns the path to append after `/api/v1/`, or null to refuse the request.
 */
export function proxyBackendPath(segments: readonly string[]): string | null {
  for (const segment of segments) {
    if (segment.includes('\\')) return null
    for (const part of segment.split('/')) {
      if (part === '.' || part === '..') return null
    }
  }
  return segments.join('/')
}
