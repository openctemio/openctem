/**
 * Response headers the /api/v1 proxy copies from the API's answer to the
 * browser. Besides the content headers it keeps the API's security headers:
 * the API answers every request with `Content-Security-Policy: default-src
 * 'none'` and `X-Content-Type-Options: nosniff`, and sends files as
 * attachments. Without them a non-JSON answer (an HTML report, a file built
 * from scan data) would render on the console's own origin with no policy.
 */
export const PROXIED_RESPONSE_HEADERS = [
  'content-type',
  'content-disposition',
  'content-security-policy',
  'x-content-type-options',
  'x-request-id',
  'x-total-count',
  'x-permission-stale',
  // An export's cap and outcome (findings and audit-log exports): the page
  // compares the cap with the list total to say when rows were left out.
  'x-export-max-rows',
  'x-export-rows',
  'x-export-truncated',
] as const

/** Headers of a streamed (binary) answer: the same, plus its length. */
export const PROXIED_STREAM_HEADERS = [...PROXIED_RESPONSE_HEADERS, 'content-length'] as const

/** Copies the listed headers that `from` carries onto `to`. */
export function copyProxiedHeaders(from: Headers, to: Headers, names: readonly string[]): void {
  for (const name of names) {
    const value = from.get(name)
    if (value) to.set(name, value)
  }
}
