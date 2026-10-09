/**
 * Caching headers for responses the API proxy (src/app/api/v1/[...path]) sends
 * back to the browser.
 *
 * The API decides how each response may be cached: `no-store` for secrets
 * (MFA enrolment, credential import, admin data), `private, max-age=…` for
 * per-user data it is safe to reuse, `public, max-age=…` for server config.
 * The proxy used to drop the header, so none of that reached the browser.
 *
 * Rules:
 * - the API's Cache-Control is forwarded as is;
 * - an authenticated response the API did not label is `no-store`: it is
 *   tenant data, and nothing said it may be kept;
 * - a cacheable authenticated response also gets `Vary: Cookie`. The access
 *   token travels in a cookie and changes on sign-in and on switching
 *   organization, so the browser never serves one session's or one
 *   organization's copy to another (the URLs are the same for every tenant).
 */
export function proxyCacheHeaders(
  backendCacheControl: string | null,
  authenticated: boolean,
  backendETag: string | null = null
): Record<string, string> {
  const value = backendCacheControl?.trim()
  if (!value) {
    return authenticated ? { 'Cache-Control': 'no-store' } : {}
  }
  const headers: Record<string, string> = { 'Cache-Control': value }
  const storable = !/\bno-store\b/i.test(value)
  if (authenticated && storable) {
    headers['Vary'] = 'Cookie'
  }
  // The validator travels only with a response the API lets the browser keep:
  // the browser then revalidates with If-None-Match and gets a body-less 304
  // instead of the whole document (research/81: the 107 KB asset type
  // registry on every asset page load).
  const etag = backendETag?.trim()
  if (storable && etag) {
    headers['ETag'] = etag
  }
  return headers
}

/**
 * Request headers a GET may carry to the API for conditional requests. The
 * API answers 304 when its ETag still matches; it never varies data on it.
 */
export const CONDITIONAL_REQUEST_HEADERS = ['if-none-match'] as const
