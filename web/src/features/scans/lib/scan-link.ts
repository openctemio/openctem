/**
 * The in-app link to a scan's page. The id comes from data, so it is only
 * ever a URI-encoded path segment under the fixed `/scans/` prefix: a value
 * holding `/`, `..`, `?`, `#`, `:` or a scheme cannot leave the scan route or
 * add a query or fragment.
 */
export function scanDetailHref(id: string): string {
  return `/scans/${encodeURIComponent(id)}`
}
