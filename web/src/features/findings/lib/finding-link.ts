/**
 * The in-app link to a finding's page. The id comes from data, so it is only
 * ever a URI-encoded path segment under the fixed `/findings/` prefix: a value
 * holding `/`, `..`, `?`, `#`, `:` or a scheme cannot leave the finding route
 * or add a query or fragment.
 */
export function findingDetailHref(id: string): string {
  return `/findings/${encodeURIComponent(id)}`
}
