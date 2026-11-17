/**
 * The page of one organization (Customers > Organizations). The id is data:
 * it goes in as one URI-encoded path segment under a fixed path, so no value
 * can leave the page it names.
 */
export function organizationHref(id: string): string {
  return `/organizations/${encodeURIComponent(id)}`
}
