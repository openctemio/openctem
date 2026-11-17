/**
 * Links to console pages that carry a record id. The id is data: it goes in
 * as one URI-encoded path segment under a fixed path, so no value can leave
 * the page it names.
 */

/** The page of one account (Customers > Users). */
export function platformUserHref(id: string): string {
  return `/users/${encodeURIComponent(id)}`
}
