/**
 * The detail page of an asset group: a fixed same-origin prefix with the id
 * URI-encoded as one path segment, so an id from data can never change the
 * route or leave the site.
 */
export function assetGroupHref(id: string): string {
  return `/assets/groups/${encodeURIComponent(id)}`
}
