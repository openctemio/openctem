/** The package page: a fixed path with the id URI-encoded as one segment. */
export function componentHref(id: string): string {
  return `/components/${encodeURIComponent(id)}`
}
