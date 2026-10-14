import type { FindingApiFilters } from '../api/finding-api.types'

/**
 * The list filter without its paging and sort: what a grouped view and its
 * rows share with the ungrouped list.
 */
export function withoutPaging(query: FindingApiFilters): FindingApiFilters {
  const rest = { ...query }
  delete rest.page
  delete rest.per_page
  delete rest.sort
  return rest
}
