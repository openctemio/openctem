import type { FindingApiFilters } from '../api/finding-api.types'

/**
 * The list filter without its paging and sort: what a grouped view and its
 * rows share with the ungrouped list.
 */
export function withoutPaging(query: FindingApiFilters): FindingApiFilters {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { page, per_page, sort, ...rest } = query
  return rest
}
