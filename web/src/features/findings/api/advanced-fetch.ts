/**
 * The findings list for a filter that chips cannot show (`fq`), through the
 * shared advanced search: the text is checked by /query/parse and the
 * resulting document goes to POST /api/v1/findings/search.
 */

import { AdvancedFilterError, fetchAdvanced } from '@/features/query/api/advanced-search'
import type { ApiFindingListResponse } from './finding-api.types'

export { AdvancedFilterError }

/** Params of the list URL that are not part of the filter. */
const PAGE_PARAMS = new Set(['page', 'per_page', 'sort', 'fq', 'include'])

/** The list for a URL that carries fq. */
export function fetchAdvancedFindings(url: string): Promise<ApiFindingListResponse> {
  return fetchAdvanced<ApiFindingListResponse>(url, {
    entity: 'findings',
    searchPath: '/api/v1/findings/search',
    pageParams: PAGE_PARAMS,
  })
}
