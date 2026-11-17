/**
 * The findings list for a filter that chips cannot show (`fq`), through the
 * shared advanced search: the text is checked by /query/parse and the
 * resulting document goes to POST /api/v1/findings/search.
 */

import {
  AdvancedFilterError,
  advancedDocument,
  fetchAdvanced,
  type AdvancedSearchSpec,
} from '@/features/query/api/advanced-search'
import type { ApiFindingListResponse } from './finding-api.types'

export { AdvancedFilterError }

/** Params of the list URL that are not part of the filter. */
const PAGE_PARAMS = new Set(['page', 'per_page', 'sort', 'fq', 'include'])

const SPEC: AdvancedSearchSpec = {
  entity: 'findings',
  searchPath: '/api/v1/findings/search',
  pageParams: PAGE_PARAMS,
}

/** The list for a URL that carries fq. */
export function fetchAdvancedFindings(url: string): Promise<ApiFindingListResponse> {
  return fetchAdvanced<ApiFindingListResponse>(url, SPEC)
}

/**
 * The checked filter document of a list URL that carries fq, with its sort:
 * what a saved view stores for a filter the flat params cannot say.
 */
export async function advancedFindingsDocument(url: string): Promise<Record<string, unknown>> {
  const { document, url: u } = await advancedDocument(url, SPEC)
  const sort = u.searchParams.get('sort')
  return sort ? { ...document, sort: sort.split(',') } : document
}
