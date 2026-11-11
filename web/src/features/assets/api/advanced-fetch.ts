/**
 * The inventory for a filter that chips cannot show (`fq`), through the shared
 * advanced search: the page's other filters and the fq text are checked by
 * POST /api/v1/query/parse as the signed-in person and the resulting filter
 * document goes to POST /api/v1/assets/search (same registry, data scope and
 * tenant as GET /assets). The list never receives text.
 */

import {
  AdvancedFilterError,
  advancedDocument,
  fetchAdvanced,
  type AdvancedSearchSpec,
} from '@/features/query/api/advanced-search'

export { AdvancedFilterError }

/** Params of the list URL that are not part of the filter. */
const PAGE_PARAMS = new Set(['page', 'per_page', 'sort', 'fq', 'cursor', 'with_triage'])

/**
 * The inventory leaves out names awaiting review and names marked not ours
 * unless the filter says something about attribution.
 */
export const DEFAULT_ATTRIBUTION_PARAMS = { attribution: 'approved' }

const SPEC: AdvancedSearchSpec = {
  entity: 'assets',
  searchPath: '/api/v1/assets/search',
  pageParams: PAGE_PARAMS,
  defaultPerPage: 20,
  defaultParams: { field: 'attribution', params: DEFAULT_ATTRIBUTION_PARAMS },
}

/** The list for a URL that carries fq (an asset list response). */
export function fetchAdvancedAssets<T>(url: string): Promise<T> {
  return fetchAdvanced<T>(url, SPEC)
}

/** The filter document of a list URL that carries fq (what a saved view stores). */
export async function advancedAssetsDocument(url: string): Promise<Record<string, unknown>> {
  return (await advancedDocument(url, SPEC)).document
}
