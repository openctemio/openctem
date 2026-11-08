/**
 * The findings list for a filter that chips cannot show (`fq`: an OR across
 * fields, a nested group). The list never receives text: the page's other
 * list params and the fq text are checked by POST /api/v1/query/parse as
 * the signed-in person and the resulting filter document is sent to
 * POST /api/v1/findings/search, the same registry and scope as GET /findings.
 */

import { post } from '@/lib/api/client'
import { queryApi } from '@/features/query/api/query-api'
import type { ApiFindingListResponse } from './finding-api.types'

/** Params of the list URL that are not part of the filter. */
const PAGE_PARAMS = new Set(['page', 'per_page', 'sort', 'fq', 'include'])

/** An fq filter the server refused: the list shows its problem. */
export class AdvancedFilterError extends Error {
  constructor(readonly code: string) {
    super('the filter is not valid')
  }
}

/** The list for a URL that carries fq. */
export async function fetchAdvancedFindings(url: string): Promise<ApiFindingListResponse> {
  const u = new URL(url, 'http://local')
  const fq = u.searchParams.get('fq') ?? ''
  const rest = new URLSearchParams()
  u.searchParams.forEach((v, k) => {
    if (!PAGE_PARAMS.has(k)) rest.append(k, v)
  })
  if (rest.has('view')) throw new AdvancedFilterError('view_with_query')
  let text = fq
  if (rest.toString() !== '') {
    const base = await queryApi.parse({ entity: 'findings', params: rest.toString() })
    if (!base.valid) throw new AdvancedFilterError(base.problems[0]?.code ?? 'invalid')
    if (base.text) text = `(${base.text}) (${fq})`
  }
  const res = await queryApi.parse({ entity: 'findings', text })
  if (!res.valid || !res.document) throw new AdvancedFilterError(res.problems[0]?.code ?? 'invalid')
  const sort = u.searchParams.get('sort')
  const page = Number(u.searchParams.get('page') ?? '1') || 1
  const perPage = Number(u.searchParams.get('per_page') ?? '20') || 20
  return post<ApiFindingListResponse>('/api/v1/findings/search', {
    ...res.document,
    ...(sort ? { sort: sort.split(',') } : {}),
    page: { page, per_page: perPage },
  })
}
