/**
 * The scans list for a filter that the page's controls cannot show (`fq`: an
 * OR across fields, a nested group). The list never receives text: the page's
 * other list params and the fq text are checked by POST /api/v1/query/parse
 * as the signed-in person and the resulting filter document is sent to
 * POST /api/v1/scans/search, the same registry and visibility as GET /scans.
 */

import { post } from '@/lib/api/client'
import { queryApi } from '@/features/query/api/query-api'
import type { ScanConfigListResponse } from '@/lib/api/scan-types'

/** Params of the list URL that are not part of the filter. */
const PAGE_PARAMS = new Set(['page', 'per_page', 'sort', 'fq', 'include_ad_hoc'])

/** An fq filter the server refused: the list shows its problem. */
export class AdvancedScanFilterError extends Error {
  constructor(readonly code: string) {
    super('the filter is not valid')
  }
}

/** The list for a URL that carries fq. */
export async function fetchAdvancedScans(url: string): Promise<ScanConfigListResponse> {
  const u = new URL(url, 'http://local')
  const fq = u.searchParams.get('fq') ?? ''
  const rest = new URLSearchParams()
  u.searchParams.forEach((v, k) => {
    if (!PAGE_PARAMS.has(k)) rest.append(k, v)
  })
  let text = fq
  if (rest.toString() !== '') {
    const base = await queryApi.parse({ entity: 'scans', params: rest.toString() })
    if (!base.valid) throw new AdvancedScanFilterError(base.problems[0]?.code ?? 'invalid')
    if (base.text) text = `(${base.text}) (${fq})`
  }
  const res = await queryApi.parse({ entity: 'scans', text })
  if (!res.valid || !res.document) {
    throw new AdvancedScanFilterError(res.problems[0]?.code ?? 'invalid')
  }
  const sort = u.searchParams.get('sort')
  const page = Number(u.searchParams.get('page') ?? '1') || 1
  const perPage = Number(u.searchParams.get('per_page') ?? '20') || 20
  const adHoc = u.searchParams.get('include_ad_hoc') === 'true' ? '?include_ad_hoc=true' : ''
  return post<ScanConfigListResponse>(`/api/v1/scans/search${adHoc}`, {
    ...res.document,
    ...(sort ? { sort: [sort] } : {}),
    page: { page, per_page: perPage },
  })
}
