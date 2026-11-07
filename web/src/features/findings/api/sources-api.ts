/**
 * What each source reported for one finding (GET /api/v1/findings/{id}/sources,
 * docs/architecture/finding-source-records.md): one record per source with
 * its own title, text, severity, native identity, scores and unmapped fields,
 * the primary (first reporting) source first, and the fields the sources
 * disagree on. The API answers 404 outside the caller's data scope and
 * leaves out the sensor without sensors:read.
 */

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { useCurrentTenantId } from '@/context/tenant-provider'
import type { components } from '@/lib/api/generated'

type S = components['schemas']
export type FindingSourceRecord = S['internal_infra_http_handler.FindingSourceRecordResponse']
export type FindingSourceDifference = S['internal_infra_http_handler.FindingSourceDifference']
export type FindingSourcesResponse = S['internal_infra_http_handler.FindingSourcesResponse']

export function findingSourcesUrl(findingId: string): string {
  return `/api/v1/findings/${encodeURIComponent(findingId)}/sources`
}

const swrConfig = { revalidateOnFocus: false, shouldRetryOnError: false }

/** The per-source records of one finding. */
export function useFindingSources(findingId: string | undefined) {
  const tenantId = useCurrentTenantId()
  const key = tenantId && findingId ? findingSourcesUrl(findingId) : null
  return useSWR<FindingSourcesResponse>(
    key,
    (url: string) => get<FindingSourcesResponse>(url),
    swrConfig
  )
}
