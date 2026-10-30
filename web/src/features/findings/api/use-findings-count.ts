import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { buildFindingsEndpoint } from './findings-query'
import type { ApiFindingListResponse, FindingApiFilters } from './finding-api.types'

/**
 * The number of findings a filter selects (one row asked, `total` read), for a
 * count beside the list such as "Informational hidden (N)". Its own hook, so it
 * is never mistaken for the list request. The caller renders it only inside
 * the signed-in list page; `enabled` gates the request.
 */
export function useFindingsCount(filters: FindingApiFilters, enabled = true): number | undefined {
  const key = enabled
    ? buildFindingsEndpoint({ ...filters, page: 1, per_page: 1, sort: undefined })
    : null
  const { data } = useSWR<ApiFindingListResponse>(
    key,
    (url: string) => get<ApiFindingListResponse>(url),
    {
      revalidateOnFocus: false,
      keepPreviousData: true,
      onError: () => {},
    }
  )
  return data?.total
}
