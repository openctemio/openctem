'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { buildFindingsQuery } from './findings-query'
import type { FindingApiFilters } from './finding-api.types'
import type { FindingPractice } from '../lib/practice'

export const PRACTICE_COUNTS_URL = '/api/v1/findings/practice-counts'

/** Response of GET /findings/practice-counts. */
export interface PracticeCountsResponse {
  total: number
  vulnerabilities: number
  practices: { practice: FindingPractice; count: number }[]
}

/** The practice switch's counts as a map, plus the two main slices. */
export interface PracticeCounts {
  byPractice: Partial<Record<FindingPractice, number>>
  vulnerabilities: number
  total: number
}

/**
 * The caller's findings per practice under the list's filters (the server
 * leaves the practice condition out), in the caller's scope. Paging and
 * sorting are not part of the key, so turning a page asks nothing.
 */
export function usePracticeCounts(filters: FindingApiFilters, enabled: boolean) {
  const params = buildFindingsQuery({
    ...filters,
    page: undefined,
    per_page: undefined,
    sort: undefined,
  })
  params.delete('practice')
  params.delete('practice_not')
  const qs = params.toString()
  const key = enabled ? `${PRACTICE_COUNTS_URL}${qs ? `?${qs}` : ''}` : null
  const { data } = useSWR<PracticeCountsResponse>(
    key,
    (url: string) => get<PracticeCountsResponse>(url),
    {
      revalidateOnFocus: false,
      keepPreviousData: true,
      dedupingInterval: 30_000,
      // The switch shows no counts when this fails; a toast would be noise.
      onError: () => {},
    }
  )
  if (!data) return undefined
  const byPractice: Partial<Record<FindingPractice, number>> = {}
  for (const p of data.practices ?? []) byPractice[p.practice] = p.count
  return {
    byPractice,
    vulnerabilities: data.vulnerabilities,
    total: data.total,
  } satisfies PracticeCounts
}
