'use client'

import { useMemo } from 'react'
import { useSWRConfig } from 'swr'
import { buildFindingsEndpoint } from './findings-query'
import { useFindingsApi } from './use-findings-api'
import type {
  ApiFindingListResponse,
  ApiPracticeCounts,
  FindingApiFilters,
} from './finding-api.types'
import type { FindingPractice } from '../lib/practice'

/** The include value of GET /findings that adds practice_counts to the page. */
export const INCLUDE_PRACTICE_COUNTS = 'practice_counts'

/** The practice switch's counts as a map, plus the two main slices. */
export interface PracticeCounts {
  byPractice: Partial<Record<FindingPractice, number>>
  vulnerabilities: number
  total: number
}

export function toPracticeCounts(raw: ApiPracticeCounts): PracticeCounts {
  const byPractice: Partial<Record<FindingPractice, number>> = {}
  for (const p of raw.practices ?? []) byPractice[p.practice as FindingPractice] = p.count
  return { byPractice, vulnerabilities: raw.vulnerabilities, total: raw.total }
}

/**
 * The list request of the findings page and the practice switch's counts.
 *
 * The counts come with the list (GET /findings?include=practice_counts): the
 * list's filter with its practice condition left out, counted as the caller
 * (tenant, data scope and pentest membership), so the switch costs no request
 * of its own. Page 1 asks for them; a later page reads them from page 1's
 * cached answer, and asks itself only when there is none (a link straight to
 * page 3), so turning a page counts nothing again. The grouped view, which
 * loads no flat page, asks for one row with the counts. An fq filter has no
 * counts: POST /findings/search answers the rows only.
 */
export function usePracticeCountsList(
  apiFilters: FindingApiFilters,
  opts: { enabled: boolean; grouped: boolean }
) {
  const { cache } = useSWRConfig()
  const active = opts.enabled && !apiFilters.fq
  const firstPage = buildFindingsEndpoint({
    ...apiFilters,
    page: 1,
    include: INCLUDE_PRACTICE_COUNTS,
  })
  const cached = active
    ? (cache?.get(firstPage)?.data as ApiFindingListResponse | undefined)?.practice_counts
    : undefined
  const onFirstPage = (apiFilters.page ?? 1) === 1
  const include = active && !opts.grouped && (onFirstPage || !cached)
  const listFilters = useMemo(
    () => (include ? { ...apiFilters, include: INCLUDE_PRACTICE_COUNTS } : apiFilters),
    [apiFilters, include]
  )
  // The grouped view: one row and the counts.
  const grouped = active && opts.grouped
  const groupedFilters = useMemo(
    () => ({
      ...apiFilters,
      page: 1,
      per_page: 1,
      sort: undefined,
      include: INCLUDE_PRACTICE_COUNTS,
    }),
    [apiFilters]
  )
  const { data: groupedPage } = useFindingsApi(groupedFilters, {
    enabled: grouped,
    keepPreviousData: true,
    // The switch shows no counts when this fails; a toast would be noise.
    onError: () => {},
  })

  return {
    listFilters,
    /** The counts for the list's own answer (or the grouped view's one-row page). */
    countsFor(list: ApiFindingListResponse | undefined): PracticeCounts | undefined {
      if (!active) return undefined
      const raw = opts.grouped
        ? groupedPage?.practice_counts
        : ((include ? list?.practice_counts : undefined) ?? cached)
      return raw ? toPracticeCounts(raw) : undefined
    },
  }
}
