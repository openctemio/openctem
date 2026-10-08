'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import { get } from '@/lib/api/client'
import type { StateChangeResponse } from '@/lib/api/generated'

/**
 * The five "What changed" views. Each maps to one /api/v1/state-history
 * endpoint; all of them take the same from / page / per_page / internet_facing
 * parameters and return the list envelope (`data`, `total`, `page`,
 * `per_page`, `total_pages`) with a real total.
 */
export const CHANGE_VIEWS = [
  'appeared',
  'disappeared',
  'newly_exposed',
  'exposure_changes',
  'shadow_it',
] as const

export type ChangeView = (typeof CHANGE_VIEWS)[number]

const VIEW_ENDPOINT: Record<ChangeView, string> = {
  appeared: '/api/v1/state-history/appearances',
  disappeared: '/api/v1/state-history/disappearances',
  newly_exposed: '/api/v1/state-history/newly-exposed',
  exposure_changes: '/api/v1/state-history/exposure-changes',
  shadow_it: '/api/v1/state-history/shadow-it',
}

export function isChangeView(v: string): v is ChangeView {
  return (CHANGE_VIEWS as readonly string[]).includes(v)
}

export interface ChangeListPage {
  data: StateChangeResponse[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface ChangeQuery {
  /** RFC3339 lower bound on changed_at. */
  from: string
  /** Only assets that are internet-facing now. */
  internetOnly: boolean
}

/** The request URL for one page (1-based) of a view (exported for tests). */
export function changeUrl(view: ChangeView, q: ChangeQuery, perPage: number, page: number): string {
  const params = new URLSearchParams({ from: q.from, per_page: String(perPage) })
  if (page > 1) params.set('page', String(page))
  if (q.internetOnly) params.set('internet_facing', 'true')
  return `${VIEW_ENDPOINT[view]}?${params.toString()}`
}

const swrConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  keepPreviousData: true,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
}

/** One server-paginated page of a view. `enabled` false skips the request. */
export function useAssetChanges(
  view: ChangeView,
  q: ChangeQuery,
  page: { pageIndex: number; pageSize: number },
  enabled = true
) {
  const key = enabled ? changeUrl(view, q, page.pageSize, page.pageIndex + 1) : null
  const { data, error, isLoading, mutate } = useSWR<ChangeListPage>(
    key,
    (url: string) => get<ChangeListPage>(url),
    swrConfig
  )
  return {
    changes: data?.data ?? [],
    total: data?.total ?? 0,
    error,
    isLoading,
    mutate,
  }
}

export type ChangeCounts = Record<ChangeView, number>

/** The count of every view for the period, for the metric strip. */
export function useAssetChangeCounts(q: ChangeQuery, enabled = true) {
  // One request for the five totals (GET /state-history/counts), where the
  // strip used to send one per_page=1 list request per view (research/81).
  // The API leaves newly exposed out of the internet-facing toggle, as the
  // page does: it is internet-facing by definition.
  const { data, error, isLoading, mutate } = useSWR<ChangeCounts>(
    enabled ? changeCountsUrl(q) : null,
    (url: string) => get<ChangeCounts>(url),
    swrConfig
  )
  return { counts: data, error, isLoading, mutate }
}

/** The URL of the five view totals for a window (exported for tests). */
export function changeCountsUrl(q: ChangeQuery): string {
  const params = new URLSearchParams({ from: q.from })
  if (q.internetOnly) params.set('internet_facing', 'true')
  return `/api/v1/state-history/counts?${params.toString()}`
}
