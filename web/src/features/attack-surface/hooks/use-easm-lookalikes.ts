'use client'

import useSWR from 'swr'
import useSWRInfinite from 'swr/infinite'
import { del, get, post, put } from '@/lib/api/client'
import type { LookalikeWatch, LookalikeWatchList } from '@/lib/api/generated'
import type { ExposureListResponse } from '@/lib/api/exposure-types'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'

export const LOOKALIKE_WATCHES_KEY = '/api/v1/easm/lookalikes/watches'

function useModuleOn() {
  const { moduleIds, isLoading } = useTenantModules()
  return !isLoading && moduleIds.includes('attack_surface')
}

/** GET /api/v1/easm/lookalikes/watches (RFC-083), scope:read. */
export function useLookalikeWatches() {
  const { can } = usePermissions()
  const on = useModuleOn()
  const { data, error, isLoading, mutate } = useSWR<LookalikeWatchList>(
    on && can(Permission.ScopeRead) ? LOOKALIKE_WATCHES_KEY : null,
    get,
    { revalidateOnFocus: false }
  )
  return {
    watches: data?.items ?? [],
    techniques: data?.techniques ?? [],
    max: data?.max ?? 20,
    error,
    isLoading,
    mutate,
  }
}

export const LOOKALIKE_PAGE_SIZE = 50

/**
 * Lookalike exposures to triage (GET /api/v1/exposures, the findings:read and
 * exposures:read gates apply server-side), one page at a time: `loadMore`
 * appends the next page, `total` is the whole count in this state.
 */
export function useLookalikeExposures(
  state: 'active' | 'accepted' | 'false_positive' | 'resolved'
) {
  const { can } = usePermissions()
  const on = useModuleOn()
  const allowed = on && can(Permission.FindingsRead) && can(Permission.ExposuresRead)
  const { data, error, isLoading, isValidating, mutate, size, setSize } =
    useSWRInfinite<ExposureListResponse>(
      (index) =>
        allowed
          ? `/api/v1/exposures?event_type=lookalike_domain&state=${state}&page=${index + 1}&per_page=${LOOKALIKE_PAGE_SIZE}`
          : null,
      get,
      { revalidateOnFocus: false, revalidateFirstPage: false }
    )
  const exposures = (data ?? []).flatMap((p) => p?.data ?? [])
  const total = data?.[0]?.total ?? 0
  const loadingMore = isValidating && size > (data?.length ?? 0)
  return {
    exposures,
    total,
    error,
    isLoading,
    mutate,
    allowed,
    hasMore: exposures.length < total,
    loadingMore,
    loadMore: () => setSize(size + 1),
    reset: () => setSize(1),
  }
}

export interface LookalikeWatchInput {
  domain?: string
  enabled?: boolean
  techniques: string[]
  max_candidates: number
}

export function createLookalikeWatch(input: LookalikeWatchInput) {
  return post<LookalikeWatch>(LOOKALIKE_WATCHES_KEY, input)
}

export function updateLookalikeWatch(id: string, input: LookalikeWatchInput) {
  return put<LookalikeWatch>(`${LOOKALIKE_WATCHES_KEY}/${encodeURIComponent(id)}`, input)
}

export function deleteLookalikeWatch(id: string) {
  return del(`${LOOKALIKE_WATCHES_KEY}/${encodeURIComponent(id)}`)
}
