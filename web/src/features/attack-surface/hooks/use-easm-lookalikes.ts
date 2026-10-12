'use client'

import useSWR from 'swr'
import { del, get, post, put } from '@/lib/api/client'
import type {
  LookalikeCandidateList,
  LookalikeWatch,
  LookalikeWatchList,
} from '@/lib/api/generated'
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

/** Registered lookalikes of one watch. */
export function useRegisteredLookalikes(watchId: string | null) {
  const { data, error, isLoading } = useSWR<LookalikeCandidateList>(
    watchId ? `${LOOKALIKE_WATCHES_KEY}/${encodeURIComponent(watchId)}/registered` : null,
    get,
    { revalidateOnFocus: false }
  )
  return { items: data?.items ?? [], error, isLoading }
}

/**
 * Open lookalike exposures to triage (GET /api/v1/exposures, the
 * findings:read and exposures:read gates apply server-side).
 */
export function useLookalikeExposures(
  state: 'active' | 'accepted' | 'false_positive' | 'resolved'
) {
  const { can } = usePermissions()
  const on = useModuleOn()
  const allowed = on && can(Permission.FindingsRead) && can(Permission.ExposuresRead)
  const key = allowed
    ? `/api/v1/exposures?event_type=lookalike_domain&state=${state}&per_page=50`
    : null
  const { data, error, isLoading, mutate } = useSWR<ExposureListResponse>(key, get, {
    revalidateOnFocus: false,
  })
  return { exposures: data?.data ?? [], total: data?.total ?? 0, error, isLoading, mutate, allowed }
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
