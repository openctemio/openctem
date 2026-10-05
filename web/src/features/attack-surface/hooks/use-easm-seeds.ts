'use client'

import useSWR from 'swr'
import { del, get, patch, post } from '@/lib/api/client'
import type { EASMSeed, EASMSeedList } from '@/lib/api/generated'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'

export const EASM_SEEDS_KEY = '/api/v1/easm/seeds'

/**
 * GET /api/v1/easm/seeds (RFC-036 §6.3). Fetched only with scope:read and the
 * attack_surface module, so a tenant without it gets no 403.
 */
export function useEASMSeeds() {
  const { can } = usePermissions()
  const { moduleIds, isLoading: modulesLoading } = useTenantModules()
  const enabled =
    can(Permission.ScopeRead) && !modulesLoading && moduleIds.includes('attack_surface')
  const { data, error, isLoading, mutate } = useSWR<EASMSeedList>(
    enabled ? EASM_SEEDS_KEY : null,
    get,
    {
      revalidateOnFocus: false,
    }
  )
  return { seeds: data?.data ?? [], error, isLoading: isLoading || modulesLoading, mutate, enabled }
}

export interface NewSeed {
  kind: 'root_domain'
  value: string
  label?: string
  discovery_enabled?: boolean
}

/** POST /api/v1/easm/seeds — attested: the caller states the authority. */
export function createSeed(seed: NewSeed) {
  return post<EASMSeed>(EASM_SEEDS_KEY, { ...seed, attested: true })
}

/** PATCH /api/v1/easm/seeds/{id} */
export function updateSeed(id: string, changes: { label?: string; discovery_enabled?: boolean }) {
  return patch<EASMSeed>(`${EASM_SEEDS_KEY}/${encodeURIComponent(id)}`, changes)
}

/** DELETE /api/v1/easm/seeds/{id} */
export function deleteSeed(id: string) {
  return del(`${EASM_SEEDS_KEY}/${encodeURIComponent(id)}`)
}
