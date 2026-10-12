'use client'

import useSWR from 'swr'
import { del, get, post } from '@/lib/api/client'
import type { EASMNetworkSeed, EASMNetworkSeedList } from '@/lib/api/generated'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'

export const EASM_NETWORK_SEEDS_KEY = '/api/v1/easm/network-seeds'

/**
 * GET /api/v1/easm/network-seeds (RFC-082): the organization's AS number and
 * organization seeds with what public routing data says about them. Needs
 * scope:read and the attack_surface module. The panel re-reads once a few
 * seconds after a lookup starts (no polling).
 */
export function useEASMNetworkSeeds() {
  const { can } = usePermissions()
  const { moduleIds, isLoading: modulesLoading } = useTenantModules()
  const enabled =
    can(Permission.ScopeRead) && !modulesLoading && moduleIds.includes('attack_surface')
  const { data, error, isLoading, mutate } = useSWR<EASMNetworkSeedList>(
    enabled ? EASM_NETWORK_SEEDS_KEY : null,
    get,
    { revalidateOnFocus: false }
  )
  return {
    seeds: data?.items ?? [],
    max: data?.max ?? 50,
    error,
    isLoading: isLoading || modulesLoading,
    mutate,
    enabled,
  }
}

/** POST /api/v1/easm/network-seeds (scope:write, audited). */
export function addNetworkSeed(kind: 'asn' | 'org_name', value: string, label?: string) {
  return post<EASMNetworkSeed>(EASM_NETWORK_SEEDS_KEY, { kind, value, label })
}

/** DELETE /api/v1/easm/network-seeds/{id} (scope:delete, audited). */
export function deleteNetworkSeed(id: string) {
  return del(`${EASM_NETWORK_SEEDS_KEY}/${encodeURIComponent(id)}`)
}

/** POST /api/v1/easm/network-seeds/{id}/expand: at most once per 15 minutes. */
export function refreshNetworkSeed(id: string) {
  return post(`${EASM_NETWORK_SEEDS_KEY}/${encodeURIComponent(id)}/expand`, {})
}
