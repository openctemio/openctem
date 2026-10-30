'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'

/** One open port of an address the name resolves to. */
export interface ResolvedPort {
  address_id: string
  address: string
  port_id: string
  port: number
  transport?: string
  service?: string
  product?: string
  version?: string
  last_seen?: string
}

export interface ResolvedPorts {
  items: ResolvedPort[]
  /** Ports whose address or port is outside the caller's data scope. */
  hidden_count: number
  truncated: boolean
}

/** The URL the asset view primes (api AssetViewParts). */
export function resolvedPortsUrl(assetId: string): string {
  return `/api/v1/assets/${assetId}/resolved-ports`
}

/**
 * GET /api/v1/assets/{id}/resolved-ports: the open ports of the addresses a
 * domain or subdomain resolves to. The API filters every address and port by
 * the caller's data scope and only counts the others.
 */
export function useResolvedPorts(assetId: string | null) {
  const { can } = usePermissions()
  const key = assetId && can(Permission.AssetsRead) ? resolvedPortsUrl(assetId) : null
  const { data, error, isLoading } = useSWR<ResolvedPorts>(key, get, {
    revalidateOnFocus: false,
  })
  return { data, error, isLoading }
}
