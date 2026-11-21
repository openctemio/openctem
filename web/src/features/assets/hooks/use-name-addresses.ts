'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'

/** One source's record of an address. */
export interface NameAddressSource {
  kind: string
  name: string
  first_seen: string
  last_seen: string
  removed_at?: string
}

/** One address a name resolved to, over every source. */
export interface NameAddress {
  address: string
  /** Set for an address inside a provider's published shared range. */
  provider?: string
  class?: string
  /** A source still reports it. */
  current: boolean
  first_seen: string
  last_seen: string
  removed_at?: string
  sources: NameAddressSource[]
}

export interface NameAddresses {
  items: NameAddress[]
  /** Addresses left out past the read's limit. */
  truncated: number
}

export function nameAddressesUrl(assetId: string): string {
  return `/api/v1/assets/${assetId}/addresses`
}

/**
 * GET /api/v1/assets/{id}/addresses: every address a domain or subdomain
 * resolved to, with first and last seen, current ones first. Shared provider
 * addresses are recorded only here (research/531).
 */
export function useNameAddresses(assetId: string | null) {
  const { can } = usePermissions()
  const key = assetId && can(Permission.AssetsRead) ? nameAddressesUrl(assetId) : null
  const { data, error, isLoading } = useSWR<NameAddresses>(key, get, {
    revalidateOnFocus: false,
  })
  return { data, error, isLoading }
}

/** A group of current addresses: one per provider, then the others. */
export interface AddressGroup {
  /** Empty for the addresses no provider range holds. */
  provider: string
  addresses: string[]
}

/** The current addresses grouped by provider, providers first. */
export function currentAddressGroups(items: readonly NameAddress[]): AddressGroup[] {
  const byProvider = new Map<string, string[]>()
  for (const it of items) {
    if (!it.current) continue
    const key = it.provider ?? ''
    const list = byProvider.get(key) ?? []
    list.push(it.address)
    byProvider.set(key, list)
  }
  return [...byProvider.entries()]
    .sort(([a], [b]) => (a === '' ? 1 : b === '' ? -1 : a.localeCompare(b)))
    .map(([provider, addresses]) => ({ provider, addresses }))
}
