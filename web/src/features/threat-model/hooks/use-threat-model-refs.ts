'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import type { AttackerProfileLite } from '../types'

/** Crown-jewel asset picked as a threat-model scope. */
export interface CrownJewelAsset {
  id: string
  name: string
  type?: string
  criticality?: string
}

interface AssetListResponse {
  data: Array<Record<string, unknown>>
  total: number
}

/** Crown jewels = assets flagged is_crown_jewel; scope candidates for a model. */
export function useCrownJewels() {
  const { data, isLoading, error } = useSWR<AssetListResponse>(
    '/api/v1/assets?is_crown_jewel=true&per_page=100',
    get,
    { revalidateOnFocus: false }
  )
  const crownJewels: CrownJewelAsset[] = (data?.data ?? []).map((a) => ({
    id: String(a.id),
    name: String(a.name ?? a.id),
    type: a.type as string | undefined,
    criticality: a.criticality as string | undefined,
  }))
  return { crownJewels, isLoading, error }
}

interface AttackerProfileListResponse {
  data: AttackerProfileLite[]
  total: number
}

/**
 * Map of attacker-profile id → { name, type } for resolving threat rows.
 *
 * The `/attacker-profiles` endpoint belongs to the (Phase-3 gated)
 * attacker_profiles module. This hook is used on the Threat Model page (which
 * lives under a different module), so pass `enabled: false` when the module is
 * disabled to skip the fetch — it would otherwise 403. A null key = no fetch;
 * threat rows fall back to the raw id.
 */
export function useAttackerProfileMap(enabled: boolean = true) {
  const { data, isLoading } = useSWR<AttackerProfileListResponse>(
    enabled ? '/api/v1/attacker-profiles?per_page=100' : null,
    get,
    { revalidateOnFocus: false }
  )
  const map = new Map<string, AttackerProfileLite>()
  for (const p of data?.data ?? []) map.set(p.id, p)
  return { profileMap: map, isLoading }
}

/** The most ids one batch read takes (the asset list's page size limit). */
export const ASSET_NAME_BATCH = 100

/** `GET /assets?ids=…` for one batch of ids. */
export function assetNamesURL(ids: string[]): string {
  return `/api/v1/assets?ids=${ids.map(encodeURIComponent).join(',')}&per_page=${ids.length}`
}

/**
 * Resolve a set of asset ids → display names, with ONE list request per 100
 * ids (`GET /assets?ids=…`) instead of one `GET /assets/{id}` per asset
 * (research/81). The API applies the caller's data scope: an asset the caller
 * may not see, or one deleted or merged since, resolves to a short id rather
 * than failing the page.
 */
export function useAssetNameMap(assetIds: string[]) {
  const unique = Array.from(new Set(assetIds.filter(Boolean))).sort()
  const batches: string[][] = []
  for (let i = 0; i < unique.length; i += ASSET_NAME_BATCH) {
    batches.push(unique.slice(i, i + ASSET_NAME_BATCH))
  }
  // One key per id set (the ids are sorted), so pages naming the same assets share it.
  const key = batches.length ? batches.map(assetNamesURL).join(' ') : null

  const { data, isLoading } = useSWR<Record<string, string>>(
    key,
    async () => {
      const pages = await Promise.all(
        batches.map((ids) =>
          get<AssetListResponse>(assetNamesURL(ids)).catch(() => ({ data: [], total: 0 }))
        )
      )
      const names: Record<string, string> = {}
      for (const page of pages) {
        for (const a of page.data ?? []) {
          if (typeof a.id === 'string' && typeof a.name === 'string') names[a.id] = a.name
        }
      }
      return names
    },
    { revalidateOnFocus: false }
  )

  const nameFor = (id: string | undefined): string => {
    if (!id) return '—'
    return data?.[id] ?? shortId(id)
  }

  return { nameFor, isLoading }
}

function shortId(id: string): string {
  return id.length > 8 ? `${id.slice(0, 8)}…` : id
}
