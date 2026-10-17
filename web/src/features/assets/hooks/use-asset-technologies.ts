'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import type { TechnologyCategory } from '../types'

/** One technology detected on an asset (GET /assets/{id}/technologies, RFC-112). */
export interface AssetTechnology {
  name: string
  version?: string
  category: TechnologyCategory
  kind: 'software' | 'infrastructure' | 'http_security' | 'marketing'
  /** The tool's own confidence, 0-100; 0 = the tool gave none. */
  confidence: number
  source?: string
  first_seen_at: string
  last_seen_at: string
}

/** Every technology detected on the asset, with confidence and sightings. */
export function useAssetTechnologies(assetId: string | null) {
  const { can } = usePermissions()
  const key =
    assetId && can(Permission.AssetsRead)
      ? `/api/v1/assets/${encodeURIComponent(assetId)}/technologies`
      : null
  const { data, error, isLoading, mutate } = useSWR<{ data: AssetTechnology[] }>(key, get, {
    revalidateOnFocus: false,
  })
  return { data: data?.data, error, isLoading, mutate }
}

/** One technology across the assets the caller may list (the filter's options). */
export interface TechnologyFacet {
  name: string
  key: string
  category: TechnologyCategory
  asset_count: number
}

/**
 * GET /api/v1/assets/technologies: the technologies on the assets the caller
 * may list (tenant and data scope applied by the API), most used first; `q`
 * filters names by substring.
 */
export function useTechnologyFacets(q?: string, enabled = true) {
  const { can } = usePermissions()
  const params = new URLSearchParams({ limit: '100' })
  if (q) params.set('q', q)
  const key = enabled && can(Permission.AssetsRead) ? `/api/v1/assets/technologies?${params}` : null
  const { data, error, isLoading } = useSWR<{ data: TechnologyFacet[] }>(key, get, {
    revalidateOnFocus: false,
    keepPreviousData: true,
  })
  return { facets: data?.data ?? [], error, isLoading }
}
