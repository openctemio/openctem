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
