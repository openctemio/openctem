'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import type { AssetLineage } from '../lib/asset-lineage'

/** The URL the asset view primes (api AssetViewParts). */
export function assetLineageUrl(assetId: string): string {
  return `/api/v1/assets/${assetId}/lineage`
}

/**
 * GET /api/v1/assets/{id}/lineage: the asset and its ancestors up to the
 * root. The API redacts every ancestor outside the caller's data scope.
 */
export function useAssetLineage(assetId: string | null) {
  const { can } = usePermissions()
  const key = assetId && can(Permission.AssetsRead) ? assetLineageUrl(assetId) : null
  const { data, error, isLoading, mutate } = useSWR<AssetLineage>(key, get, {
    revalidateOnFocus: false,
  })
  return { lineage: data, error, isLoading, mutate }
}
