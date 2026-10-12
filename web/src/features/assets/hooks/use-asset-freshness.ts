'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import type { AssetFreshness } from '../lib/asset-freshness'

/** GET /api/v1/assets/{id}/freshness — when each attribute class was last observed (RFC-075). */
export function useAssetFreshness(assetId: string | null) {
  const { can } = usePermissions()
  const key = assetId && can(Permission.AssetsRead) ? `/api/v1/assets/${assetId}/freshness` : null
  const { data, error, isLoading, mutate } = useSWR<AssetFreshness>(key, get, {
    revalidateOnFocus: false,
  })
  return { data, error, isLoading, mutate }
}
