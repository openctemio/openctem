'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import type { AssetCoverage } from '../lib/asset-coverage'

/** GET /api/v1/assets/{id}/coverage — what each capability the asset needs has done (RFC-093). */
export function useAssetCoverage(assetId: string | null) {
  const { can } = usePermissions()
  const key = assetId && can(Permission.AssetsRead) ? `/api/v1/assets/${assetId}/coverage` : null
  const { data, error, isLoading, mutate } = useSWR<AssetCoverage>(key, get, {
    revalidateOnFocus: false,
  })
  return { data, error, isLoading, mutate }
}
