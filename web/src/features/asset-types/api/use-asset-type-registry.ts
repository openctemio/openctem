'use client'

import { useCallback } from 'react'
import useSWR from 'swr'
import { fetcher } from '@/lib/api/client'
import { SWR_STATIC } from '@/lib/swr-config'
import { classAndLensLabel, type AssetTypeRegistry } from '../lib/asset-registry'

/** GET /api/v1/asset-types: the RFC-042 asset type registry. */
export const ASSET_TYPE_REGISTRY_ENDPOINT = '/api/v1/asset-types'

/**
 * The asset type registry: classes, lenses and every type's schema. It holds
 * no tenant data and changes only with a release, so it is fetched once per
 * session and shared by every caller (SWR dedupes on the endpoint).
 *
 * `classAndLens(type, subType)` labels an asset ("Code repository · Code"). It
 * answers from the generated constants until the registry has loaded.
 */
export function useAssetTypeRegistry() {
  // Static data: once per session in memory. Across page loads the browser
  // keeps the response and revalidates it with its ETag (a 304 without the
  // 107 KB body), through the API proxy.
  const { data, error, isLoading } = useSWR<AssetTypeRegistry>(
    ASSET_TYPE_REGISTRY_ENDPOINT,
    fetcher<AssetTypeRegistry>,
    { ...SWR_STATIC, revalidateOnFocus: false }
  )

  const classAndLens = useCallback(
    (type: string, subType?: string | null) => classAndLensLabel(data, type, subType),
    [data]
  )

  return { registry: data, classAndLens, isLoading, error }
}
