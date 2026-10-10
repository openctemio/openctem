'use client'

import useSWRInfinite from 'swr/infinite'
import { get } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import { changesUrl, type AssetChangePage, type ChangeFilters } from '../lib/asset-timeline'

/**
 * Pages of an asset's change timeline (assetId) or of the organization feed
 * (null), newest first, following next_cursor. Needs assets:read; the API
 * answers only for assets in the caller's data scope.
 */
export function useAssetChanges(assetId: string | null, filters: ChangeFilters, enabled = true) {
  const { can } = usePermissions()
  const allowed = enabled && can(Permission.AssetsRead)
  const { data, error, isLoading, isValidating, size, setSize, mutate } =
    useSWRInfinite<AssetChangePage>(
      (index, previous: AssetChangePage | null) => {
        if (!allowed) return null
        if (index === 0) return changesUrl(assetId, filters)
        if (!previous?.next_cursor) return null
        return changesUrl(assetId, filters, previous.next_cursor)
      },
      get,
      { revalidateOnFocus: false, revalidateFirstPage: false }
    )
  const pages = data ?? []
  const events = pages.flatMap((p) => p.items ?? [])
  const hasMore = pages.length > 0 && !!pages[pages.length - 1]?.next_cursor
  return {
    events,
    error,
    isLoading,
    loadingMore: isValidating && size > pages.length,
    hasMore,
    loadMore: () => setSize(size + 1),
    mutate,
  }
}
