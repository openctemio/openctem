'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { endpoints } from '@/lib/api/endpoints'
import { usePermissions, Permission } from '@/lib/permissions'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import type { NeighborhoodResponse } from '../lib/neighborhood-graph'

export type NeighborhoodDepth = 1 | 2 | 3

/** The query string of a neighborhood request. */
export function neighborhoodQuery(depth: NeighborhoodDepth): string {
  return new URLSearchParams({ depth: String(depth) }).toString()
}

/** Reads the depth-1 neighborhood of one node (expand from it). */
export function fetchNodeNeighborhood(assetId: string): Promise<NeighborhoodResponse> {
  return get<NeighborhoodResponse>(endpoints.assets.neighborhood(assetId, neighborhoodQuery(1)))
}

/**
 * GET /api/v1/assets/{id}/neighborhood: the assets around an asset (both
 * directions, large sibling groups as clusters) and its discovery lineage.
 * Follows the relationships module and assets:read, as the API does.
 */
export function useAssetNeighborhood(assetId: string | null | undefined, depth: NeighborhoodDepth) {
  const { can } = usePermissions()
  const moduleOn = useModuleEnabled('relationships')
  const key =
    assetId && can(Permission.AssetsRead) && moduleOn
      ? endpoints.assets.neighborhood(assetId, neighborhoodQuery(depth))
      : null
  const { data, error, isLoading, mutate } = useSWR<NeighborhoodResponse>(
    key,
    (url: string) => get<NeighborhoodResponse>(url),
    { revalidateOnFocus: false, keepPreviousData: true }
  )
  return { data, error, isLoading: key ? isLoading : false, mutate }
}
