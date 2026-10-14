'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { endpoints } from '@/lib/api/endpoints'
import { usePermissions, Permission } from '@/lib/permissions'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import type { RelationshipType } from '../types'

export type RelatedDirection = 'outgoing' | 'incoming'

/** The asset at the other end of an edge, as GET .../relationships/groups returns it. */
export interface RelatedAssetRef {
  id: string
  name: string
  type: string
  sub_type?: string
  status?: string
  criticality?: string
  exposure?: string
  last_seen?: string
}

/** One edge seen from the asset being viewed. */
export interface RelatedAssetItem {
  relationship_id: string
  type: RelationshipType
  direction: RelatedDirection
  asset: RelatedAssetRef
  discovery_method: string
  confidence: string
  is_control_plane: boolean
  last_verified?: string
  created_at: string
}

export interface RelatedAssetGroup {
  type: RelationshipType
  direction: RelatedDirection
  total: number
  items: RelatedAssetItem[]
}

export interface RelatedAssetsResponse {
  groups: RelatedAssetGroup[]
  /** Edges the caller may see. */
  total: number
  /** Related assets outside the caller's data scope: a number, never names. */
  hidden_count: number
}

export interface RelatedAssetsQuery {
  type?: RelationshipType
  direction?: RelatedDirection
  q?: string
  offset?: number
  limit?: number
}

function queryString(q: RelatedAssetsQuery): string {
  const p = new URLSearchParams()
  if (q.type) p.set('type', q.type)
  if (q.direction) p.set('direction', q.direction)
  if (q.q?.trim()) p.set('q', q.q.trim())
  if (q.offset) p.set('offset', String(q.offset))
  if (q.limit) p.set('limit', String(q.limit))
  return p.toString()
}

/**
 * The related assets of one asset, grouped by relationship type and direction.
 * Without type/direction: every group with its first `limit` rows. With both:
 * one group paged by offset/limit, optionally narrowed by a name search.
 * Follows the relationships module and assets:read, as the API does.
 */
export function useRelatedAssets(
  assetId: string | null | undefined,
  query: RelatedAssetsQuery = {}
) {
  const { can } = usePermissions()
  const moduleOn = useModuleEnabled('relationships')
  const shouldFetch = !!assetId && can(Permission.AssetsRead) && moduleOn
  const key = shouldFetch ? endpoints.assets.relationshipGroups(assetId, queryString(query)) : null

  const { data, error, isLoading, mutate } = useSWR<RelatedAssetsResponse>(
    key,
    (url: string) => get<RelatedAssetsResponse>(url),
    { revalidateOnFocus: false, keepPreviousData: true }
  )

  return {
    data,
    groups: data?.groups ?? [],
    total: data?.total ?? 0,
    hiddenCount: data?.hidden_count ?? 0,
    isLoading: shouldFetch ? isLoading : false,
    error,
    mutate,
    enabled: shouldFetch,
  }
}
