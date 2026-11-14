'use client'

/**
 * The first members of a counted group (cluster) of the neighborhood graph,
 * shown in the card under the graph when the group is selected, so the card
 * answers "which assets" without another step (api
 * docs/architecture/asset-relationships.md, "Neighborhood").
 *
 * Data scope: the names come only from the relationship groups endpoint,
 * which returns the assets the caller may see and counts the rest
 * (hidden_count); nothing here invents or keeps a name the server did not
 * send for this anchor, type and direction.
 */

import * as React from 'react'
import useSWR from 'swr'
import { ChevronRight } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { get } from '@/lib/api/client'
import { endpoints } from '@/lib/api/endpoints'
import { cn } from '@/lib/utils'
import type { RelatedAssetItem, RelatedAssetsResponse } from '../../hooks/use-related-assets'
import { getAssetTypeLabel } from '../../lib/asset-type-icon'
import { typeDotClass, type GraphClusterNode } from '../../lib/neighborhood-graph'

/** Members named in the card; "Show all" draws the rest. */
export const CLUSTER_PREVIEW = 5

/**
 * The members of one group the response names: only rows of the group's own
 * relationship type and direction, at most `limit`.
 */
export function clusterPreviewItems(
  res: RelatedAssetsResponse | undefined,
  cluster: Pick<GraphClusterNode, 'relType' | 'direction'>,
  limit = CLUSTER_PREVIEW
): { items: RelatedAssetItem[]; total: number } {
  const group = res?.groups.find(
    (g) => g.type === cluster.relType && g.direction === cluster.direction
  )
  if (!group) return { items: [], total: 0 }
  const items = group.items
    .filter((it) => it.type === cluster.relType && it.direction === cluster.direction)
    .slice(0, limit)
  return { items, total: group.total }
}

export interface ClusterMembersProps {
  cluster: GraphClusterNode
  onNavigateToAsset?: (assetId: string, name: string) => void
}

export function ClusterMembers({ cluster, onNavigateToAsset }: ClusterMembersProps) {
  const { t } = useTranslation()
  const key = endpoints.assets.relationshipGroups(
    cluster.anchor,
    new URLSearchParams({
      type: cluster.relType,
      direction: cluster.direction,
      limit: String(CLUSTER_PREVIEW),
      offset: String(cluster.offset),
    }).toString()
  )
  const { data, error, isLoading } = useSWR<RelatedAssetsResponse>(key, (url: string) =>
    get<RelatedAssetsResponse>(url)
  )
  const { items, total } = clusterPreviewItems(data, cluster)
  const more = Math.max(0, cluster.remaining - items.length)

  if (isLoading && !data) {
    return (
      <div className="mt-2 space-y-1" aria-busy="true">
        {[0, 1, 2].map((i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    )
  }
  if (error) {
    return (
      <p className="mt-2 text-xs text-muted-foreground">
        {t('assets.graph.membersFailed', 'Could not load the assets in this group')}
      </p>
    )
  }
  if (items.length === 0) {
    return total === 0 && cluster.remaining > 0 ? (
      <p className="mt-2 text-xs text-muted-foreground">
        {t('assets.graph.membersNone', 'None of these assets is in your data scope')}
      </p>
    ) : null
  }
  return (
    <div className="mt-2">
      <ul
        aria-label={t('assets.graph.membersLabel', 'Assets in this group')}
        className="divide-y rounded-md border bg-card"
      >
        {items.map((it) => (
          <li key={it.relationship_id}>
            <button
              type="button"
              className={cn(
                'flex min-h-11 w-full items-center gap-2 px-3 py-1.5 text-left sm:min-h-9',
                'hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none'
              )}
              onClick={() => onNavigateToAsset?.(it.asset.id, it.asset.name)}
            >
              <span
                aria-hidden
                className={cn('size-2 shrink-0 rounded-sm', typeDotClass(it.asset.type))}
              />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-medium" title={it.asset.name}>
                  {it.asset.name}
                </span>
                <span className="block truncate text-xs text-muted-foreground">
                  {t(`assets.typeLabel.${it.asset.type}`, getAssetTypeLabel(it.asset.type))}
                </span>
              </span>
              <ChevronRight className="size-4 shrink-0 text-muted-foreground" aria-hidden />
            </button>
          </li>
        ))}
      </ul>
      {more > 0 && (
        <p className="mt-1.5 text-xs text-muted-foreground tabular-nums">
          {t('assets.graph.membersMore', 'and {n} more', { n: more })}
        </p>
      )}
    </div>
  )
}
