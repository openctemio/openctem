'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { GitMerge, ArrowRight, History } from 'lucide-react'
import { DetailSection } from '@/features/shared'
import { EntityActivity } from '@/features/activity/components/entity-activity'
import type { ActivityItem } from '@/features/activity/types'

interface MergeLogEntry {
  id: string
  kept_asset_name: string
  merged_asset_name: string | null
  correlation_type: string
  action: string
  old_name: string | null
  new_name: string | null
  source: string
  created_at: string
}

interface AssetMergeHistoryProps {
  assetId: string
  /** The asset's name, under the panel title. */
  assetName?: string
}

/** Merge-log rows as the shared ActivityPanel's events (text only). */
export function mergeLogItems(entries: MergeLogEntry[]): ActivityItem[] {
  const out: ActivityItem[] = []
  for (const e of entries) {
    let summary: string | null = null
    if (e.action === 'merge' && e.merged_asset_name) {
      summary = `merged “${e.merged_asset_name}” into this asset`
    } else if (e.action === 'rename' && e.old_name && e.new_name) {
      summary = `renamed it from “${e.old_name}” to “${e.new_name}”`
    } else if (e.action === 'normalize' && e.old_name) {
      summary = `normalized the name from “${e.old_name}”`
    }
    if (!summary) continue
    out.push({
      kind: 'event',
      id: e.id,
      at: e.created_at,
      actor: { name: e.source ? `Deduplication (${e.source})` : 'Deduplication', kind: 'system' },
      icon: e.action === 'merge' ? GitMerge : ArrowRight,
      summary,
      detail: e.correlation_type
        ? `Matched by ${e.correlation_type.replace(/_/g, ' ')}`
        : undefined,
    })
  }
  return out
}

/**
 * The asset's identity history (merges, renames, normalisations) in the
 * asset drawer: the shared activity trigger + panel, read only.
 */
export function AssetMergeHistory({ assetId, assetName }: AssetMergeHistoryProps) {
  const { data } = useSWR<{ data: MergeLogEntry[] }>(
    assetId ? `/api/v1/assets/dedup/merge-log?asset_id=${assetId}&limit=10` : null,
    get,
    { revalidateOnFocus: false }
  )

  const entries = data?.data
  if (!entries || entries.length === 0) return null

  return (
    <DetailSection title="Identity history" icon={History} count={entries.length}>
      <EntityActivity
        entityKey={`asset-identity:${assetId}`}
        title="Identity history"
        subject={assetName}
        items={mergeLogItems(entries)}
        urlParam={false}
      />
    </DetailSection>
  )
}
