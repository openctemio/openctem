import useSWR from 'swr'
import { assetListKey, useAssets } from '../../hooks/use-assets'
import { useDedupReviews } from '../../api/use-asset-dedup'
import { useSuggestionCount } from '@/features/relationships/api/use-relationship-suggestions'
import type { AttentionReasonDef } from '@/config/section-tabs'
import { attentionCountQuery, type AttentionReason } from './attention-filters'

const ASSET_REASONS: readonly string[] = [
  'validate_primary',
  'decide_monitoring',
  'no_owner',
  'context',
  'unscanned',
]

/**
 * How many items a reason holds, or `undefined` while loading or when
 * `enabled` is false (nothing is requested then). Every figure comes from the
 * list endpoint the queue itself reads, so it is scoped to what the reader may
 * open: never a count of assets they cannot see. Only the request for this
 * reason is sent.
 *
 * `cacheOnly` (asset reasons): send nothing, show the figure only when this
 * tab already holds the same answer (a page that does not need the count for
 * itself, such as the Assets tab strip on Groups).
 */
export function useAttentionCount(
  id: AttentionReasonDef['id'],
  enabled = true,
  { cacheOnly = false }: { cacheOnly?: boolean } = {}
): number | undefined {
  const isAsset = ASSET_REASONS.includes(id)
  const query = attentionCountQuery(
    isAsset ? (id as AttentionReason) : 'no_owner',
    !(enabled && isAsset && !cacheOnly)
  )
  const assets = useAssets(query)
  // No fetcher: reads the cache entry `useAssets` fills for the same query.
  const cached = useSWR<{ total?: number }>(
    enabled && isAsset && cacheOnly ? assetListKey(query) : null,
    null,
    { revalidateOnFocus: false, revalidateIfStale: false, revalidateOnMount: false }
  )
  const suggestions = useSuggestionCount(enabled && id === 'relationships')
  const duplicates = useDedupReviews(enabled && id === 'duplicates')
  if (!enabled) return undefined
  if (isAsset && cacheOnly) return cached.data ? (cached.data.total ?? 0) : undefined
  if (isAsset) return assets.hasLoaded ? assets.total : undefined
  if (id === 'relationships') return suggestions.data?.count
  return duplicates.data ? (duplicates.data.total ?? duplicates.data.data?.length ?? 0) : undefined
}
