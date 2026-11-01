import { useAssets } from '../../hooks/use-assets'
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
 */
export function useAttentionCount(
  id: AttentionReasonDef['id'],
  enabled = true
): number | undefined {
  const isAsset = ASSET_REASONS.includes(id)
  const assets = useAssets(
    attentionCountQuery(isAsset ? (id as AttentionReason) : 'no_owner', !(enabled && isAsset))
  )
  const suggestions = useSuggestionCount(enabled && id === 'relationships')
  const duplicates = useDedupReviews(enabled && id === 'duplicates')
  if (!enabled) return undefined
  if (isAsset) return assets.hasLoaded ? assets.total : undefined
  if (id === 'relationships') return suggestions.data?.count
  return duplicates.data ? (duplicates.data.total ?? duplicates.data.data?.length ?? 0) : undefined
}
