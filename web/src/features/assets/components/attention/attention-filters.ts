import { attributionQuery, type InventoryFilters } from '../../lib/inventory-url'
import type { AssetSearchFilters } from '../../hooks/use-assets'

/** The asset reasons of Needs attention. */
export type AttentionReason = 'no_owner' | 'context' | 'unscanned'

/** Each reason as an inventory filter: the list here and the inventory link agree. */
export const ATTENTION_FILTERS: Record<AttentionReason, InventoryFilters> = {
  no_owner: { hasOwner: false },
  context: { criticalities: ['none'] },
  unscanned: { coverage: 'uncovered' },
}

/**
 * The query that counts a reason: the queue's own filter and attribution, one
 * row per page, so the number is the queue's `total` for the same reader and
 * data scope.
 */
export function attentionCountQuery(reason: AttentionReason, skip: boolean): AssetSearchFilters {
  const base = ATTENTION_FILTERS[reason]
  return { ...base, attribution: attributionQuery(base), page: 1, pageSize: 1, skip }
}
