import {
  ATTRIBUTION_FILTER_VALUES,
  attributionQuery,
  type InventoryFilters,
} from '../../lib/inventory-url'
import type { AssetSearchFilters } from '../../hooks/use-assets'

/** The asset reasons of Needs attention. */
export type AttentionReason =
  'validate_primary' | 'decide_monitoring' | 'no_owner' | 'context' | 'unscanned'

/**
 * The monitoring states that wait for a person: a name awaiting review, or a
 * discovered one with too little evidence. Every attribution state is asked,
 * since the inventory's default leaves names awaiting review out.
 */
const UNDECIDED: InventoryFilters = {
  monitoringState: ['pending_decision', 'unvalidated'],
  attribution: [...ATTRIBUTION_FILTER_VALUES],
}

/** Each reason as an inventory filter: the list here and the inventory link agree. */
export const ATTENTION_FILTERS: Record<AttentionReason, InventoryFilters> = {
  validate_primary: { ...UNDECIDED, isPrimary: true },
  decide_monitoring: UNDECIDED,
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
