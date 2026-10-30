'use client'

import { useTranslation } from '@/context/i18n-provider'
import { LockedChip, LockedChipAction } from '@/features/shared/components/filter-chips-row'

/**
 * What the default inventory hides, as the quiet locked chip first in the
 * filter row: names awaiting review and names marked not ours (attribution,
 * RFC-036). "Show" lists every attribution, and the row then shows an ordinary
 * removable attribution chip instead; "Review" opens the queue where the names
 * awaiting review are decided. This chip is not dismissible, because it states
 * what the list leaves out.
 *
 * It renders only when something is hidden: with no count (unknown while other
 * filters apply, or still loading) or a count of 0 there is nothing to state,
 * and a chip claiming otherwise would be false.
 */
export function InventoryHiddenChip({
  count,
  onShowAll,
}: {
  /** How many it hides; the chip is absent unless this is above 0. */
  count?: number
  onShowAll: () => void
}) {
  const { t } = useTranslation()
  if (count === undefined || count <= 0) return null
  return (
    <LockedChip
      data-testid="inventory-hidden-chip"
      hint={t(
        'assets.hidden.hint',
        'Discovery adds names passively until a scope entry covers them. Names awaiting review and names marked not yours are left out of this list. Review decides the ones awaiting review.'
      )}
      actionLabel={t('assets.hidden.show', 'Show')}
      onAction={onShowAll}
      actions={
        <LockedChipAction href="/attack-surface/review">
          {t('assets.hidden.review', 'Review')}
        </LockedChipAction>
      }
    >
      {t(
        'assets.hidden.chipCount',
        '{count, plural, one {Hiding # name awaiting review or not ours} other {Hiding # names awaiting review or not ours}}',
        { count }
      )}
    </LockedChip>
  )
}
