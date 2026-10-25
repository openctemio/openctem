'use client'

import { useTranslation } from '@/context/i18n-provider'
import { LockedChip } from '@/features/shared/components/filter-chips-row'

/**
 * What the default inventory hides, as the quiet locked chip first in the
 * filter row: names awaiting review and names marked not ours (attribution,
 * RFC-036). "Show" lists every attribution, and the row then shows an ordinary
 * removable attribution chip instead; this one is not dismissible, because it
 * states what the list leaves out.
 */
export function InventoryHiddenChip({ onShowAll }: { onShowAll: () => void }) {
  const { t } = useTranslation()
  return (
    <LockedChip
      data-testid="inventory-hidden-chip"
      hint={t(
        'assets.hidden.hint',
        'Discovery adds names passively until a scope entry covers them. Names awaiting review and names marked not yours are left out of this list.'
      )}
      actionLabel={t('assets.hidden.show', 'Show')}
      onAction={onShowAll}
    >
      {t('assets.hidden.chip', 'Hiding names awaiting review and not ours')}
    </LockedChip>
  )
}
