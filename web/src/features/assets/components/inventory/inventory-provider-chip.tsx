'use client'

import { useTranslation } from '@/context/i18n-provider'
import { LockedChip } from '@/features/shared/components/filter-chips-row'

/**
 * Provider addresses the default inventory leaves out (research/531):
 * addresses inside ranges a provider shares with many organizations, kept
 * with their history but not the organization's assets. "Show" lists only
 * them (attribution=provider_address). Renders only when the count is above 0.
 */
export function InventoryProviderChip({ count, onShow }: { count?: number; onShow: () => void }) {
  const { t } = useTranslation()
  if (count === undefined || count <= 0) return null
  return (
    <LockedChip
      data-testid="inventory-provider-chip"
      hint={t(
        'assets.providerAddresses.hint',
        'Addresses inside ranges a provider shares with many organizations. They are third-party infrastructure: kept with their history, left out of this list and of your totals.'
      )}
      actionLabel={t('assets.providerAddresses.show', 'Show')}
      onAction={onShow}
    >
      {t(
        'assets.providerAddresses.chip',
        '{count, plural, one {Provider addresses (#)} other {Provider addresses (#)}}',
        { count }
      )}
    </LockedChip>
  )
}
