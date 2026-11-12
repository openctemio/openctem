'use client'

/**
 * The type tabs of the External surface lens: All, then Domains, Subdomains, IP
 * addresses, Services, Web endpoints and Certificates, each with its count. A
 * tab is a locked type condition of the list (`?tab=<type>`), one choice at a
 * time, on the shared segmented control.
 */

import { useMemo } from 'react'
import { SegmentedLens } from '@/features/shared/components/segmented-lens'
import { useTranslation } from '@/context/i18n-provider'
import { INVENTORY_TABS } from '../../lib/inventory-tabs'

const ALL = 'all'

export function InventoryTypeTabs({
  value,
  counts,
  total,
  onChange,
}: {
  /** The open tab's id; undefined is the whole lens. */
  value: string | undefined
  /** Assets per tab id, once known. */
  counts: Record<string, number> | undefined
  /** Assets of the whole lens, once known. */
  total: number | undefined
  onChange: (tab: string | undefined) => void
}) {
  const { t } = useTranslation()
  const options = useMemo(
    () => [
      { value: ALL, label: t('assets.tabs.type.all', 'All'), count: total },
      ...INVENTORY_TABS.map((tab) => ({
        value: tab.id,
        label: t(tab.labelKey, tab.label),
        count: counts?.[tab.id],
      })),
    ],
    [t, counts, total]
  )
  return (
    <div className="max-w-full overflow-x-auto" data-testid="inventory-type-tabs">
      <SegmentedLens // anatomy-ok: a tab is a locked type with its own columns (IP addresses: network, names, open ports), not a removable filter token
        label={t('assets.tabs.type.aria', 'Asset type')}
        value={value ?? ALL}
        options={options}
        countNoun={t('assets.tabs.type.noun', 'assets')}
        onChange={(v) => onChange(v === ALL ? undefined : v)}
      />
    </div>
  )
}
