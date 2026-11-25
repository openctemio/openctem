'use client'

/**
 * The type of the External surface lens: All, then Domains, Subdomains, IP
 * addresses, Services, Web endpoints and Certificates, each with its count. A
 * type is a locked condition of the list (`?tab=<type>`, its own columns),
 * one at a time. It is a filter token at the start of the list toolbar, not a
 * second row of tabs under the Assets tabs (owner rule 2026-11-24: one tab
 * level per screen).
 */

import { useMemo } from 'react'
import { FilterSelect } from '@/features/shared/components/filter-select'
import { useTranslation } from '@/context/i18n-provider'
import { INVENTORY_TABS } from '../../lib/inventory-tabs'

export function InventoryTypeSelect({
  value,
  counts,
  total,
  onChange,
}: {
  /** The chosen type's id; undefined is the whole lens. */
  value: string | undefined
  /** Assets per type id, once known. */
  counts: Record<string, number> | undefined
  /** Assets of the whole lens, once known. */
  total: number | undefined
  onChange: (tab: string | undefined) => void
}) {
  const { t } = useTranslation()
  const options = useMemo(
    () =>
      INVENTORY_TABS.map((tab) => ({
        value: tab.id,
        label: t(tab.labelKey, tab.label),
        count: counts?.[tab.id],
      })),
    [t, counts]
  )
  return (
    <FilterSelect<string>
      label={t('assets.tabs.type.label', 'Type')}
      value={value ?? ''}
      options={options}
      allCount={total}
      allLabel={t('assets.tabs.type.all', 'All')}
      foldLabel
      onChange={(v) => onChange(v || undefined)}
    />
  )
}
