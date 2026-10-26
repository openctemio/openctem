'use client'

import { useMemo } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { GatedSectionTabs } from '@/features/shared'
import { ASSETS_SECTION_TABS } from '@/config/section-tabs'

/** The tab label's i18n key, by route (the config holds the English fallback). */
const TAB_LABEL_KEYS: Record<string, string> = {
  '/assets': 'assets.tabs.inventory',
  '/assets/attention': 'assets.tabs.attention',
  '/assets/groups': 'assets.tabs.groups',
  '/assets/changes': 'assets.tabs.changes',
}

/**
 * Inventory · Needs attention · Groups · Activity, the route
 * tabs of Discovery > Assets (research/242 D1). Placed directly under the
 * page's `PageHeader` (see docs/ui-style-contract.md); the next block carries
 * `mt-5`.
 */
export function AssetsSectionTabs() {
  const { t } = useTranslation()
  const tabs = useMemo(
    () =>
      ASSETS_SECTION_TABS.map((tab) => {
        const key = TAB_LABEL_KEYS[tab.href]
        return key ? { ...tab, label: t(key, tab.label) } : tab
      }),
    [t]
  )
  return <GatedSectionTabs tabs={tabs} label={t('assets.tabs.aria', 'Assets sections')} />
}
