'use client'

import { useMemo } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { GatedSectionTabs } from '@/features/shared'
import { ASSETS_SECTION_TABS, ASSET_ATTENTION_TABS } from '@/config/section-tabs'
import { useVisibleSectionTabs } from '@/lib/permissions'
import { useSuggestionCount } from '@/features/relationships/api/use-relationship-suggestions'

const SUGGESTIONS_HREF = '/assets/suggestions'

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
  return (
    <GatedSectionTabs
      tabs={tabs}
      label={t('assets.tabs.aria', 'Assets sections')}
      className="mt-4 mb-0"
    />
  )
}

/**
 * The reasons of Needs attention, as a second row of route tabs on each of
 * its pages. Relationships shows how many suggestions wait for review,
 * fetched only when that tab is visible (its module is `relationships`).
 */
export function AssetAttentionTabs() {
  const { t } = useTranslation()
  const visible = useVisibleSectionTabs(ASSET_ATTENTION_TABS)
  const showsSuggestions = visible.some((tab) => tab.href === SUGGESTIONS_HREF)
  const { data } = useSuggestionCount(showsSuggestions)
  return (
    <GatedSectionTabs
      tabs={ASSET_ATTENTION_TABS}
      label={t('assets.attention.tabsAria', 'Needs attention reasons')}
      className="mt-3 mb-0"
      counts={{ [SUGGESTIONS_HREF]: data?.count }}
    />
  )
}
