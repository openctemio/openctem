'use client'

import { useMemo } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { GatedSectionTabs } from '@/features/shared'
import { ASSETS_SECTION_TABS } from '@/config/section-tabs'
import { useVisibleSectionTabs } from '@/lib/permissions'
import { useSuggestionCount } from '@/features/relationships/api/use-relationship-suggestions'

const SUGGESTIONS_HREF = '/assets/suggestions'

/** The tab label's i18n key, by route (the config holds the English fallback). */
const TAB_LABEL_KEYS: Record<string, string> = {
  '/assets': 'assets.tabs.inventory',
  '/assets/groups': 'assets.tabs.groups',
  '/assets/changes': 'assets.tabs.changes',
  '/assets/web': 'assets.tabs.webSurface',
  [SUGGESTIONS_HREF]: 'assets.tabs.suggestions',
}

/**
 * Inventory · Groups · Activity · Web surface · Suggestions, the route tabs of Discovery
 * > Assets. Placed directly under the page's `PageHeader` (see
 * docs/ui-style-contract.md); the next block carries `mt-5`. Suggestions shows
 * how many relationship suggestions wait for review, fetched only when that
 * tab is visible (its module is `relationships`).
 */
export function AssetsSectionTabs() {
  const { t } = useTranslation()
  const visible = useVisibleSectionTabs(ASSETS_SECTION_TABS)
  const tabs = useMemo(
    () =>
      ASSETS_SECTION_TABS.map((tab) => {
        const key = TAB_LABEL_KEYS[tab.href]
        return key ? { ...tab, label: t(key, tab.label) } : tab
      }),
    [t]
  )
  const showsSuggestions = visible.some((t) => t.href === SUGGESTIONS_HREF)
  const { data } = useSuggestionCount(showsSuggestions)
  return (
    <GatedSectionTabs
      tabs={tabs}
      label={t('assets.tabs.aria', 'Assets sections')}
      className="mt-4 mb-0"
      counts={{ [SUGGESTIONS_HREF]: data?.count }}
    />
  )
}
