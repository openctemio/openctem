'use client'

import { useMemo } from 'react'
import { usePathname } from 'next/navigation'
import { useTranslation } from '@/context/i18n-provider'
import { GatedSectionTabs } from '@/features/shared'
import { ASSETS_SECTION_TABS } from '@/config/section-tabs'
import { useVisibleSectionTabs } from '@/lib/permissions'
import { useAttentionCount } from './attention/use-attention-count'

/** The tab label's i18n key, by route (the config holds the English fallback). */
const TAB_LABEL_KEYS: Record<string, string> = {
  '/assets': 'assets.tabs.inventory',
  '/assets/attention': 'assets.tabs.attention',
  '/assets/groups': 'assets.tabs.groups',
  '/assets/changes': 'assets.tabs.changes',
}

const ATTENTION_HREF = '/assets/attention'
/**
 * The pages that send the count's request anyway: the inventory (its tab
 * strip is where the figure is read first) and the Needs attention landing
 * (its Decide monitoring row). Other Assets pages show it from the cache only.
 */
const FETCHES_COUNT: readonly string[] = ['/assets', ATTENTION_HREF]

/**
 * Inventory · Needs attention · Groups · Activity, the route
 * tabs of Discovery > Assets (research/242 D1). Placed directly under the
 * page's `PageHeader` (see docs/ui-style-contract.md); the next block carries
 * `mt-5`.
 *
 * Needs attention shows how many assets wait for a scoping decision (the
 * "Decide monitoring" queue, which holds the root domains to validate too),
 * asked only when that tab is visible. It is the same one-row request the
 * landing's Decide monitoring row sends, so the figure is the reader's own
 * scope and the request is shared, not repeated; pages that do not send it
 * for themselves add no request (cache only). Zero shows nothing.
 */
export function AssetsSectionTabs() {
  const { t } = useTranslation()
  const visible = useVisibleSectionTabs(ASSETS_SECTION_TABS)
  const showsAttention = visible.some((tab) => tab.href === ATTENTION_HREF)
  const cacheOnly = !FETCHES_COUNT.includes(usePathname() ?? '')
  const waiting = useAttentionCount('decide_monitoring', showsAttention, { cacheOnly })
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
      counts={{ [ATTENTION_HREF]: waiting }}
      countLabels={{
        [ATTENTION_HREF]: t(
          'assets.tabs.attentionWaiting',
          'Needs attention, {count, plural, one {# asset} other {# assets}} waiting',
          { count: waiting ?? 0 }
        ),
      }}
    />
  )
}
