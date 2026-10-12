'use client'

import { useMemo } from 'react'
import { GatedSectionTabs } from '@/features/shared'
import { ATTACK_SURFACE_SECTION_TABS } from '@/config/section-tabs'
import { useTranslation } from '@/context/i18n-provider'
import { useVisibleSectionTabs } from '@/lib/permissions'
import { useEASMReviewCount } from '../hooks/use-easm-review'

const REVIEW_HREF = '/attack-surface/review'

/**
 * Overview | Review | Changes, the route tabs of Discovery > Attack surface.
 * Review shows how many names wait for an ownership decision (the queue's
 * own count), fetched only when that tab is visible.
 */
export function AttackSurfaceSectionTabs() {
  const { t } = useTranslation()
  const visible = useVisibleSectionTabs(ATTACK_SURFACE_SECTION_TABS)
  const showsReview = visible.some((tab) => tab.href === REVIEW_HREF)
  const waiting = useEASMReviewCount(showsReview)
  const tabs = useMemo(
    () =>
      ATTACK_SURFACE_SECTION_TABS.map((tab) => {
        switch (tab.href) {
          case '/attack-surface':
            return { ...tab, label: t('attackSurface.tab.overview', tab.label) }
          case REVIEW_HREF:
            return { ...tab, label: t('attackSurface.tab.review', tab.label) }
          case '/attack-surface/changes':
            return { ...tab, label: t('attackSurface.tab.changes', tab.label) }
          default:
            return tab
        }
      }),
    [t]
  )
  return (
    <GatedSectionTabs
      tabs={tabs}
      label={t('attackSurface.tab.label', 'Attack surface sections')}
      className="mt-4 mb-0"
      counts={{ [REVIEW_HREF]: waiting }}
    />
  )
}
