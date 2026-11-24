'use client'

import { useMemo } from 'react'
import { ATTACK_SURFACE_TAB_ORDER } from '@/config/attack-surface-views'
import { ATTACK_SURFACE_SECTION_TABS } from '@/config/section-tabs'
import { useTranslation } from '@/context/i18n-provider'
import { useVisibleSectionTabs } from '@/lib/permissions'
import { SectionTabs, type SectionTab } from '@/features/shared'
import { useEASMSuggestionCount } from '../hooks/use-easm-suggestions'

const REVIEW_HREF = '/attack-surface/review'

const LABELS: Record<string, [key: string, fallback: string]> = {
  '/attack-surface': ['attackSurface.tab.overview', 'Overview'],
  '/attack-surface/technologies': ['attackSurface.tab.technologies', 'Technologies'],
  '/attack-surface/certificates': ['attackSurface.tab.certificates', 'Certificates'],
  '/attack-surface/web': ['attackSurface.tab.webSurface', 'Web surface'],
  '/attack-surface/exposures': ['attackSurface.tab.exposures', 'Exposures'],
  '/attack-surface/lookalikes': ['lookalikes.tab', 'Lookalikes'],
  '/attack-surface/changes': ['attackSurface.tab.changes', 'Changes'],
  '/attack-surface/pages': ['pageMonitor.tab', 'Page changes'],
  '/attack-surface/discovery': ['attackSurface.tab.discovery', 'Discovery'],
  [REVIEW_HREF]: ['attackSurface.tab.review', 'Review'],
}

/**
 * The one tab row of Discovery > Attack surface (owner rule 2026-11-24: one
 * tab level per screen): the section tabs the user can open, in the order of
 * `ATTACK_SURFACE_TAB_ORDER`. A page opened from another (Posture) is not a
 * tab; the Overview tab stays active on it, as `SectionTabs` marks the most
 * specific match. On a phone the row is one swipe row with an edge fade.
 * Review shows how many decisions wait (one per card, not per row), fetched
 * only when that tab is visible.
 */
export function AttackSurfaceSectionTabs() {
  const { t } = useTranslation()
  const visible = useVisibleSectionTabs(ATTACK_SURFACE_SECTION_TABS)
  const showsReview = visible.some((tab) => tab.href === REVIEW_HREF)
  const waiting = useEASMSuggestionCount(showsReview)
  const tabs = useMemo<SectionTab[]>(() => {
    const byHref = new Map(visible.map((tab) => [tab.href, tab]))
    return ATTACK_SURFACE_TAB_ORDER.flatMap((href) => {
      const tab = byHref.get(href)
      if (!tab) return []
      const [key, fallback] = LABELS[href] ?? [tab.labelKey ?? '', tab.label]
      // The row draws no icons (research/244 anatomy): ten labels already
      // make one row, and an icon each would only push more past the edge.
      return [{ ...tab, icon: undefined, label: key ? t(key, fallback) : tab.label }]
    })
  }, [visible, t])
  if (tabs.length < 2) return null
  return (
    <SectionTabs
      tabs={tabs}
      label={t('attackSurface.tab.label', 'Attack surface sections')}
      counts={{ [REVIEW_HREF]: waiting }}
    />
  )
}
