'use client'

import { useMemo } from 'react'
import { ATTACK_SURFACE_SECTION_TABS } from '@/config/section-tabs'
import { useTranslation } from '@/context/i18n-provider'
import { useVisibleSectionTabs } from '@/lib/permissions'
import { useEASMSuggestionCount } from '../hooks/use-easm-suggestions'
import { AttackSurfaceNav } from './attack-surface-nav'

const REVIEW_HREF = '/attack-surface/review'
const LOOKALIKES_HREF = '/attack-surface/lookalikes'

/**
 * Overview | Posture | Review | Lookalikes | Changes | Web surface | Technologies |
 * Exposure items | Certificates, the route tabs of
 * Discovery > Attack surface. Review shows how many decisions wait (one per card, not
 * per row), fetched only when that tab is visible.
 */
export function AttackSurfaceSectionTabs() {
  const { t } = useTranslation()
  const visible = useVisibleSectionTabs(ATTACK_SURFACE_SECTION_TABS)
  const showsReview = visible.some((tab) => tab.href === REVIEW_HREF)
  const waiting = useEASMSuggestionCount(showsReview)
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
          case LOOKALIKES_HREF:
            return { ...tab, label: t('lookalikes.tab', tab.label) }
          case '/attack-surface/posture':
            return { ...tab, label: t('attackSurface.tab.posture', tab.label) }
          case '/attack-surface/technologies':
            return { ...tab, label: t('attackSurface.tab.technologies', tab.label) }
          case '/attack-surface/exposures':
            return { ...tab, label: t('attackSurface.tab.exposureItems', tab.label) }
          case '/attack-surface/certificates':
            return { ...tab, label: t('attackSurface.tab.certificates', tab.label) }
          case '/attack-surface/web':
            return { ...tab, label: t('attackSurface.tab.webSurface', tab.label) }
          default:
            return tab
        }
      }),
    [t]
  )
  return (
    <AttackSurfaceNav
      tabs={tabs}
      label={t('attackSurface.tab.label', 'Attack surface sections')}
      counts={{ [REVIEW_HREF]: waiting }}
    />
  )
}
