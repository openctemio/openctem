'use client'

import { GatedSectionTabs } from '@/features/shared'
import { ATTACK_SURFACE_SECTION_TABS } from '@/config/section-tabs'
import { useVisibleSectionTabs } from '@/lib/permissions'
import { useEASMReviewCount } from '../hooks/use-easm-review'

const REVIEW_HREF = '/attack-surface/review'

/**
 * Overview | Review, the route tabs of Discovery > Attack surface. Review
 * shows how many names wait for an ownership decision (the queue's own
 * count), fetched only when that tab is visible.
 */
export function AttackSurfaceSectionTabs() {
  const visible = useVisibleSectionTabs(ATTACK_SURFACE_SECTION_TABS)
  const showsReview = visible.some((t) => t.href === REVIEW_HREF)
  const waiting = useEASMReviewCount(showsReview)
  return (
    <GatedSectionTabs
      tabs={ATTACK_SURFACE_SECTION_TABS}
      label="Attack surface sections"
      className="mt-4 mb-0"
      counts={{ [REVIEW_HREF]: waiting }}
    />
  )
}
