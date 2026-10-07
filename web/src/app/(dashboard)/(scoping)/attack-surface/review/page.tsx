'use client'

/**
 * Attack surface › Review: confirm or reject the names discovery found but
 * could not prove are the organisation's (RFC-036 §6.4, §6.11). Reached from
 * the sidebar row's Review tab (research/22 P0-12); `?tab=rejected` opens the
 * "Not ours" list.
 */

import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared'
import { AttackSurfaceSectionTabs, EASMReviewQueue } from '@/features/attack-surface'

export default function AttackSurfaceReviewPage() {
  return (
    <Main>
      <PageHeader
        title="Attack surface"
        description="Names discovery found that may be yours. Names under your scope join automatically; these need a decision. Confirming records ownership; a scope entry is still what lets scans reach a name."
      />
      <AttackSurfaceSectionTabs />
      <div className="mt-5">
        <EASMReviewQueue />
      </div>
    </Main>
  )
}
