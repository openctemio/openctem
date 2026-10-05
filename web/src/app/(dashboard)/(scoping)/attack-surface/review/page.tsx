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
        description="Names found in Certificate Transparency and discovery that may be yours. Scans skip them until you confirm them."
      />
      <AttackSurfaceSectionTabs />
      <div className="mt-5">
        <EASMReviewQueue />
      </div>
    </Main>
  )
}
