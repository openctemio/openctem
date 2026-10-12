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
import { useTranslation } from '@/context/i18n-provider'

export default function AttackSurfaceReviewPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageHeader
        title={t('scope.review.title', 'Attack surface')}
        description={t(
          'scope.review.description',
          'Names discovery found that may be yours. Confirming records ownership; only a scope entry lets scans reach a name.'
        )}
      />
      <AttackSurfaceSectionTabs />
      <div className="mt-5">
        <EASMReviewQueue />
      </div>
    </Main>
  )
}
