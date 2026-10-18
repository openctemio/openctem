'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { SecurityOverview } from '@/features/security-overview/components/security-overview'
import { PageHeader } from '@/features/shared'

/**
 * Settings › Security overview: a score and the checks behind it. Owners and
 * admins only (the route guard and the API gate agree); the API computes it.
 */
export default function SecurityOverviewPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageHeader
        title={t('securityOverview.title', 'Security overview')}
        description={t(
          'securityOverview.description',
          'How well this organization is protected, and what to fix first.'
        )}
      />
      <div className="mt-5">
        <SecurityOverview />
      </div>
    </Main>
  )
}
