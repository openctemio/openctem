'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { OrganizationPlanUsage } from '@/features/plans/components/organization-plan-usage'
import { PageHeader } from '@/features/shared'

/** Settings > Organization > Plan & usage (owners and admins). */
export default function PlanUsagePage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageHeader
        title={t('settings.item.plan', 'Plan & usage')}
        description={t(
          'settings.desc.plan',
          'Your plan, its limits and what this organization uses.'
        )}
      />
      <div className="mt-5">
        <OrganizationPlanUsage />
      </div>
    </Main>
  )
}
