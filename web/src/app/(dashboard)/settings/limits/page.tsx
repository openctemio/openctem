'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { OrganizationLimitsUsage } from '@/features/limits/components/organization-limits-usage'
import { PageHeader } from '@/features/shared'

/**
 * Settings > Organization > Usage & limits (owners and admins). Listed in the
 * settings rail only while a limit applies to the organization.
 */
export default function UsageAndLimitsPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageHeader
        title={t('settings.item.limits', 'Usage & limits')}
        description={t(
          'settings.desc.limits',
          'The limits that apply to this organization and what it uses.'
        )}
      />
      <div className="mt-5">
        <OrganizationLimitsUsage />
      </div>
    </Main>
  )
}
