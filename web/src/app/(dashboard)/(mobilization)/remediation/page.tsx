'use client'

import { useTranslation } from '@/context/i18n-provider'
import { FixPlan } from '@/features/remediation-hub/components/fix-plan'
import { HubPage } from '@/features/remediation-hub/components/hub-page'

export default function RemediationFixPlanPage() {
  const { t } = useTranslation()
  return (
    <HubPage description={t('remediationHub.plan.description')}>
      <FixPlan />
    </HubPage>
  )
}
