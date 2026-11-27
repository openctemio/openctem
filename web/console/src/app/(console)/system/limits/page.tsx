'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SettingsPage } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useSelfServiceLimits } from '@console/features/admin-console/api/use-limits'
import { SelfServiceLimitsForm } from '@console/features/admin-console/components/self-service-limits-form'
import { StorageQuotaCard } from '@console/features/admin-console/components/storage-quota-card'
import { adminHas } from '@console/features/admin-console/types'

/**
 * System -> Limits: the limits self-service organizations start with. Any
 * administrator sees them; super admins change them. Limits of one
 * organization are set on that organization's Limits tab.
 */
export default function LimitsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useSelfServiceLimits()

  return (
    <SettingsPage
      title={t('limits.console.page.title', 'Limits')}
      description={t(
        'limits.console.page.description',
        'Limits of organizations on this installation. None apply unless you set them.'
      )}
      state={error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
    >
      {data && (
        <SelfServiceLimitsForm
          defaults={data}
          canEdit={adminHas(me, 'platform.settings.limits.write')}
          onSaved={() => void mutate()}
        />
      )}
      <StorageQuotaCard canEdit={adminHas(me, 'platform.settings.general.write')} />
    </SettingsPage>
  )
}
