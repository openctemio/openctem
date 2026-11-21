'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SettingsPage } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useAlertWebhook } from '@console/features/admin-console/api/use-platform-settings'
import { AlertWebhookForm } from '@console/features/admin-console/components/alert-webhook-form'
import { adminHas } from '@console/features/admin-console/types'

/** Settings -> Alerts: the alert webhook (RFC-079). */
export default function AlertsSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useAlertWebhook()
  const canEdit = adminHas(me, 'platform.settings.general.write')
  return (
    <SettingsPage
      title={t('admin.nav.alerts', 'Alerts')}
      description={t(
        'admin.alerts.pageDescription',
        'Where administrator alerts go besides e-mail.'
      )}
      state={error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
      readOnly={
        !canEdit &&
        t('admin.settings.superAdminOnly', 'Only a super admin can change this setting.')
      }
    >
      {data && <AlertWebhookForm settings={data} canEdit={canEdit} onSaved={() => void mutate()} />}
    </SettingsPage>
  )
}
