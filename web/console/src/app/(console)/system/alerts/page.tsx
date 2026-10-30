'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader, PageStack } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useAlertWebhook } from '@console/features/admin-console/api/use-platform-settings'
import { AlertWebhookForm } from '@console/features/admin-console/components/alert-webhook-form'
import { adminHas } from '@console/features/admin-console/types'

/** Settings -> Alerts: the alert webhook (RFC-079). */
export default function AlertsSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useAlertWebhook()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.nav.alerts', 'Alerts')}
          description={t(
            'admin.alerts.pageDescription',
            'Where administrator alerts go besides e-mail.'
          )}
        />
        {error ? (
          <ErrorState
            title={t('admin.alerts.errorTitle', 'the alert webhook')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-72 w-full" />
        ) : (
          <AlertWebhookForm
            settings={data}
            canEdit={adminHas(me, 'platform.settings.general.write')}
            onSaved={() => void mutate()}
          />
        )}
      </PageStack>
    </Main>
  )
}
