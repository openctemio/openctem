'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState, PageHeader } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { SignupEventsPanel } from '@console/features/admin-console/components/signup-events-panel'
import { SignupAlertsForm } from '@console/features/admin-console/components/signup-alerts-form'
import {
  saveSignupAlerts,
  useSignupAlerts,
} from '@console/features/admin-console/api/use-signup-events'
import { adminCan } from '@console/features/admin-console/types'

/**
 * Requests -> Sign-ups: accounts, organizations and access requests as they
 * arrive (email domain and network prefix only), and the burst alert
 * thresholds. Any administrator reads; super admins change the thresholds.
 */
export default function SignupsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const alerts = useSignupAlerts()

  return (
    <Main>
      <PageHeader title={t('admin.signups.pageTitle')} description={t('admin.signups.pageDesc')} />
      <div className="mt-5 space-y-8">
        <SignupEventsPanel />
        {alerts.error ? (
          <ErrorState
            title={t('admin.signupAlerts.errorTitle')}
            error={alerts.error}
            onRetry={() => void alerts.mutate()}
          />
        ) : alerts.isLoading || !alerts.data ? (
          <Skeleton className="h-64 w-full" />
        ) : (
          <SignupAlertsForm
            thresholds={alerts.data}
            canEdit={adminCan(me.role, 'super_admin')}
            onSave={async (next, reason, code) => {
              const saved = await saveSignupAlerts({
                ...next,
                version: alerts.data?.version ?? 0,
                reason,
                totp_code: code,
              })
              await alerts.mutate(saved, { revalidate: false })
            }}
          />
        )}
      </div>
    </Main>
  )
}
