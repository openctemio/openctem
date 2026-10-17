'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useEmailSettings } from '@console/features/admin-console/api/use-email-settings'
import { EmailSettingsForm } from '@console/features/admin-console/components/email-settings-form'
import { adminCan } from '@console/features/admin-console/types'

/**
 * System -> E-mail: the platform's SMTP server (RFC-079). Any administrator
 * sees it; super admins change it and send the test e-mail.
 */
export default function EmailSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useEmailSettings()

  return (
    <Main>
      <PageHeader
        title={t('admin.email.pageTitle', 'E-mail')}
        description={t('admin.email.pageDescription', 'How this deployment sends e-mail.')}
      />
      <div className="mt-5">
        {error ? (
          <ErrorState
            title={t('admin.email.errorSubject', 'the e-mail settings')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full" />
        ) : (
          <EmailSettingsForm
            settings={data}
            canEdit={adminCan(me.role, 'super_admin')}
            onSaved={() => void mutate()}
          />
        )}
      </div>
    </Main>
  )
}
