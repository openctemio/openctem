'use client'

import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, SettingsPage } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useEmailSettings } from '@console/features/admin-console/api/use-email-settings'
import { useEmailRelay } from '@console/features/admin-console/api/use-platform-settings'
import { EmailRelayForm } from '@console/features/admin-console/components/email-relay-form'
import { EmailSettingsForm } from '@console/features/admin-console/components/email-settings-form'
import { adminHas } from '@console/features/admin-console/types'

/**
 * System -> E-mail: the platform's SMTP server (RFC-079) and whether an
 * organization's own server may send its organization mail. Any
 * administrator sees them; super admins change them and send the test e-mail.
 */
export default function EmailSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useEmailSettings()
  const relay = useEmailRelay()
  const canEdit = adminHas(me, 'platform.settings.email.write')

  return (
    <SettingsPage
      title={t('admin.email.pageTitle', 'E-mail')}
      description={t('admin.email.pageDescription', 'How this deployment sends e-mail.')}
      state={error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
      readOnly={
        !canEdit && t('admin.email.superAdminOnly', 'Only a super admin can change these settings.')
      }
    >
      {data && (
        <EmailSettingsForm settings={data} canEdit={canEdit} onSaved={() => void mutate()} />
      )}
      {relay.error ? (
        <ErrorState
          title={t('admin.emailRelay.errorSubject', 'the organization mail setting')}
          error={relay.error}
          onRetry={() => void relay.mutate()}
        />
      ) : relay.isLoading || !relay.data ? (
        <Skeleton className="h-64 w-full" />
      ) : (
        <EmailRelayForm
          settings={relay.data}
          canEdit={canEdit}
          onSaved={() => void relay.mutate()}
        />
      )}
    </SettingsPage>
  )
}
