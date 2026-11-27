'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SettingsPage } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useLeakedSecretStorage } from '@console/features/admin-console/api/use-platform-settings'
import { LeakedSecretStorageForm } from '@console/features/admin-console/components/leaked-secret-storage-form'
import { adminHas } from '@console/features/admin-console/types'

/**
 * System -> Leaked credentials: the default of whether imported leaked secret
 * values are kept. Any administrator sees it; a super admin changes it.
 */
export default function LeakedCredentialsSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useLeakedSecretStorage()
  const canEdit = adminHas(me, 'platform.settings.general.write')
  return (
    <SettingsPage
      title={t('admin.leakedSecrets.pageTitle', 'Leaked credentials')}
      description={t(
        'admin.leakedSecrets.pageDescription',
        'What organizations keep when they import leaked credentials.'
      )}
      state={error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
      readOnly={
        !canEdit &&
        t('admin.settings.superAdminOnly', 'Only a super admin can change this setting.')
      }
    >
      {data && (
        <LeakedSecretStorageForm settings={data} canEdit={canEdit} onSaved={() => void mutate()} />
      )}
    </SettingsPage>
  )
}
