'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SettingsPage } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useLegalSettings } from '@console/features/admin-console/api/use-legal-settings'
import { LegalSettingsForm } from '@console/features/admin-console/components/legal-settings-form'
import { adminHas } from '@console/features/admin-console/types'

/**
 * System -> Legal: the operator's legal information (RFC-079). Any administrator
 * sees it; super admins change it.
 */
export default function LegalSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useLegalSettings()
  const canEdit = adminHas(me, 'platform.settings.legal.write')

  return (
    <SettingsPage
      title={t('admin.legal.pageTitle', 'Legal')}
      description={t('admin.legal.pageDescription', 'What visitors see before they sign in.')}
      state={error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
      readOnly={
        !canEdit && t('admin.legal.superAdminOnly', 'Only a super admin can change these settings.')
      }
    >
      {data && (
        <LegalSettingsForm settings={data} canEdit={canEdit} onSaved={() => void mutate()} />
      )}
    </SettingsPage>
  )
}
