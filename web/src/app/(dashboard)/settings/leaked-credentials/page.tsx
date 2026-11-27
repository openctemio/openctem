'use client'

import { useTranslation } from '@/context/i18n-provider'
import { NoAccessState, SettingsPage } from '@/features/shared'
import { CredentialStorageSettingsForm, useCredentialSettings } from '@/features/credentials'
import { usePermissions, Permission } from '@/lib/permissions'

/**
 * Settings > Leaked credentials: whether the organization keeps imported
 * leaked secret values (owners and administrators).
 */
export default function LeakedCredentialSettingsPage() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canManage = can(Permission.TeamUpdate)
  const { data, error, isLoading, mutate } = useCredentialSettings({ isPaused: () => !canManage })

  return (
    <SettingsPage
      title={t('credentials.settings.title', 'Leaked credentials')}
      description={t(
        'credentials.settings.description',
        'What is kept when a leaked credential is imported.'
      )}
      state={!canManage ? 'ready' : error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
    >
      {!canManage ? (
        <NoAccessState
          title={t('credentials.settings.loadError', 'the leaked credential settings')}
          permission={Permission.TeamUpdate}
        />
      ) : (
        data && (
          <CredentialStorageSettingsForm settings={data} onSaved={(s) => void mutate(s, false)} />
        )
      )}
    </SettingsPage>
  )
}
