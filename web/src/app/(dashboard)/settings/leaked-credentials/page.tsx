'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, NoAccessState, PageHeader, PageStack } from '@/features/shared'
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
    <Main>
      <PageStack>
        <PageHeader
          title={t('credentials.settings.title', 'Leaked credentials')}
          description={t(
            'credentials.settings.description',
            'What is kept when a leaked credential is imported.'
          )}
        />
        {!canManage ? (
          <NoAccessState
            title={t('credentials.settings.loadError', 'the leaked credential settings')}
            permission={Permission.TeamUpdate}
          />
        ) : error ? (
          <ErrorState
            title={t('credentials.settings.loadError', 'the leaked credential settings')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-64 w-full rounded-xl" />
        ) : (
          <CredentialStorageSettingsForm settings={data} onSaved={(s) => void mutate(s, false)} />
        )}
      </PageStack>
    </Main>
  )
}
