'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader, PageStack } from '@/features/shared'
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

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.leakedSecrets.pageTitle', 'Leaked credentials')}
          description={t(
            'admin.leakedSecrets.pageDescription',
            'What organizations keep when they import leaked credentials.'
          )}
        />
        {error ? (
          <ErrorState
            title={t('admin.leakedSecrets.errorSubject', 'the leaked credential setting')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-64 w-full" />
        ) : (
          <LeakedSecretStorageForm
            settings={data}
            canEdit={adminHas(me, 'platform.settings.general.write')}
            onSaved={() => void mutate()}
          />
        )}
      </PageStack>
    </Main>
  )
}
