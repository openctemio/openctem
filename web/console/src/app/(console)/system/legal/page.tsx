'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader, PageStack } from '@/features/shared'
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

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.legal.pageTitle', 'Legal')}
          description={t('admin.legal.pageDescription', 'What visitors see before they sign in.')}
        />
        {error ? (
          <ErrorState
            title={t('admin.legal.errorSubject', 'the legal settings')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full" />
        ) : (
          <LegalSettingsForm
            settings={data}
            canEdit={adminHas(me, 'platform.settings.legal.write')}
            onSaved={() => void mutate()}
          />
        )}
      </PageStack>
    </Main>
  )
}
