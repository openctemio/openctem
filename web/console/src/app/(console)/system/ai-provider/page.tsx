'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { usePlatformAI } from '@console/features/admin-console/api/use-platform-settings'
import { PlatformAIForm } from '@console/features/admin-console/components/platform-ai-form'
import { adminCan } from '@console/features/admin-console/types'

/** Settings -> AI provider: the platform AI provider and key (RFC-079). */
export default function AIProviderSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = usePlatformAI()
  return (
    <Main>
      <PageHeader
        title={t('admin.nav.aiProvider', 'AI provider')}
        description={t(
          'admin.ai.pageDescription',
          'The AI provider organizations use when they do not bring their own key.'
        )}
      />
      <div className="mt-5">
        {error ? (
          <ErrorState
            title={t('admin.ai.errorTitle', 'the AI provider')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-72 w-full" />
        ) : (
          <PlatformAIForm
            settings={data}
            canEdit={adminCan(me.role, 'super_admin')}
            onSaved={() => void mutate()}
          />
        )}
      </div>
    </Main>
  )
}
