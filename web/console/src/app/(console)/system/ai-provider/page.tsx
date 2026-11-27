'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SettingsPage } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { usePlatformAI } from '@console/features/admin-console/api/use-platform-settings'
import { PlatformAIForm } from '@console/features/admin-console/components/platform-ai-form'
import { adminHas } from '@console/features/admin-console/types'

/** Settings -> AI provider: the platform AI provider and key (RFC-079). */
export default function AIProviderSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = usePlatformAI()
  const canEdit = adminHas(me, 'platform.settings.ai.write')
  return (
    <SettingsPage
      title={t('admin.nav.aiProvider', 'AI provider')}
      description={t(
        'admin.ai.pageDescription',
        'The AI provider organizations use when they do not bring their own key.'
      )}
      state={error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
      readOnly={
        !canEdit &&
        t('admin.settings.superAdminOnly', 'Only a super admin can change this setting.')
      }
    >
      {data && <PlatformAIForm settings={data} canEdit={canEdit} onSaved={() => void mutate()} />}
    </SettingsPage>
  )
}
