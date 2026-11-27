'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SettingsPage } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useCaptchaSettings } from '@console/features/admin-console/api/use-platform-settings'
import { CaptchaSettingsForm } from '@console/features/admin-console/components/captcha-settings-form'
import { adminHas } from '@console/features/admin-console/types'

/** Settings -> CAPTCHA: the Turnstile keys (RFC-079). */
export default function CaptchaSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useCaptchaSettings()
  const canEdit = adminHas(me, 'platform.settings.general.write')
  return (
    <SettingsPage
      title={t('admin.nav.captcha', 'CAPTCHA')}
      description={t(
        'admin.captcha.pageDescription',
        'The check that stops automated sign-ups and password guessing.'
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
        <CaptchaSettingsForm settings={data} canEdit={canEdit} onSaved={() => void mutate()} />
      )}
    </SettingsPage>
  )
}
