'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useCaptchaSettings } from '@console/features/admin-console/api/use-platform-settings'
import { CaptchaSettingsForm } from '@console/features/admin-console/components/captcha-settings-form'
import { adminCan } from '@console/features/admin-console/types'

/** Settings -> CAPTCHA: the Turnstile keys (RFC-079). */
export default function CaptchaSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useCaptchaSettings()
  return (
    <Main>
      <PageHeader
        title={t('admin.nav.captcha', 'CAPTCHA')}
        description={t(
          'admin.captcha.pageDescription',
          'The check that stops automated sign-ups and password guessing.'
        )}
      />
      <div className="mt-5">
        {error ? (
          <ErrorState
            title={t('admin.captcha.errorTitle', 'the CAPTCHA keys')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-72 w-full" />
        ) : (
          <CaptchaSettingsForm
            settings={data}
            canEdit={adminCan(me.role, 'super_admin')}
            onSaved={() => void mutate()}
          />
        )}
      </div>
    </Main>
  )
}
