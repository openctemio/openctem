'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader, PageStack } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useSocialLoginSettings } from '@console/features/admin-console/api/use-platform-settings'
import { SocialLoginSettingsForm } from '@console/features/admin-console/components/social-login-settings-form'
import { adminCan } from '@console/features/admin-console/types'

/** Settings -> Social login: Google, GitHub and Microsoft sign-in. */
export default function SocialLoginSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useSocialLoginSettings()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.nav.socialLogin', 'Social login')}
          description={t(
            'admin.socialLogin.pageDescription',
            'Let people sign in to organizations with Google, GitHub or Microsoft.'
          )}
        />
        {error ? (
          <ErrorState
            title={t('admin.socialLogin.errorTitle', 'the social login settings')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full" />
        ) : (
          <SocialLoginSettingsForm
            settings={data}
            canEdit={adminCan(me.role, 'super_admin')}
            onSaved={() => void mutate()}
          />
        )}
      </PageStack>
    </Main>
  )
}
