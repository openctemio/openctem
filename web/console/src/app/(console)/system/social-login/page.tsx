'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SettingsPage } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useSocialLoginSettings } from '@console/features/admin-console/api/use-platform-settings'
import { SocialLoginSettingsForm } from '@console/features/admin-console/components/social-login-settings-form'
import { adminCan } from '@console/features/admin-console/types'

/** Settings -> Social login: Google, GitHub and Microsoft sign-in. */
export default function SocialLoginSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useSocialLoginSettings()
  const canEdit = adminCan(me.role, 'super_admin')
  return (
    <SettingsPage
      title={t('admin.nav.socialLogin', 'Social login')}
      description={t(
        'admin.socialLogin.pageDescription',
        'Let people sign in to organizations with Google, GitHub or Microsoft.'
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
        <SocialLoginSettingsForm settings={data} canEdit={canEdit} onSaved={() => void mutate()} />
      )}
    </SettingsPage>
  )
}
