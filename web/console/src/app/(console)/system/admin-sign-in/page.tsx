'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SettingsPage } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useAdminUsers } from '@console/features/admin-console/api/use-admin-users'
import { usePlatformIdP } from '@console/features/admin-console/api/use-platform-idp'
import { PlatformIdPForm } from '@console/features/admin-console/components/platform-idp-form'
import { ConsoleMfaPolicyCard } from '@console/features/admin-console/components/console-mfa-policy-card'
import { adminHas } from '@console/features/admin-console/types'
import { RoleRequiredNotice } from '@console/features/admin-console/components/role-required-notice'

/**
 * System -> Admin sign-in: the administrators' identity provider and the
 * "require IdP" policy (RFC-022 revision 4), and "require security keys"
 * (RFC-078). Super admins only.
 */
export default function AdminSignInPage() {
  const me = useAdmin()
  const { t } = useTranslation()
  const isSuper = adminHas(me, 'platform.identity.manage')
  const { data, error, isLoading, mutate } = usePlatformIdP(isSuper)
  const { data: admins } = useAdminUsers(1, isSuper)
  const title = t('admin.nav.adminSignIn', 'Admin sign-in')

  if (!isSuper) {
    return (
      <SettingsPage title={title}>
        <RoleRequiredNotice needed="super_admin" variant="page" />
      </SettingsPage>
    )
  }

  const hasBreakGlass = (admins?.data ?? []).some(
    (a) => a.is_break_glass && a.is_active && a.role === 'super_admin'
  )

  return (
    <SettingsPage
      title={title}
      description={t(
        'admin.systemAdminSignInPage.howAdministratorsSignInTo',
        'How administrators sign in to this console. Separate from organization sign-in.'
      )}
      state={error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
    >
      <ConsoleMfaPolicyCard />
      {data && (
        <PlatformIdPForm idp={data} hasBreakGlass={hasBreakGlass} onSaved={() => void mutate()} />
      )}
    </SettingsPage>
  )
}
