'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useAdminUsers } from '@console/features/admin-console/api/use-admin-users'
import { usePlatformIdP } from '@console/features/admin-console/api/use-platform-idp'
import { PlatformIdPForm } from '@console/features/admin-console/components/platform-idp-form'
import { ConsoleMfaPolicyCard } from '@console/features/admin-console/components/console-mfa-policy-card'
import { adminCan } from '@console/features/admin-console/types'
import { RoleRequiredNotice } from '@console/features/admin-console/components/role-required-notice'

/**
 * System -> Admin sign-in: the administrators' identity provider and the
 * "require IdP" policy (RFC-022 revision 4), and "require security keys"
 * (RFC-078). Super admins only.
 */
export default function AdminSignInPage() {
  const me = useAdmin()
  const { t } = useTranslation()
  const isSuper = adminCan(me.role, 'super_admin')
  const { data, error, isLoading, mutate } = usePlatformIdP(isSuper)
  const { data: admins } = useAdminUsers(1, isSuper)

  if (!isSuper) {
    return (
      <Main>
        <PageHeader title={t('admin.nav.adminSignIn', 'Admin sign-in')} />
        <RoleRequiredNotice needed="super_admin" variant="page" />
      </Main>
    )
  }

  const hasBreakGlass = (admins?.data ?? []).some(
    (a) => a.is_break_glass && a.is_active && a.role === 'super_admin'
  )

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.adminSignIn', 'Admin sign-in')}
        description={t(
          'admin.systemAdminSignInPage.howAdministratorsSignInTo',
          'How administrators sign in to this console. Separate from organization sign-in.'
        )}
      />
      <div className="mt-5 space-y-4">
        <ConsoleMfaPolicyCard />
        {error ? (
          <ErrorState
            title={t('admin.systemAdminSignInPage.adminSignIn', 'admin sign-in')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <div className="space-y-3">
            <Skeleton className="h-48 w-full" />
            <Skeleton className="h-32 w-full" />
          </div>
        ) : (
          <PlatformIdPForm idp={data} hasBreakGlass={hasBreakGlass} onSaved={() => void mutate()} />
        )}
      </div>
    </Main>
  )
}
