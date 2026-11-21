'use client'

import Link from '@/components/link'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { KeyValueList } from '@/features/shared'
import { LeaveOrganization } from '@/features/organization/components/leave-organization'
import { formatDateSafe } from '@/lib/format-date'

/**
 * Your membership: the signed-in person in the open organization (their role,
 * since when, until when for external access) and leaving it. Needs no role.
 * The person's own account settings are in the account area.
 */
export default function MembershipPage() {
  const { t } = useTranslation()
  const { currentTenant, tenants } = useTenant()
  const membership = tenants.find((m) => m.id === currentTenant?.id)

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{currentTenant?.name ?? ''}</CardTitle>
          <CardDescription>
            {t(
              'settings.membership.accountHint',
              'Your profile, password and two-factor authentication are in your account settings.'
            )}{' '}
            <Link href="/account" className="text-primary underline-offset-4 hover:underline">
              {t('settings.membership.openAccount', 'Open account settings')}
            </Link>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <KeyValueList
            items={[
              {
                key: 'role',
                label: t('settings.membership.role', 'Your role'),
                value: currentTenant
                  ? t(`org.role.${currentTenant.role}`, currentTenant.role)
                  : '-',
              },
              {
                key: 'joined',
                label: t('settings.membership.joined', 'Member since'),
                value: formatDateSafe(membership?.joined_at, 'PP', '-'),
              },
              ...(membership?.access_expires_at
                ? [
                    {
                      key: 'ends',
                      label: t('settings.membership.accessEnds', 'Access ends'),
                      value: formatDateSafe(membership.access_expires_at, 'PP', '-'),
                    },
                  ]
                : []),
            ]}
          />
        </CardContent>
      </Card>
      <LeaveOrganization />
    </>
  )
}
