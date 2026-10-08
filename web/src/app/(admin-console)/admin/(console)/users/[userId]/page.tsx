'use client'

import { use } from 'react'
import Link from 'next/link'
import { ChevronLeft } from 'lucide-react'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import {
  DetailField,
  DetailFieldGrid,
  ErrorState,
  PageHeader,
  RelativeTime,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { usePlatformUser } from '@/features/admin-console/api/use-platform-users'
import { useAdminAuditLogs } from '@/features/admin-console/api/use-admin-audit'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { AdminActivityTable } from '@/features/admin-console/components/admin-activity-table'
import { PlatformUserActions } from '@/features/admin-console/components/platform-user-actions'
import { PlatformUserBadges } from '@/features/admin-console/components/platform-user-badges'
import { adminCan } from '@/features/admin-console/types'

export default function AdminUserPage({ params }: { params: Promise<{ userId: string }> }) {
  const { userId } = use(params)
  const admin = useAdmin()
  const { t } = useTranslation()
  const { data: user, error, isLoading, mutate } = usePlatformUser(userId)
  const activity = useAdminAuditLogs({ page: 1, resourceId: userId, perPage: 10 })
  const refresh = () => {
    void mutate()
    void activity.mutate()
  }

  return (
    <Main>
      <Button asChild variant="ghost" size="sm" className="mb-2 -ms-2">
        <Link href="/admin/users">
          <ChevronLeft className="me-1 size-4" />
          {t('admin.nav.users', 'Users')}
        </Link>
      </Button>
      {error ? (
        <ErrorState title="the account" error={error} onRetry={refresh} />
      ) : isLoading || !user ? (
        <div className="space-y-3">
          <Skeleton className="h-10 w-1/3" />
          <Skeleton className="h-48 w-full" />
        </div>
      ) : (
        <div className="space-y-5">
          <PageHeader title={user.name || user.email} description={user.email}>
            <PlatformUserBadges user={user} />
          </PageHeader>

          {adminCan(admin.role, 'ops_admin') && (
            <PlatformUserActions user={user} onDone={refresh} />
          )}

          <Card>
            <CardContent className="pt-6">
              <DetailFieldGrid>
                <DetailField label={t('admin.users.field.signIn', 'Signs in with')}>
                  <span className="capitalize">{user.auth_provider}</span>
                </DetailField>
                <DetailField label={t('admin.users.field.mfa', 'Two-step verification')}>
                  {user.mfa_enabled
                    ? t('admin.users.field.mfaOn', 'On')
                    : t('admin.users.field.mfaOff', 'Off')}
                </DetailField>
                <DetailField label={t('admin.users.field.lastSignIn', 'Last sign-in')}>
                  {user.last_login_at ? (
                    <RelativeTime date={user.last_login_at} />
                  ) : (
                    t('admin.users.never', 'Never')
                  )}
                </DetailField>
                <DetailField label={t('admin.users.field.failed', 'Failed sign-ins')}>
                  <span className="tabular-nums">{user.failed_logins}</span>
                  {user.locked && user.locked_until && (
                    <span className="text-muted-foreground">
                      {' '}
                      ({t('admin.users.field.lockedUntil', 'locked until')}{' '}
                      {new Date(user.locked_until).toLocaleTimeString()})
                    </span>
                  )}
                </DetailField>
                <DetailField label={t('admin.users.field.created', 'Created')}>
                  <RelativeTime date={user.created_at} />
                </DetailField>
                <DetailField label={t('admin.users.field.id', 'User ID')}>
                  <code className="text-xs break-all select-all">{user.id}</code>
                </DetailField>
              </DetailFieldGrid>
            </CardContent>
          </Card>

          <div className="grid gap-5 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('admin.users.orgs', 'Organizations')}
                  <span className="ms-2 text-sm font-normal text-muted-foreground tabular-nums">
                    {user.membership_list.length}
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {user.membership_list.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    {t('admin.users.noOrgs', 'Not a member of any organization.')}
                  </p>
                ) : (
                  <ul className="divide-y">
                    {user.membership_list.map((m) => (
                      <li
                        key={m.tenant_id}
                        className="flex items-center justify-between gap-3 py-2"
                      >
                        <Link
                          href={`/admin/organizations/${encodeURIComponent(m.tenant_id)}?tab=users`}
                          className="min-w-0 truncate text-sm font-medium hover:underline"
                        >
                          {m.tenant_name}
                        </Link>
                        <div className="flex shrink-0 items-center gap-2">
                          <Badge variant="secondary" className="capitalize">
                            {m.role}
                          </Badge>
                          {m.status !== 'active' && (
                            <Badge variant="outline" className="capitalize">
                              {m.status}
                            </Badge>
                          )}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('admin.users.identities', 'Linked identities')}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {user.identities.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    {t('admin.users.noIdentities', 'No identity provider is linked.')}
                  </p>
                ) : (
                  <ul className="divide-y">
                    {user.identities.map((i) => (
                      <li key={`${i.issuer}|${i.subject}`} className="space-y-0.5 py-2 text-sm">
                        <div className="truncate font-medium">{i.issuer}</div>
                        <div className="truncate font-mono text-xs text-muted-foreground">
                          {i.subject}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {t('admin.users.sessions', 'Active sessions')}
                <span className="ms-2 text-sm font-normal text-muted-foreground tabular-nums">
                  {user.sessions.length}
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {user.sessions.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t('admin.users.noSessions', 'No active session.')}
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="text-start text-muted-foreground">
                      <tr>
                        <th className="py-2 pe-3 text-start font-medium">
                          {t('admin.users.session.ip', 'IP address')}
                        </th>
                        <th className="py-2 pe-3 text-start font-medium">
                          {t('admin.users.session.method', 'Method')}
                        </th>
                        <th className="py-2 pe-3 text-start font-medium">
                          {t('admin.users.session.started', 'Started')}
                        </th>
                        <th className="py-2 text-start font-medium">
                          {t('admin.users.session.lastSeen', 'Last seen')}
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y">
                      {user.sessions.map((s) => (
                        <tr key={s.id}>
                          <td className="py-2 pe-3 tabular-nums" title={s.user_agent}>
                            {s.ip_address || '-'}
                          </td>
                          <td className="py-2 pe-3 capitalize">{s.auth_method}</td>
                          <td className="py-2 pe-3">
                            <RelativeTime date={s.created_at} />
                          </td>
                          <td className="py-2">
                            <RelativeTime date={s.last_activity_at} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>

          <section className="space-y-3">
            <h2 className="text-base font-semibold">
              {t('admin.users.activity', 'Administrator actions on this account')}
            </h2>
            <AdminActivityTable
              entries={activity.data?.data ?? []}
              isLoading={activity.isLoading}
            />
          </section>
        </div>
      )}
    </Main>
  )
}
