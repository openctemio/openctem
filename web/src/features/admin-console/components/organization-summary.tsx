'use client'

import type { ReactNode } from 'react'
import { AlertTriangle, ArrowRight, Gauge, KeyRound, Users } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailField, DetailFieldGrid, RelativeTime } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { PLAN_KEY_LABEL, PLAN_LABEL, isPlanKey, isPlanName } from '@/features/plans/lib/plan-keys'
import { useTenantPlan } from '../api/use-plans'
import { useAdminAuditLogs } from '../api/use-admin-audit'
import { AdminActivityTable } from './admin-activity-table'
import { SSOPostureBadges } from './sso-posture-badges'
import type { AdminOrganization } from '../types'

function SummaryCard({
  icon: Icon,
  title,
  children,
  action,
}: {
  icon: typeof Users
  title: string
  children: ReactNode
  action?: { label: string; onClick: () => void }
}) {
  return (
    <Card className="gap-2 py-4">
      <CardHeader className="flex flex-row items-center gap-2 space-y-0 px-4">
        <Icon className="size-4 text-muted-foreground" aria-hidden="true" />
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col justify-between gap-2 px-4">
        <div className="min-w-0 text-sm">{children}</div>
        {action && (
          <Button
            variant="link"
            size="sm"
            className="h-auto self-start p-0"
            onClick={action.onClick}
          >
            {action.label}
            <ArrowRight className="ms-1 size-3.5" />
          </Button>
        )}
      </CardContent>
    </Card>
  )
}

/**
 * Organization 360, Overview tab: who owns it, its size, plan and usage, how
 * people sign in, and the latest administrator actions on it. Each card leads
 * to the tab where the administrator acts. Nothing from inside the
 * organization (findings, assets) is shown: the console never reads it.
 */
export function OrganizationSummary({
  org,
  onOpenTab,
}: {
  org: AdminOrganization
  onOpenTab: (tab: string) => void
}) {
  const { t } = useTranslation()
  const plan = useTenantPlan(org.id)
  const activity = useAdminAuditLogs({ page: 1, resourceId: org.id, perPage: 5 })
  const planName = plan.data?.plan ?? org.plan
  const overLimit = plan.data?.limits?.filter((l) => l.over_limit) ?? []

  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <SummaryCard
          icon={Users}
          title={t('admin.org.summary.owners', 'Owners')}
          action={{
            label: t('admin.org.summary.members', 'Members'),
            onClick: () => onOpenTab('users'),
          }}
        >
          {org.owner_emails.length === 0 ? (
            <span className="flex items-center gap-1.5 font-medium text-warning">
              <AlertTriangle className="size-4" aria-hidden="true" />
              {t('admin.org.noOwner', 'No owner')}
            </span>
          ) : (
            <ul className="space-y-0.5">
              {org.owner_emails.slice(0, 3).map((e) => (
                <li key={e} className="truncate">
                  {e}
                </li>
              ))}
              {org.owner_emails.length > 3 && (
                <li className="text-muted-foreground">+{org.owner_emails.length - 3}</li>
              )}
            </ul>
          )}
          <p className="mt-1 text-muted-foreground">
            {t('admin.org.summary.activeMembers', '{count} active members', {
              count: org.active_members,
            })}
          </p>
        </SummaryCard>

        <SummaryCard
          icon={Gauge}
          title={t('admin.org.summary.plan', 'Plan')}
          action={{
            label: t('admin.org.summary.limits', 'Limits and usage'),
            onClick: () => onOpenTab('plan'),
          }}
        >
          {plan.isLoading ? (
            <Skeleton className="h-5 w-24" />
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium">
                {isPlanName(planName) ? PLAN_LABEL[planName] : planName}
              </span>
              {plan.data?.over_limit && (
                <Badge variant="destructive">
                  {t('admin.org.summary.overLimit', 'Over limit')}
                </Badge>
              )}
            </div>
          )}
          {overLimit.length > 0 && (
            <p className="mt-1 text-muted-foreground">
              {t('admin.org.summary.atLimit', 'Over the limit: {keys}', {
                keys: overLimit
                  .map((l) => (l.key && isPlanKey(l.key) ? PLAN_KEY_LABEL[l.key] : l.key))
                  .join(', '),
              })}
            </p>
          )}
        </SummaryCard>

        <SummaryCard
          icon={KeyRound}
          title={t('admin.org.summary.signIn', 'Sign-in')}
          action={{
            label: t('admin.org.summary.sso', 'Single sign-on'),
            onClick: () => onOpenTab('sso'),
          }}
        >
          <SSOPostureBadges org={org} />
          <p className="mt-1 text-muted-foreground">
            {t('admin.org.summary.domains', '{count} verified domain(s)', {
              count: org.verified_domains,
            })}
          </p>
        </SummaryCard>

        <Card className="gap-2 py-4">
          <CardContent className="px-4">
            <DetailFieldGrid>
              <DetailField label={t('admin.org.summary.slug', 'Slug')}>
                <code className="text-sm">{org.slug}</code>
              </DetailField>
              <DetailField label={t('admin.org.summary.created', 'Created')}>
                <RelativeTime date={org.created_at} />
              </DetailField>
              <DetailField label={t('admin.org.summary.id', 'ID')} full>
                <code className="text-xs break-all select-all">{org.id}</code>
              </DetailField>
            </DetailFieldGrid>
          </CardContent>
        </Card>
      </div>

      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold">
            {t('admin.org.summary.recent', 'Recent administrator actions on this organization')}
          </h2>
          <Button
            variant="link"
            size="sm"
            className="h-auto p-0"
            onClick={() => onOpenTab('activity')}
          >
            {t('admin.overview.viewAll', 'View all')}
          </Button>
        </div>
        <AdminActivityTable entries={activity.data?.data ?? []} isLoading={activity.isLoading} />
      </section>
    </div>
  )
}
