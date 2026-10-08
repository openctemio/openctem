'use client'

import { useMemo } from 'react'
import Link from 'next/link'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import {
  ErrorState,
  MetricStrip,
  PageHeader,
  RelativeTime,
  type MetricStripItem,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useAdminOverview } from '@/features/admin-console/api/use-admin-overview'
import { useAdminAuditLogs } from '@/features/admin-console/api/use-admin-audit'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { AdminActivityTable } from '@/features/admin-console/components/admin-activity-table'
import { AttentionQueue } from '@/features/admin-console/components/attention-queue'
import { buildAttention } from '@/features/admin-console/lib/attention'

export default function AdminOverviewPage() {
  const admin = useAdmin()
  const { t } = useTranslation()
  const overview = useAdminOverview()
  const activity = useAdminAuditLogs({ page: 1 })
  const o = overview.data

  const attention = useMemo(() => (o ? buildAttention(o, admin.role) : []), [o, admin.role])

  const metrics: MetricStripItem[] = o
    ? [
        {
          key: 'orgs',
          label: t('admin.overview.organizations', 'Organizations'),
          value: o.organizations.total,
          hint: t('admin.overview.withoutOwner', '{count} without an owner', {
            count: o.organizations.without_owner,
          }),
          tone: o.organizations.without_owner > 0 ? 'warning' : 'default',
        },
        {
          key: 'sensors',
          label: t('admin.overview.platformSensors', 'Platform sensors online'),
          value:
            o.platform.platform_sensors.total > 0
              ? `${o.platform.platform_sensors.online} / ${o.platform.platform_sensors.total}`
              : t('admin.overview.none', 'None'),
          tone: o.platform.platform_sensors.offline > 0 ? 'warning' : 'default',
        },
        {
          key: 'failed',
          label: t('admin.overview.failedActions', 'Refused admin actions (24 h)'),
          value: o.security.failed_admin_actions_24h,
          tone: o.security.failed_admin_actions_24h > 0 ? 'danger' : 'default',
        },
        {
          key: 'schema',
          label: t('admin.overview.schema', 'Database schema'),
          value: o.platform.schema_known ? o.platform.schema_version : '—',
          hint:
            o.platform.schema_shipped > 0
              ? t('admin.overview.schemaShipped', 'This release ships {version}', {
                  version: o.platform.schema_shipped,
                })
              : undefined,
          tone:
            o.platform.schema_dirty ||
            (o.platform.schema_shipped > 0 &&
              o.platform.schema_version !== o.platform.schema_shipped)
              ? 'danger'
              : 'default',
        },
      ]
    : []

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.overview', 'Overview')}
        description={t(
          'admin.overview.description',
          'What needs a platform administrator now, and the state of the installation.'
        )}
      >
        {o && (
          <span className="text-xs text-muted-foreground">
            {t('admin.overview.updated', 'Updated')} <RelativeTime date={o.generated_at} />
          </span>
        )}
      </PageHeader>
      <div className="mt-5 space-y-6">
        {overview.error && !o ? (
          <ErrorState
            title="the overview"
            error={overview.error}
            onRetry={() => void overview.mutate()}
          />
        ) : (
          <>
            <section className="space-y-3" aria-labelledby="attention-heading">
              <h2 id="attention-heading" className="text-base font-semibold">
                {t('admin.attention.heading', 'Needs attention')}
                {attention.length > 0 && (
                  <span className="ms-2 text-sm font-normal text-muted-foreground tabular-nums">
                    {attention.length}
                  </span>
                )}
              </h2>
              <AttentionQueue items={attention} isLoading={overview.isLoading && !o} />
            </section>
            <MetricStrip items={metrics} loading={overview.isLoading && !o} />
          </>
        )}
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold">
              {t('admin.overview.recentActivity', 'Recent administrator activity')}
            </h2>
            <Button asChild variant="link" size="sm" className="h-auto p-0">
              <Link href="/admin/security/activity">{t('admin.overview.viewAll', 'View all')}</Link>
            </Button>
          </div>
          <AdminActivityTable
            entries={(activity.data?.data ?? []).slice(0, 10)}
            isLoading={activity.isLoading}
          />
        </section>
      </div>
    </Main>
  )
}
