'use client'

import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { formatDateSafe } from '@/lib/format-date'
import { AdminApiError } from '@console/lib/admin-api/client'
import { rebuildDashboardData, useDashboardDataStatus } from '../api/use-admin-dashboard-data'

interface Props {
  tenantId: string
  /** ops_admin or super_admin (the route's gate); others see the status only. */
  canRebuild: boolean
}

/**
 * An organization's dashboard data: last rebuild and reconciliation, drift the
 * last run corrected, and "Rebuild dashboard data" (ops_admin+, once per hour
 * per organization, shared with the organization's own request; audited).
 */
export function OrganizationDashboardDataPanel({ tenantId, canRebuild }: Props) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useDashboardDataStatus(tenantId)
  const [busy, setBusy] = useState(false)
  const title = t('admin.org.dashboardData.title', 'Dashboard data')

  if (error) {
    return <ErrorState title={title} error={error} onRetry={() => void mutate()} />
  }
  if (isLoading || !data) {
    return <Skeleton className="h-32 w-full" />
  }

  const rebuild = async () => {
    setBusy(true)
    try {
      await mutate(await rebuildDashboardData(tenantId), { revalidate: false })
      toast.success(t('admin.org.dashboardData.requested', 'Rebuild requested.'))
    } catch (err) {
      if (err instanceof AdminApiError && err.status === 429) {
        toast.error(
          t('admin.org.dashboardData.tooSoon', 'Dashboard data can be rebuilt once per hour.')
        )
        void mutate()
      } else {
        toast.error(t('admin.org.dashboardData.failed', 'Could not request a rebuild.'))
      }
    } finally {
      setBusy(false)
    }
  }

  const inProgress = data.pending || Boolean(data.running)
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>
          {t(
            'admin.org.dashboardData.description',
            'Stored per-asset data behind the organization dashboards, kept current from every change and reconciled every night.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <dt className="text-muted-foreground">
              {t('admin.org.dashboardData.lastRebuilt', 'Last full run')}
            </dt>
            <dd>{formatDateSafe(data.rebuilt_at, 'PPp')}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">
              {t('admin.org.dashboardData.lastDrift', 'Drift corrected')}
            </dt>
            <dd>{data.last_drift ?? '—'}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">
              {t('admin.org.dashboardData.pendingChanges', 'Changes waiting')}
            </dt>
            <dd>{data.queue_depth}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">{t('admin.org.dashboardData.state', 'State')}</dt>
            <dd>
              {data.running
                ? t('admin.org.dashboardData.running', 'Running')
                : data.pending
                  ? t('admin.org.dashboardData.pending', 'Requested')
                  : t('admin.org.dashboardData.idle', 'Idle')}
            </dd>
          </div>
        </dl>
        {canRebuild && (
          <div className="flex flex-wrap items-center gap-3">
            <Button
              onClick={() => void rebuild()}
              disabled={busy || inProgress || Boolean(data.next_rebuild_at)}
            >
              <RefreshCw className="me-2 h-4 w-4" aria-hidden />
              {t('admin.org.dashboardData.rebuild', 'Rebuild dashboard data')}
            </Button>
            {data.next_rebuild_at && (
              <span className="text-muted-foreground text-sm">
                {t('admin.org.dashboardData.nextAt', 'Next rebuild possible at {time}', {
                  time: formatDateSafe(data.next_rebuild_at, 'p'),
                })}
              </span>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
