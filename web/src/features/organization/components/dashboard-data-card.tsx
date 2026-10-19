'use client'

import { useCallback, useEffect, useState } from 'react'
import { AlertCircle, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { get, post } from '@/lib/api/client'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'
import { useCanMutate } from '@/lib/permissions'

/** GET /api/v1/dashboard-data/ (and the console's per-organization copy). */
export interface DashboardDataStatus {
  rebuilt_at: string | null
  reconciled_at: string | null
  last_drift: number | null
  rebuild_requested_at: string | null
  running?: 'initial' | 'requested' | 'nightly'
  pending: boolean
  queue_depth: number
  next_rebuild_at: string | null
}

const STATUS_PATH = '/api/v1/dashboard-data/'
const REBUILD_PATH = '/api/v1/dashboard-data/rebuild'

/**
 * Organization › General › Dashboard data: when the organization's dashboard
 * facts were last rebuilt and reconciled, and "Rebuild dashboard data"
 * (owners and administrators; once per hour, audited). The rebuild runs in
 * the background; the card shows it as pending, then running.
 */
export function DashboardDataCard() {
  const { t } = useTranslation()
  const canRebuild = useCanMutate(`POST ${REBUILD_PATH}`)
  const [status, setStatus] = useState<DashboardDataStatus>()
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [loadError, setLoadError] = useState<string>()
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    setState('loading')
    get<DashboardDataStatus>(STATUS_PATH)
      .then((data) => {
        setStatus(data)
        setState('ready')
      })
      .catch((err: unknown) => {
        setLoadError(getErrorMessage(err, ''))
        setState('error')
      })
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const rebuild = async () => {
    setBusy(true)
    try {
      const next = await post<DashboardDataStatus>(REBUILD_PATH)
      setStatus(next)
      toast.success(
        t('org.dashboardData.requested', 'Rebuild requested. Dashboards update when it finishes.')
      )
    } catch (err) {
      if (err instanceof ApiClientError && err.statusCode === 429) {
        toast.error(t('org.dashboardData.tooSoon', 'Dashboard data can be rebuilt once per hour.'))
        load()
      } else {
        toast.error(
          getErrorMessage(err, t('org.dashboardData.failed', 'Could not request a rebuild.'))
        )
      }
    } finally {
      setBusy(false)
    }
  }

  const title = t('org.dashboardData.title', 'Dashboard data')
  if (state === 'loading') {
    return (
      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <Skeleton className="h-4 w-1/2" />
          <Skeleton className="h-4 w-1/3" />
        </CardContent>
      </Card>
    )
  }
  if (state === 'error' || !status) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" aria-hidden />
        <AlertTitle>
          {t('org.dashboardData.loadFailed', 'Could not load dashboard data status')}
        </AlertTitle>
        <AlertDescription>
          {loadError}
          <Button variant="link" className="h-auto p-0 ps-2" onClick={load}>
            {t('common.retry', 'Retry')}
          </Button>
        </AlertDescription>
      </Alert>
    )
  }

  const inProgress = status.pending || Boolean(status.running)
  const blocked = Boolean(status.next_rebuild_at)
  let stateText = t(
    'org.dashboardData.notBuilt',
    'Not built yet: the first build runs in the background.'
  )
  if (status.running) {
    stateText = t('org.dashboardData.running', 'Rebuilding now.')
  } else if (status.pending) {
    stateText = t('org.dashboardData.pending', 'Rebuild requested; it starts within a few minutes.')
  } else if (status.rebuilt_at) {
    stateText = t('org.dashboardData.upToDate', 'Kept up to date automatically.')
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>
          {t(
            'org.dashboardData.description',
            'Dashboard numbers are computed from stored per-asset data, kept current from every change and checked every night. Rebuild it if dashboards look wrong.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm">{stateText}</p>
        <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-muted-foreground">
              {t('org.dashboardData.lastRebuilt', 'Last full rebuild')}
            </dt>
            <dd>{formatDateSafe(status.rebuilt_at, 'PPp')}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">
              {t('org.dashboardData.pendingChanges', 'Changes waiting')}
            </dt>
            <dd>{status.queue_depth}</dd>
          </div>
        </dl>
        {canRebuild && (
          <div className="flex flex-wrap items-center gap-3">
            <Button onClick={() => void rebuild()} disabled={busy || inProgress || blocked}>
              <RefreshCw className="me-2 h-4 w-4" aria-hidden />
              {t('org.dashboardData.rebuild', 'Rebuild dashboard data')}
            </Button>
            {blocked && (
              <span className="text-muted-foreground text-sm">
                {t('org.dashboardData.nextAt', 'Next rebuild possible at {time}', {
                  time: formatDateSafe(status.next_rebuild_at, 'p'),
                })}
              </span>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
