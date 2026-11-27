'use client'

import { useCallback, useEffect, useState } from 'react'
import { type ReactNode } from 'react'
import { AlertCircle, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { HealthStatus } from '@/components/ui/health-status'
import { Skeleton } from '@/components/ui/skeleton'
import { SettingsBlock, SettingsRow, SettingsSection } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { get, post } from '@/lib/api/client'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'
import { useCanMutate } from '@/lib/permissions'
import { useNearViewport } from '@/hooks/use-near-viewport'

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
const SECTION_ID = 'dashboard-data'

/**
 * Organization › General › Dashboard data: when the organization's dashboard
 * facts were last rebuilt and reconciled, and "Rebuild dashboard data"
 * (owners and administrators; once per hour, audited). The rebuild runs in
 * the background; the section shows it as pending, then running.
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

  // The section sits below the fold of General: it reads its state when it
  // comes near the viewport (a link to it scrolls it there), not on the load.
  const near = useNearViewport(SECTION_ID)
  useEffect(() => {
    if (near) load()
  }, [near, load])

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

  const section = (body: ReactNode) => (
    <SettingsSection framed id={SECTION_ID} title={t('org.dashboardData.title', 'Dashboard data')}>
      {body}
    </SettingsSection>
  )

  if (state === 'loading') {
    return section(
      <SettingsBlock>
        <Skeleton className="h-4 w-1/2" />
        <Skeleton className="h-4 w-1/3" />
      </SettingsBlock>
    )
  }

  if (state === 'error' || !status) {
    return section(
      <SettingsBlock>
        <Alert variant="destructive">
          <AlertCircle aria-hidden />
          <AlertTitle>
            {t('org.dashboardData.loadFailed', 'Could not load dashboard data status')}
          </AlertTitle>
          <AlertDescription>
            {loadError && <p>{loadError}</p>}
            <Button variant="outline" className="mt-2" onClick={load}>
              {t('common.retry', 'Retry')}
            </Button>
          </AlertDescription>
        </Alert>
      </SettingsBlock>
    )
  }

  const inProgress = status.pending || Boolean(status.running)
  const blocked = Boolean(status.next_rebuild_at)
  let stateText = t(
    'org.dashboardData.notBuilt',
    'Not built yet: the first build runs in the background.'
  )
  let health: 'ok' | 'run' | 'queued' | 'unknown' = 'unknown'
  if (status.running) {
    stateText = t('org.dashboardData.running', 'Rebuilding now.')
    health = 'run'
  } else if (status.pending) {
    stateText = t('org.dashboardData.pending', 'Rebuild requested; it starts within a few minutes.')
    health = 'queued'
  } else if (status.rebuilt_at) {
    stateText = t('org.dashboardData.upToDate', 'Kept up to date automatically.')
    health = 'ok'
  }

  return section(
    <>
      <SettingsRow
        // The state is a sentence: the glyph, then the sentence wrapping in
        // full (the state chip holds one short word and would cut it).
        label={
          <span className="inline-flex items-start gap-1.5 text-xs font-medium">
            <span aria-hidden className="mt-px shrink-0">
              <HealthStatus state={health} label={stateText} iconOnly />
            </span>
            <span className="min-w-0 break-words">{stateText}</span>
          </span>
        }
        hint={t(
          'org.dashboardData.description',
          'Dashboard numbers are computed from stored per-asset data, kept current from every change and checked every night. Rebuild it if dashboards look wrong.'
        )}
      >
        {canRebuild && (
          <Button
            variant="outline"
            onClick={() => void rebuild()}
            disabled={busy || inProgress || blocked}
          >
            <RefreshCw aria-hidden />
            {t('org.dashboardData.rebuild', 'Rebuild dashboard data')}
          </Button>
        )}
      </SettingsRow>
      <SettingsBlock divider={false}>
        <dl className="flex flex-wrap gap-x-8 gap-y-2 text-dense">
          <div>
            <dt className="text-cap text-muted-foreground">
              {t('org.dashboardData.lastRebuilt', 'Last full rebuild')}
            </dt>
            <dd>{formatDateSafe(status.rebuilt_at, 'PPp')}</dd>
          </div>
          <div>
            <dt className="text-cap text-muted-foreground">
              {t('org.dashboardData.pendingChanges', 'Changes waiting')}
            </dt>
            <dd className="tabular-nums">{status.queue_depth}</dd>
          </div>
        </dl>
        {canRebuild && blocked && (
          <p className="text-cap text-muted-foreground">
            {t('org.dashboardData.nextAt', 'Next rebuild possible at {time}', {
              time: formatDateSafe(status.next_rebuild_at, 'p'),
            })}
          </p>
        )}
      </SettingsBlock>
    </>
  )
}
