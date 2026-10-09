'use client'

import type { ReactNode } from 'react'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState, PageHeader, RelativeTime } from '@/features/shared'
import { TonePill, type PillTone } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import { useAdminOperations } from '@/features/admin-console/api/use-admin-operations'
import {
  schemaState,
  summarizeSensors,
  type SchemaState,
} from '@/features/admin-console/lib/operations'
import type { AdminOperations } from '@/features/admin-console/types'

function HealthTile({
  title,
  tone,
  state,
  children,
}: {
  title: string
  tone: PillTone
  state: string
  children: ReactNode
}) {
  return (
    <Card className="gap-2 py-4">
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 px-4">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <TonePill tone={tone} label={state} />
      </CardHeader>
      <CardContent className="space-y-0.5 px-4 text-sm">{children}</CardContent>
    </Card>
  )
}

function Row({ label, value, warn }: { label: string; value: ReactNode; warn?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1.5">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className={warn ? 'font-medium text-warning tabular-nums' : 'tabular-nums'}>{value}</dd>
    </div>
  )
}

const SCHEMA_TONE: Record<SchemaState, PillTone> = {
  ok: 'success',
  behind: 'destructive',
  dirty: 'destructive',
  ahead: 'warning',
  unknown: 'muted',
}

function minutes(seconds: number): string {
  if (seconds <= 0) return '-'
  if (seconds < 120) return `${seconds} s`
  return `${Math.round(seconds / 60)} min`
}

function Body({ o }: { o: AdminOperations }) {
  const { t } = useTranslation()
  const schema = schemaState(o)
  const fleet = summarizeSensors(o)
  const q = o.queues

  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <HealthTile
          title={t('admin.ops.api', 'API')}
          tone="success"
          state={t('admin.ops.running', 'Running')}
        >
          <p className="font-medium">{o.build.version || '-'}</p>
          <p className="text-muted-foreground">
            {o.build.commit ? `${o.build.commit} · ` : ''}
            {o.build.channel}
          </p>
        </HealthTile>
        <HealthTile
          title={t('admin.ops.database', 'Database')}
          tone={o.database.ok ? 'success' : 'destructive'}
          state={o.database.ok ? t('admin.ops.ok', 'OK') : t('admin.ops.down', 'Unreachable')}
        >
          <p>{t('admin.ops.latency', '{ms} ms', { ms: o.database.latency_ms.toFixed(1) })}</p>
          <p className="text-muted-foreground">
            {t('admin.ops.pool', 'Pool {inUse} in use of {open} open (max {max})', {
              inUse: o.database.in_use,
              open: o.database.open_connections,
              max: o.database.max_open || '-',
            })}
          </p>
        </HealthTile>
        <HealthTile
          title={t('admin.ops.redis', 'Redis')}
          tone={!o.redis.configured ? 'muted' : o.redis.ok ? 'success' : 'destructive'}
          state={
            !o.redis.configured
              ? t('admin.ops.notConfigured', 'Not configured')
              : o.redis.ok
                ? t('admin.ops.ok', 'OK')
                : t('admin.ops.down', 'Unreachable')
          }
        >
          <p>
            {o.redis.configured
              ? t('admin.ops.latency', '{ms} ms', { ms: o.redis.latency_ms.toFixed(1) })
              : '-'}
          </p>
        </HealthTile>
        <HealthTile
          title={t('admin.ops.schema', 'Database schema')}
          tone={SCHEMA_TONE[schema]}
          state={t(`admin.ops.schema.${schema}`, schema)}
        >
          <p>
            {t('admin.ops.applied', 'Applied {v}', { v: o.schema.known ? o.schema.applied : '-' })}
          </p>
          <p className="text-muted-foreground">
            {t('admin.ops.shipped', 'This release ships {v}', { v: o.schema.shipped || '-' })}
          </p>
        </HealthTile>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('admin.ops.queues', 'Work queues')}</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="divide-y">
              <Row
                label={t('admin.ops.q.pending', 'Sensor jobs waiting')}
                value={q.commands_pending}
              />
              <Row
                label={t('admin.ops.q.oldest', 'Oldest waiting job')}
                value={minutes(q.command_oldest_pending_seconds)}
                warn={q.command_oldest_pending_seconds > 900}
              />
              <Row
                label={t('admin.ops.q.running', 'Sensor jobs running')}
                value={q.commands_running}
              />
              <Row label={t('admin.ops.q.runs', 'Scan runs open')} value={q.scan_runs_open} />
              <Row
                label={t('admin.ops.q.pastDeadline', 'Scan runs past their deadline')}
                value={q.scan_runs_past_deadline}
                warn={q.scan_runs_past_deadline > 0}
              />
              <Row
                label={t('admin.ops.q.outbox', 'Notifications waiting')}
                value={q.outbox_pending}
              />
              <Row
                label={t('admin.ops.q.outboxOldest', 'Oldest waiting notification')}
                value={minutes(q.outbox_oldest_pending_seconds)}
                warn={q.outbox_oldest_pending_seconds > 900}
              />
              <Row
                label={t('admin.ops.q.outboxFailed', 'Notifications retrying')}
                value={q.outbox_failed}
                warn={q.outbox_failed > 0}
              />
              <Row
                label={t('admin.ops.q.outboxDead', 'Notifications that gave up')}
                value={q.outbox_dead}
                warn={q.outbox_dead > 0}
              />
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('admin.ops.fleet', 'Sensor fleet')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <dl className="divide-y">
              <Row
                label={t('admin.ops.fleet.platform', 'Platform sensors (online / total)')}
                value={`${fleet.platform.online} / ${fleet.platform.total}`}
                warn={fleet.platform.unhealthy > 0}
              />
              <Row
                label={t('admin.ops.fleet.customer', 'Customer sensors (online / total)')}
                value={`${fleet.customer.online} / ${fleet.customer.total}`}
              />
            </dl>
            <div className="space-y-2">
              <h3 className="text-sm font-medium">
                {t('admin.ops.fleet.versions', 'SDK versions in the field')}
                {o.sdk_min_version && (
                  <span className="ms-2 font-normal text-muted-foreground">
                    {t('admin.ops.fleet.min', 'minimum {v}', { v: o.sdk_min_version })}
                  </span>
                )}
              </h3>
              {fleet.versions.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t('admin.ops.fleet.none', 'No active sensor.')}
                </p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {fleet.versions.map((v) => (
                    <Badge key={v.version} variant={v.belowMin ? 'destructive' : 'secondary'}>
                      {v.version} · {v.count}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('admin.ops.jobs', 'Background jobs')}</CardTitle>
        </CardHeader>
        <CardContent>
          {o.controllers.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t('admin.ops.jobs.none', 'No background job has reported yet.')}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-muted-foreground">
                  <tr>
                    <th className="py-2 pe-3 text-start font-medium">
                      {t('admin.ops.jobs.name', 'Job')}
                    </th>
                    <th className="py-2 pe-3 text-start font-medium">
                      {t('admin.ops.jobs.last', 'Last run')}
                    </th>
                    <th className="py-2 pe-3 text-end font-medium">
                      {t('admin.ops.jobs.errors', 'Errors since start')}
                    </th>
                    <th className="py-2 text-start font-medium">
                      {t('admin.ops.jobs.state', 'State')}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {o.controllers.map((c) => (
                    <tr key={c.name}>
                      <td className="py-2 pe-3 font-mono text-xs">{c.name}</td>
                      <td className="py-2 pe-3">
                        {c.last_reconcile_at ? <RelativeTime date={c.last_reconcile_at} /> : '-'}
                      </td>
                      <td
                        className={
                          c.errors_total > 0
                            ? 'py-2 pe-3 text-end font-medium text-warning tabular-nums'
                            : 'py-2 pe-3 text-end tabular-nums'
                        }
                      >
                        {c.errors_total}
                      </td>
                      <td className="py-2">
                        {c.running ? (
                          <Badge variant="secondary">
                            {t('admin.ops.jobs.running', 'Started')}
                          </Badge>
                        ) : (
                          <span className="font-medium text-warning">
                            {t('admin.ops.jobs.idle', 'Stopped')}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

export default function AdminOperationsPage() {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useAdminOperations()
  return (
    <Main>
      <PageHeader
        title={t('admin.nav.operations', 'Operations')}
        description={t(
          'admin.ops.description',
          'The health of this installation as the API sees it: build, database, Redis, work queues, sensors and background jobs.'
        )}
      >
        {data && (
          <span className="text-xs text-muted-foreground">
            {t('admin.overview.updated', 'Updated')} <RelativeTime date={data.checked_at} />
          </span>
        )}
      </PageHeader>
      <div className="mt-5">
        {error && !data ? (
          <ErrorState title="operations" error={error} onRetry={() => void mutate()} />
        ) : isLoading || !data ? (
          <Skeleton className="h-64 w-full" />
        ) : (
          <Body o={data} />
        )}
      </div>
    </Main>
  )
}
