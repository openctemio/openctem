'use client'

import { useDocsHref } from '@/context/brand-provider'
import { useMemo, useState, type ReactNode } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Info } from 'lucide-react'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { DataTable, ErrorState, PageHeader, PageStack, RelativeTime } from '@/features/shared'
import { useUrlFilter } from '@/hooks/use-url-param'
import { TonePill, type PillTone } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import { useAdminOperations } from '@console/features/admin-console/api/use-admin-operations'
import { useAdminSystem } from '@console/features/admin-console/api/use-admin-system'
import {
  jobNeedsAttention,
  schemaState,
  sortJobs,
  sensorTransportView,
  summarizeSensors,
  type SchemaState,
} from '@console/features/admin-console/lib/operations'
import {
  daysLeft,
  formatBytes,
  hoursAgo,
  levelKey,
  levelTone,
} from '@console/features/admin-console/lib/system'
import type { AdminOperations, AdminSystem } from '@console/features/admin-console/types'
import { DOCS } from '@/lib/docs-links'

/**
 * One health page: what the host reports (services, storage, backup,
 * certificates, version: GET /admin/system) and what the API reports about its
 * own work (schema, queues, sensors, background jobs: GET /admin/operations).
 * Each half loads on its own, so one failing read never hides the other.
 *
 * Three tabs keep the page short: the summary first (services, storage,
 * backup, certificates, schema, version), then queues and sensors, then the
 * background jobs, where the ones that fail or stopped come first and the
 * rest wait behind "Show all".
 */

const TABS = ['summary', 'work', 'jobs'] as const
type HealthTab = (typeof TABS)[number]

type Controller = AdminOperations['controllers'][number]

function BackgroundJobs({ o }: { o: AdminOperations }) {
  const { t } = useTranslation()
  const [showAll, setShowAll] = useState(false)
  const sorted = useMemo(() => sortJobs(o.controllers), [o.controllers])
  const attention = sorted.filter(jobNeedsAttention)
  const rows = showAll ? sorted : attention
  const columns = useMemo<ColumnDef<Controller>[]>(
    () => [
      {
        accessorKey: 'name',
        header: t('admin.ops.jobs.name', 'Job'),
        cell: ({ row }) => <span className="font-mono text-xs">{row.original.name}</span>,
      },
      {
        id: 'last',
        header: t('admin.ops.jobs.last', 'Last run'),
        cell: ({ row }) =>
          row.original.last_reconcile_at ? (
            <RelativeTime date={row.original.last_reconcile_at} />
          ) : (
            '-'
          ),
      },
      {
        accessorKey: 'errors_total',
        header: t('admin.ops.jobs.errors', 'Errors since start'),
        cell: ({ row }) => <span className="tabular-nums">{row.original.errors_total}</span>,
      },
      {
        id: 'state',
        header: t('admin.ops.jobs.state', 'State'),
        cell: ({ row }) => {
          const c = row.original
          if (!c.running)
            return <TonePill tone="destructive" label={t('admin.ops.jobs.idle', 'Stopped')} />
          if (c.errors_total > 0)
            return <TonePill tone="warning" label={t('admin.ops.jobs.failing', 'Errors')} />
          return <TonePill tone="success" label={t('admin.ops.jobs.running', 'Started')} />
        },
      },
    ],
    [t]
  )

  if (o.controllers.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        {t('admin.ops.jobs.none', 'No background job has reported yet.')}
      </p>
    )
  }
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground" aria-live="polite">
          {attention.length === 0
            ? t(
                'admin.ops.jobs.allFine',
                '{count, plural, one {The background job runs} other {All # background jobs run}} without errors.',
                { count: sorted.length }
              )
            : t(
                'admin.ops.jobs.needLook',
                '{count, plural, one {# background job stopped or failed} other {# background jobs stopped or failed}} since the start.',
                { count: attention.length }
              )}
        </p>
        <Button variant="outline" size="sm" onClick={() => setShowAll((v) => !v)}>
          {showAll
            ? t('admin.ops.jobs.showAttention', 'Show only the ones to look at')
            : t('admin.ops.jobs.showAll', 'Show all ({count})', { count: sorted.length })}
        </Button>
      </div>
      {rows.length > 0 && (
        <DataTable
          columns={columns}
          data={rows}
          getRowId={(c) => c.name}
          showSearch={false}
          showColumnToggle={false}
          showSelectionCount={false}
          mobileCards
          emptyMessage={t('admin.ops.jobs.none', 'No background job has reported yet.')}
        />
      )}
    </div>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  )
}

function Row({
  label,
  children,
  value,
  warn,
}: {
  label: string
  children?: ReactNode
  value?: ReactNode
  warn?: boolean
}) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 py-1.5">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd
        className={
          warn
            ? 'flex items-center gap-2 text-sm font-medium text-warning tabular-nums'
            : 'flex items-center gap-2 text-sm tabular-nums'
        }
      >
        {value}
        {children}
      </dd>
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

function HostSections({ s, o }: { s: AdminSystem; o?: AdminOperations }) {
  const { t } = useTranslation()
  const levelLabel = (level: number) => t(`admin.system.level.${levelKey(level)}`, levelKey(level))

  const serviceState = (sv: AdminSystem['services'][number]): { tone: PillTone; label: string } => {
    if (!sv.configured)
      return { tone: 'muted', label: t('admin.system.notConfigured', 'Not configured') }
    if (sv.ok) return { tone: 'success', label: t('admin.system.ok', 'OK') }
    return {
      tone: 'destructive',
      label: t(`admin.system.code.${sv.code ?? 'unreachable'}`, sv.code ?? 'unreachable'),
    }
  }

  const b = s.backup
  const backupHours = hoursAgo(b.age_seconds)
  const check = s.version.check
  const services = s.services

  return (
    <>
      <div className="grid gap-5 lg:grid-cols-2">
        <Section title={t('admin.system.services', 'Services')}>
          <dl className="divide-y">
            {services.map((sv) => {
              const st = serviceState(sv)
              return (
                <Row key={sv.name} label={t(`admin.system.service.${sv.name}`, sv.name)}>
                  {sv.name === 'api' && (s.version.running || o?.build.version) && (
                    <span className="text-muted-foreground">
                      {[s.version.running || o?.build.version, o?.build.commit, s.version.channel]
                        .filter(Boolean)
                        .join(', ')}
                    </span>
                  )}
                  {sv.name === 'postgres' && o?.database && (
                    <span className="text-muted-foreground">
                      {t('admin.ops.pool', 'Pool {inUse} in use of {open} open (max {max})', {
                        inUse: o.database.in_use,
                        open: o.database.open_connections,
                        max: o.database.max_open || '-',
                      })}
                    </span>
                  )}
                  {sv.name === 'sensors' && sv.configured && (
                    <span className="text-muted-foreground">
                      {t('admin.system.sensorsOnline', '{n} online', { n: sv.detail ?? 0 })}
                    </span>
                  )}
                  {sv.name !== 'sensors' && sv.configured && sv.ok && sv.latency_ms > 0 && (
                    <span className="text-muted-foreground">
                      {t('admin.system.latency', '{ms} ms', { ms: sv.latency_ms.toFixed(1) })}
                    </span>
                  )}
                  <TonePill tone={st.tone} label={st.label} />
                </Row>
              )
            })}
          </dl>
        </Section>

        <Section title={t('admin.system.storage', 'Storage')}>
          {s.storage.volumes.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t('admin.system.noVolumes', 'No data volume is configured.')}
            </p>
          ) : (
            <dl className="divide-y">
              {s.storage.volumes.map((v) => (
                <Row key={v.name} label={v.name}>
                  {v.ok ? (
                    <>
                      <span className="text-muted-foreground">
                        {t('admin.system.freeOf', '{free} free of {total}', {
                          free: formatBytes(v.free_bytes),
                          total: formatBytes(v.total_bytes),
                        })}
                      </span>
                      <TonePill
                        tone={levelTone(v.level)}
                        label={t('admin.system.freePct', '{pct}% free', {
                          pct: Math.round(v.free_ratio * 100),
                        })}
                      />
                    </>
                  ) : (
                    <TonePill
                      tone="muted"
                      label={t('admin.system.code.unreadable', 'Unreadable')}
                    />
                  )}
                </Row>
              ))}
              <Row label={t('admin.system.database', 'Database size')}>
                {s.storage.database_ok ? (
                  formatBytes(s.storage.database_bytes)
                ) : (
                  <TonePill tone="muted" label={t('admin.system.code.unreadable', 'Unreadable')} />
                )}
              </Row>
            </dl>
          )}
          <p className="mt-3 text-xs text-muted-foreground">
            {t(
              'admin.system.storageNote',
              'Warning below 20% free, critical below 10%. Administrators are emailed when a volume crosses a threshold.'
            )}
          </p>
        </Section>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Section title={t('admin.system.backup', 'Backup')}>
          {b.reported && b.last_success_at ? (
            <dl className="divide-y">
              <Row label={t('admin.system.lastBackup', 'Last successful backup')}>
                <RelativeTime date={b.last_success_at} />
                <TonePill
                  tone={levelTone(b.level)}
                  label={
                    b.level > 0
                      ? t('admin.system.backupStale', 'Older than 26 h')
                      : t('admin.system.ok', 'OK')
                  }
                />
              </Row>
              {backupHours !== null && (
                <Row label={t('admin.system.backupAge', 'Age')}>
                  {t('admin.system.hours', '{n} h', { n: backupHours })}
                </Row>
              )}
              {b.last_failed && (
                <Row label={t('admin.system.lastRun', 'Last run')}>
                  <TonePill tone="warning" label={t('admin.system.backupFailed', 'Failed')} />
                </Row>
              )}
            </dl>
          ) : (
            <p className="text-sm text-muted-foreground">
              {t(
                'admin.system.backupNotReported',
                'No backup status is reported. Set SYSTEM_BACKUP_STATUS_FILE to the backup job status file.'
              )}
            </p>
          )}
        </Section>

        <Section title={t('admin.health.certsSchema', 'Certificates, schema and version')}>
          <dl className="divide-y">
            {s.certificates.length === 0 && (
              <p className="text-sm text-muted-foreground">
                {t('admin.system.noCertificates', 'No certificate is configured.')}
              </p>
            )}
            {s.certificates.map((c) => (
              <Row key={c.name} label={c.name}>
                {c.ok ? (
                  <>
                    <span className="text-muted-foreground">
                      {t('admin.system.expiresIn', 'Expires in {n} days', {
                        n: daysLeft(c.expires_in_seconds) ?? 0,
                      })}
                    </span>
                    <TonePill tone={levelTone(c.level)} label={levelLabel(c.level)} />
                  </>
                ) : (
                  <TonePill tone="muted" label={t('admin.system.code.unreadable', 'Unreadable')} />
                )}
              </Row>
            ))}
            {o && (
              <Row label={t('admin.ops.schema', 'Database schema')}>
                <span className="text-muted-foreground">
                  {t('admin.ops.applied', 'Applied {v}', {
                    v: o.schema.known ? o.schema.applied : '-',
                  })}
                  {', '}
                  {t('admin.ops.shipped', 'This release ships {v}', { v: o.schema.shipped || '-' })}
                </span>
                <TonePill
                  tone={SCHEMA_TONE[schemaState(o)]}
                  label={t(`admin.ops.schema.${schemaState(o)}`, schemaState(o))}
                />
              </Row>
            )}
            {check && (
              <>
                <Row label={t('admin.system.versionCheck', 'Version check')}>
                  {!check.configured ? (
                    <TonePill
                      tone="warning"
                      label={t('admin.system.feed.noKey', 'No release feed key in this build')}
                    />
                  ) : !check.enabled ? (
                    <TonePill tone="muted" label={t('admin.system.off', 'Off')} />
                  ) : check.last_error ? (
                    <TonePill tone="warning" label={feedErrorLabel(t, check.last_error)} />
                  ) : (
                    <TonePill tone="success" label={t('admin.system.ok', 'OK')} />
                  )}
                  {check.last_attempt_at && <RelativeTime date={check.last_attempt_at} />}
                </Row>
                {check.configured && (
                  <Row label={t('admin.system.feed.lastSuccess', 'Last release information')}>
                    {check.applied_at ? (
                      <RelativeTime date={check.applied_at} />
                    ) : (
                      <span className="text-muted-foreground">
                        {t(
                          'admin.system.feed.never',
                          'Never: the versions built into this release apply'
                        )}
                      </span>
                    )}
                  </Row>
                )}
                {check.latest && (
                  <Row label={t('admin.system.latest', 'Latest release')}>
                    {check.latest}
                    {check.update_available && (
                      <TonePill
                        tone="info"
                        label={t('admin.system.updateAvailable', 'Update available')}
                      />
                    )}
                  </Row>
                )}
                {check.advisories > 0 && (
                  <Row label={t('admin.system.advisories', 'Advisories for this version')}>
                    <TonePill tone="destructive" label={String(check.advisories)} />
                  </Row>
                )}
              </>
            )}
          </dl>
        </Section>
      </div>
    </>
  )
}

function WorkSections({ o }: { o: AdminOperations }) {
  const docsHref = useDocsHref()
  const { t } = useTranslation()
  const fleet = summarizeSensors(o)
  const transport = sensorTransportView(o.sensor_transport)
  const q = o.queues

  return (
    <>
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
              {transport && (
                <Row
                  label={t('admin.ops.transport', 'Sensor connection')}
                  value={t(`admin.ops.transport.${transport.binding}`, transport.binding)}
                />
              )}
            </dl>
            {transport?.noteKey && (
              <div
                className="flex gap-2 rounded-md border bg-muted/40 p-3 text-sm"
                data-testid="sensor-transport-note"
              >
                <Info className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
                <div className="space-y-1">
                  <p>{t(transport.noteKey)}</p>
                  <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-xs text-muted-foreground">
                    <a
                      href={docsHref(DOCS.sensors.transportPlatform)}
                      target="_blank"
                      rel="noreferrer"
                      className="underline underline-offset-2"
                    >
                      {t('admin.ops.transport.docs', 'How sensors connect')}
                    </a>
                    {transport.reason && (
                      <span className="font-mono">
                        {t('admin.ops.transport.code', 'Reason code: {code}', {
                          code: transport.reason,
                        })}
                      </span>
                    )}
                  </p>
                </div>
              </div>
            )}
            <div className="space-y-2">
              <h3 className="text-sm font-medium">
                {t('admin.ops.fleet.versions', 'SDK versions in the field')}
                {(o.sdk_advisories?.length ?? 0) > 0 && (
                  <span className="ms-2 font-normal text-muted-foreground">
                    {t('admin.ops.fleet.advisories', 'security advisory: {v}', {
                      v: (o.sdk_advisories ?? []).join(', '),
                    })}
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
                    <Badge key={v.version} variant={v.advisory ? 'destructive' : 'secondary'}>
                      {t('admin.ops.fleet.versionCount', '{version}: {count}', {
                        version: v.version,
                        count: v.count,
                      })}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </>
  )
}

export default function AdminHealthPage() {
  const { t } = useTranslation()
  const sys = useAdminSystem()
  const ops = useAdminOperations()
  const checkedAt = sys.data?.checked_at ?? ops.data?.checked_at
  const [tabParam, setTab] = useUrlFilter('tab', 'summary')
  const tab: HealthTab = (TABS as readonly string[]).includes(tabParam)
    ? (tabParam as HealthTab)
    : 'summary'
  const jobsToLook = ops.data ? ops.data.controllers.filter(jobNeedsAttention).length : null
  const opsState =
    ops.error && !ops.data ? (
      <ErrorState
        title={t('admin.healthPage.operations', 'operations')}
        error={ops.error}
        onRetry={() => void ops.mutate()}
      />
    ) : ops.isLoading || !ops.data ? (
      <Skeleton className="h-64 w-full" />
    ) : null
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.nav.health', 'Health')}
          description={t(
            'admin.health.description',
            'The health of this installation: services, storage, backup, certificates, version, work queues, sensors and background jobs. Read-only: backup, restore and upgrade run from the kit on the host.'
          )}
        >
          {checkedAt && (
            <span className="flex items-center gap-2 text-xs text-muted-foreground">
              {sys.data && (
                <TonePill
                  tone={levelTone(sys.data.level)}
                  label={t(
                    `admin.system.level.${levelKey(sys.data.level)}`,
                    levelKey(sys.data.level)
                  )}
                />
              )}
              {t('admin.overview.updated', 'Updated')} <RelativeTime date={checkedAt} />
            </span>
          )}
        </PageHeader>
        <Tabs value={tab} onValueChange={(v) => setTab(v)}>
          <TabsList aria-label={t('admin.health.tabsLabel', 'Health sections')}>
            <TabsTrigger value="summary">{t('admin.health.tab.summary', 'Summary')}</TabsTrigger>
            <TabsTrigger value="work">
              {t('admin.health.tab.work', 'Queues and sensors')}
            </TabsTrigger>
            <TabsTrigger value="jobs">
              {t('admin.health.tab.jobs', 'Background jobs')}
              <TabsCount value={jobsToLook || null} tone="danger" />
            </TabsTrigger>
          </TabsList>
          <TabsContent value="summary" className="mt-5 space-y-5">
            {sys.error && !sys.data ? (
              <ErrorState
                title={t('admin.healthPage.system', 'system')}
                error={sys.error}
                onRetry={() => void sys.mutate()}
              />
            ) : sys.isLoading || !sys.data ? (
              <Skeleton className="h-64 w-full" />
            ) : (
              <HostSections s={sys.data} o={ops.data} />
            )}
          </TabsContent>
          <TabsContent value="work" className="mt-5 space-y-5">
            {opsState ?? (ops.data && <WorkSections o={ops.data} />)}
          </TabsContent>
          <TabsContent value="jobs" className="mt-5">
            {opsState ?? (ops.data && <BackgroundJobs o={ops.data} />)}
          </TabsContent>
        </Tabs>
      </PageStack>
    </Main>
  )
}

function feedErrorLabel(t: (key: string, fallback: string) => string, code: string): string {
  switch (code) {
    case 'not_published':
      return t('admin.system.feed.notPublished', 'Release feed not published')
    case 'invalid':
    case 'no_key':
      return t('admin.system.feed.invalid', 'Release feed signature invalid')
    case 'unreachable':
      return t('admin.system.feed.unreachable', 'Release feed unreachable')
    case 'expired':
      return t('admin.system.feed.expired', 'Release feed expired')
    default:
      return t('admin.system.checkFailed', 'Last check failed')
  }
}
