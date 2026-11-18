'use client'

/**
 * The shared sensor fleet, queue and job panels of the platform scanning page
 * (api docs/rfcs/RFC-100-shared-sensors.md §12): the instance sensors with
 * their state, queue aggregates per tool lane and per organization, and job
 * metadata. Any administrator reads. A job's targets and logs need a reason
 * (super or operations administrator; the API audits the view); pause, resume
 * and retire need a super admin, a reason and a fresh authenticator code.
 * Results and findings are never shown here.
 */

import { EmptyCell } from '@/features/assets/components/service-cells'
import { useCallback, useMemo, useState, type ReactNode } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Info, ListChecks, Server } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import { useListParams } from '@/hooks/use-list-params'
import {
  DataTable,
  DataTableRowActions,
  EmptyState,
  ErrorState,
  FilterSelect,
  MetaLine,
  RelativeTime,
} from '@/features/shared'
import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import {
  actOnSharedSensor,
  useSharedFleet,
  useSharedJobs,
  useSharedQueue,
  viewSharedJob,
  type SharedFleetSensor,
  type SharedJob,
  type SharedJobDetail,
  type SharedSensorAction,
} from '@console/features/admin-console/api/use-shared-fleet'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import {
  TypedAdminConfirmDialog,
  nameToType,
} from '@console/features/admin-console/components/type-to-confirm-field'
import { AdminConfirmDialog } from '@console/features/admin-console/components/admin-confirm-dialog'
import { adminHas } from '@console/features/admin-console/types'

const JOB_STATUSES = [
  'pending',
  'acknowledged',
  'running',
  'completed',
  'failed',
  'canceled',
  'expired',
]

/**
 * The fleet as the page's list: its title row (name, one count, and an info
 * mark for `note` when there is one), the table, then the one line on what
 * pausing and retiring do.
 */
export function SharedFleetPanel({ note }: { note?: ReactNode } = {}) {
  const { t } = useTranslation()
  const me = useAdmin()
  const isSuper = adminHas(me, 'platform.sensors.manage')
  const fleet = useSharedFleet()
  const [acting, setActing] = useState<{
    sensor: SharedFleetSensor
    action: SharedSensorAction
  } | null>(null)

  // The row menu: the same items in a table row and on a phone card.
  const fleetMenu = useCallback(
    (s: SharedFleetSensor) => {
      if (!isSuper || s.status === 'revoked') return null
      return (
        <DataTableRowActions
          label={t('admin.sharedFleet.rowActions', 'Actions for the sensor {name}', {
            name: s.name,
          })}
          actions={[
            s.status === 'active'
              ? {
                  label: t('admin.sharedFleet.pause'),
                  onClick: () => setActing({ sensor: s, action: 'pause' }),
                }
              : {
                  label: t('admin.sharedFleet.resume'),
                  onClick: () => setActing({ sensor: s, action: 'resume' }),
                },
            {
              label: t('admin.sharedFleet.retire'),
              onClick: () => setActing({ sensor: s, action: 'retire' }),
              destructive: true,
              separatorBefore: true,
            },
          ]}
        />
      )
    },
    [t, isSuper]
  )

  const sensorColumns = useMemo<ColumnDef<SharedFleetSensor>[]>(
    () => [
      {
        accessorKey: 'name',
        header: t('admin.sharedFleet.col.sensor'),
        // The sensor is the row's name: its name, then its region, on one
        // line. It stays in view while the table scrolls sideways.
        meta: {
          kind: 'name',
          pin: 'start',
          minWidth: 180,
          label: t('admin.sharedFleet.col.sensor'),
        },
        cell: ({ row }) => {
          const region = row.original.region || t('admin.sharedFleet.noRegion')
          return (
            <div className="flex min-w-0 items-baseline gap-2">
              <span className="truncate font-medium" title={row.original.name}>
                {row.original.name}
              </span>
              <span className="shrink-0 text-cap text-muted-foreground">{region}</span>
            </div>
          )
        },
      },
      {
        accessorKey: 'status',
        header: t('admin.sharedFleet.col.status'),
        // Two badges (state and health); Vietnamese needs the room.
        meta: { kind: 'status', width: 232, label: t('admin.sharedFleet.col.status') },
        cell: ({ row }) => (
          <div className="flex min-w-0 gap-1 overflow-hidden">
            <Badge variant={row.original.status === 'active' ? 'secondary' : 'outline'}>
              {t(`admin.sharedFleet.status.${row.original.status}`, row.original.status)}
            </Badge>
            {row.original.health && (
              <Badge variant="outline">
                {t(`admin.sharedFleet.health.${row.original.health}`, row.original.health)}
              </Badge>
            )}
          </div>
        ),
      },
      {
        accessorKey: 'version',
        header: t('admin.sharedFleet.col.version'),
        meta: {
          kind: 'text',
          width: 120,
          hideBelow: 900,
          label: t('admin.sharedFleet.col.version'),
        },
        cell: ({ row }) =>
          row.original.version ? (
            <span className="block truncate font-mono text-code">{row.original.version}</span>
          ) : (
            <EmptyCell title={t('admin.sharedFleet.noVersion', 'Version not reported')} />
          ),
      },
      {
        id: 'tools',
        header: t('admin.sharedFleet.col.tools'),
        meta: {
          kind: 'tags',
          width: 240,
          hideBelow: 1000,
          label: t('admin.sharedFleet.col.tools'),
        },
        cell: ({ row }) =>
          row.original.tools.length === 0 ? (
            <EmptyCell title={t('admin.sharedFleet.noTools', 'No tools reported')} />
          ) : (
            <span
              className="block truncate font-mono text-code"
              title={row.original.tools.join(', ')}
            >
              {row.original.tools.join(', ')}
            </span>
          ),
      },
      {
        accessorKey: 'current_jobs',
        header: t('admin.sharedFleet.col.jobs'),
        meta: {
          kind: 'number',
          width: 96,
          hideBelow: 700,
          label: t('admin.sharedFleet.col.jobs'),
        },
        cell: ({ row }) => (
          <span className="tabular-nums">
            {row.original.max_jobs > 0
              ? `${row.original.current_jobs} / ${row.original.max_jobs}`
              : row.original.current_jobs}
          </span>
        ),
      },
      {
        accessorKey: 'last_seen_at',
        header: t('admin.sharedFleet.col.lastSeen'),
        meta: { kind: 'datetime-recent', width: 152, label: t('admin.sharedFleet.col.lastSeen') },
        cell: ({ row }) =>
          row.original.last_seen_at ? (
            <RelativeTime date={row.original.last_seen_at} />
          ) : (
            <span className="text-muted-foreground">{t('admin.sharedFleet.never')}</span>
          ),
      },
      {
        id: 'actions',
        header: '',
        enableSorting: false,
        meta: { kind: 'actions' },
        cell: ({ row }) => fleetMenu(row.original),
      },
    ],
    [t, fleetMenu]
  )

  const actionText: Record<
    SharedSensorAction,
    { title: string; desc: string; confirm: string; done: string; reason: string }
  > = {
    pause: {
      title: 'admin.sharedFleet.pauseTitle',
      desc: 'admin.sharedFleet.pauseDesc',
      confirm: 'admin.sharedFleet.pause',
      done: 'admin.sharedFleet.paused',
      reason: 'admin.sharedFleet.reasonPause',
    },
    resume: {
      title: 'admin.sharedFleet.resumeTitle',
      desc: 'admin.sharedFleet.resumeDesc',
      confirm: 'admin.sharedFleet.resume',
      done: 'admin.sharedFleet.resumed',
      reason: 'admin.sharedFleet.reasonResume',
    },
    retire: {
      title: 'admin.sharedFleet.retireTitle',
      desc: 'admin.sharedFleet.retireDesc',
      confirm: 'admin.sharedFleet.retireButton',
      done: 'admin.sharedFleet.retired',
      reason: 'admin.sharedFleet.reasonRetire',
    },
  }

  return (
    <>
      <div className="flex min-w-0 flex-col gap-3" data-testid="sensors-fleet">
        {/* On a phone the info mark is a 36 px touch target: the row has that
            height from the first frame, so the mark appearing once the setting
            is read moves nothing. */}
        <ListTitleRow
          className="max-md:min-h-control-touch"
          title={t('admin.sharedFleet.fleetTitle')}
          count={
            <ListCount
              total={fleet.data?.sensors?.length ?? 0}
              loading={!fleet.data && !fleet.error}
              label={t('admin.sharedFleet.total', undefined, {
                count: fleet.data?.sensors?.length ?? 0,
              })}
            />
          }
        >
          {note ? (
            <Popover>
              <PopoverTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={t('admin.sharedFleet.aboutShared')}
                  data-testid="sensors-shared-scanning-closed"
                >
                  <Info aria-hidden />
                </Button>
              </PopoverTrigger>
              <PopoverContent align="end" className="max-w-xs text-body text-muted-foreground">
                {note}
              </PopoverContent>
            </Popover>
          ) : null}
        </ListTitleRow>
        <DataTable
          columns={sensorColumns}
          data={fleet.data?.sensors ?? []}
          caption={t('admin.sharedFleet.fleetTitle')}
          getRowId={(s) => s.id}
          error={fleet.error}
          onRetry={() => void fleet.mutate()}
          errorTitle={t('admin.sharedFleet.fleetTitle')}
          // The first read: skeleton rows; a failed read shows in the table with Retry.
          isLoading={fleet.isLoading && !fleet.data}
          showSearch={false}
          showSelectionCount={false}
          showPagination={false}
          // A phone card with fixed slots, not the automatic label/value card.
          mobileRow={(s) => <SharedFleetMobileCard sensor={s} actions={fleetMenu(s)} />}
          emptyState={{
            nothingYet: <EmptyState icon={Server} title={t('admin.sharedFleet.noSensors')} />,
          }}
        />
        <p className="text-body text-muted-foreground">{t('admin.sharedFleet.fleetDesc')}</p>
      </div>

      {acting && (
        <TypedAdminConfirmDialog
          reasonPlaceholder={t(actionText[acting.action].reason)}
          typeToConfirm={
            acting.action === 'retire'
              ? nameToType(acting.sensor.name, acting.sensor.id)
              : undefined
          }
          open
          onOpenChange={(open) => !open && setActing(null)}
          title={t(actionText[acting.action].title, undefined, { name: acting.sensor.name })}
          description={<p>{t(actionText[acting.action].desc)}</p>}
          confirmLabel={t(actionText[acting.action].confirm)}
          destructive={acting.action !== 'resume'}
          requireCode
          onConfirm={async (proof) => {
            await actOnSharedSensor(acting.sensor.id, acting.action, proof)
            toast.success(
              t(actionText[acting.action].done, undefined, { name: acting.sensor.name })
            )
            setActing(null)
            void fleet.mutate()
          }}
        />
      )}
    </>
  )
}

/**
 * A fleet sensor on a phone. Fixed slots, one fact per element, never a
 * label/value grid:
 *
 *   shared-eu-1  eu                                   [...]
 *   Active  Online                  (wraps, never cut)
 *   v1.2.3   1 of 4 jobs   Seen 2 hours ago
 *   nuclei, httpx                   (only when it has tools)
 *
 * An item with no value (region, version, tools) is left out instead of
 * showing a dash or a placeholder.
 */
export function SharedFleetMobileCard({
  sensor,
  actions,
}: {
  sensor: SharedFleetSensor
  /** The row menu, the same one the table row has. */
  actions?: ReactNode
}) {
  const { t } = useTranslation()
  return (
    <div data-slot="fleet-card" className="flex w-full min-w-0 items-start gap-2 px-3 py-3">
      <div className="flex min-w-0 flex-1 flex-col gap-1.5">
        <div data-slot="fleet-card-title" className="flex min-w-0 items-baseline gap-2">
          <span className="min-w-0 truncate font-medium" title={sensor.name}>
            {sensor.name}
          </span>
          {sensor.region ? (
            <span className="shrink-0 text-cap text-muted-foreground">{sensor.region}</span>
          ) : null}
        </div>
        <div data-slot="fleet-card-state" className="flex flex-wrap items-center gap-1">
          <Badge variant={sensor.status === 'active' ? 'secondary' : 'outline'}>
            {t(`admin.sharedFleet.status.${sensor.status}`, sensor.status)}
          </Badge>
          {sensor.health && (
            <Badge variant="outline">
              {t(`admin.sharedFleet.health.${sensor.health}`, sensor.health)}
            </Badge>
          )}
        </div>
        <MetaLine
          className="items-center"
          items={[
            sensor.version ? (
              <span key="version">
                {t('admin.sharedFleet.card.version', 'v{version}', {
                  version: sensor.version.replace(/^v/i, ''),
                })}
              </span>
            ) : null,
            <span key="jobs" className="tabular-nums">
              {sensor.max_jobs > 0
                ? t('admin.sharedFleet.card.jobsOf', '{current} of {max} jobs', {
                    current: sensor.current_jobs,
                    max: sensor.max_jobs,
                  })
                : t('admin.sharedFleet.card.jobs', '{count, plural, one {# job} other {# jobs}}', {
                    count: sensor.current_jobs,
                  })}
            </span>,
            sensor.last_seen_at ? (
              <span key="seen">
                {t('admin.sharedFleet.card.seen', 'Seen')}{' '}
                <RelativeTime date={sensor.last_seen_at} />
              </span>
            ) : (
              <span key="seen">{t('admin.sharedFleet.card.neverSeen', 'Not seen yet')}</span>
            ),
          ]}
        />
        {sensor.tools.length > 0 && (
          <p
            data-slot="fleet-card-tools"
            className="truncate font-mono text-code text-muted-foreground"
            title={sensor.tools.join(', ')}
          >
            {sensor.tools.join(', ')}
          </p>
        )}
      </div>
      {actions && <div className="-my-1 shrink-0">{actions}</div>}
    </div>
  )
}

export function SharedQueuePanel() {
  const { t } = useTranslation()
  const me = useAdmin()
  const canView = adminHas(me, 'platform.sensors.jobs.read')
  const queue = useSharedQueue()
  const list = useListParams({ pageSizes: [20], defaultPageSize: 20, filters: { status: '' } })
  const status = list.filters.status
  const jobs = useSharedJobs(list.page, status)
  const [viewing, setViewing] = useState<SharedJob | null>(null)
  const [detail, setDetail] = useState<SharedJobDetail | null>(null)

  const jobColumns = useMemo<ColumnDef<SharedJob>[]>(
    () => [
      {
        accessorKey: 'tenant_name',
        header: t('admin.sharedFleet.col.organization'),
        // The organization is the row's name; it stays in view while the
        // table scrolls sideways.
        meta: {
          kind: 'name',
          pin: 'start',
          minWidth: 180,
          label: t('admin.sharedFleet.col.organization'),
        },
        cell: ({ row }) => {
          const org = row.original.tenant_name || row.original.tenant_id
          return (
            <span className="block truncate font-medium" title={org}>
              {org}
            </span>
          )
        },
      },
      {
        accessorKey: 'tool',
        header: t('admin.sharedFleet.col.tool'),
        meta: { kind: 'text', width: 176, label: t('admin.sharedFleet.col.tool') },
        cell: ({ row }) => (
          <span className="block truncate font-mono text-code">
            {row.original.tool || row.original.type}
          </span>
        ),
      },
      {
        accessorKey: 'status',
        header: t('admin.sharedFleet.col.status'),
        meta: { kind: 'status', width: 136, label: t('admin.sharedFleet.col.status') },
        cell: ({ row }) => (
          <Badge variant="outline">
            {t(`admin.sharedFleet.jobStatus.${row.original.status}`, row.original.status)}
          </Badge>
        ),
      },
      {
        accessorKey: 'sensor_name',
        header: t('admin.sharedFleet.col.sensor'),
        meta: {
          kind: 'text',
          width: 176,
          hideBelow: 900,
          label: t('admin.sharedFleet.col.sensor'),
        },
        cell: ({ row }) =>
          row.original.sensor_name ? (
            <span className="block truncate">{row.original.sensor_name}</span>
          ) : (
            <EmptyCell title={t('admin.sharedFleet.noSensor', 'No sensor')} />
          ),
      },
      {
        accessorKey: 'created_at',
        header: t('admin.sharedFleet.col.created'),
        meta: { kind: 'datetime-recent', width: 152, label: t('admin.sharedFleet.col.created') },
        cell: ({ row }) => <RelativeTime date={row.original.created_at} />,
      },
      {
        id: 'view',
        header: '',
        enableSorting: false,
        meta: { kind: 'actions' },
        cell: ({ row }) =>
          canView ? (
            <DataTableRowActions
              label={t('admin.sharedFleet.jobActions', 'Actions for the job of {org}', {
                org: row.original.tenant_name || row.original.tenant_id,
              })}
              actions={[
                {
                  label: t('admin.sharedFleet.viewJob'),
                  onClick: () => setViewing(row.original),
                },
              ]}
            />
          ) : null,
      },
    ],
    [t, canView]
  )

  return (
    <>
      <div className="space-y-5">
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>{t('admin.sharedFleet.lanesTitle')}</CardTitle>
              <CardDescription>{t('admin.sharedFleet.lanesDesc')}</CardDescription>
            </CardHeader>
            <CardContent>
              {queue.error ? (
                <ErrorState
                  title={t('admin.sharedFleet.lanesTitle')}
                  error={queue.error}
                  onRetry={() => void queue.mutate()}
                />
              ) : (queue.data?.lanes ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">{t('admin.sharedFleet.queueEmpty')}</p>
              ) : (
                <ul className="divide-y text-sm">
                  {(queue.data?.lanes ?? []).map((l) => (
                    <li
                      key={l.tool || '-'}
                      className="flex items-center justify-between gap-2 py-2"
                    >
                      <span className="font-mono text-xs">
                        {l.tool || t('admin.sharedFleet.anyTool')}
                      </span>
                      <span className="tabular-nums text-muted-foreground">
                        {t('admin.sharedFleet.queuedRunning', undefined, {
                          queued: l.queued,
                          running: l.running,
                        })}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>{t('admin.sharedFleet.usageTitle')}</CardTitle>
              <CardDescription>{t('admin.sharedFleet.usageDesc')}</CardDescription>
            </CardHeader>
            <CardContent>
              {(queue.data?.organizations ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">{t('admin.sharedFleet.usageEmpty')}</p>
              ) : (
                <ul className="divide-y text-sm">
                  {(queue.data?.organizations ?? []).map((o) => (
                    <li
                      key={o.tenant_id}
                      className="flex flex-wrap items-center justify-between gap-2 py-2"
                    >
                      <span className="min-w-0 truncate">{o.tenant_name || o.tenant_id}</span>
                      <span className="tabular-nums text-muted-foreground">
                        {t('admin.sharedFleet.usageCounts', undefined, {
                          queued: o.queued,
                          running: o.running,
                          completed: o.completed_24h,
                          failed: o.failed_24h,
                        })}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>{t('admin.sharedFleet.jobsTitle')}</CardTitle>
            <CardDescription>{t('admin.sharedFleet.jobsDesc')}</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={jobColumns}
              data={jobs.data?.data ?? []}
              caption={t('admin.sharedFleet.jobsTitle')}
              getRowId={(j) => j.id}
              error={jobs.error}
              onRetry={() => void jobs.mutate()}
              errorTitle={t('admin.sharedFleet.jobsTitle')}
              // The first read: skeleton rows under a toolbar that stays mounted.
              isLoading={jobs.isLoading && !jobs.data}
              isRefreshing={jobs.isValidating && !!jobs.data}
              refreshingLabel={t('admin.sharedFleet.refreshingJobs', 'Refreshing jobs')}
              showSearch={false}
              showSelectionCount={false}
              manualPagination
              pageCount={jobs.data?.total_pages ?? 1}
              rowCount={jobs.data?.total ?? 0}
              pagination={list.pagination}
              onPaginationChange={list.setPagination}
              pageSizeOptions={[20]}
              paginationNoun={t('admin.sharedFleet.jobsNoun', 'jobs')}
              mobileCards
              toolbarStart={
                <FilterSelect
                  label={t('admin.sharedFleet.col.status')}
                  value={status}
                  foldLabel
                  allLabel={t('admin.sharedFleet.allStatuses')}
                  options={JOB_STATUSES.map((s) => ({
                    value: s,
                    label: t(`admin.sharedFleet.jobStatus.${s}`),
                  }))}
                  onChange={(v) => list.setFilter('status', v)}
                />
              }
              isFiltered={!!status}
              onClearFilters={() => list.setFilter('status', '')}
              emptyState={{
                nothingYet: <EmptyState icon={ListChecks} title={t('admin.sharedFleet.noJobs')} />,
                noMatch: {
                  title: t('admin.sharedFleet.noJobsMatch', 'No job in this status'),
                },
              }}
            />
          </CardContent>
        </Card>
      </div>

      {viewing && (
        <AdminConfirmDialog
          reasonPlaceholder={t(
            'admin.sharedFleet.reasonView',
            'The organization reports a stuck scan, ticket 2231'
          )}
          open
          onOpenChange={(open) => !open && setViewing(null)}
          title={t('admin.sharedFleet.viewTitle')}
          description={
            <p>
              {t('admin.sharedFleet.viewDesc', undefined, {
                org: viewing.tenant_name || viewing.tenant_id,
              })}
            </p>
          }
          confirmLabel={t('admin.sharedFleet.viewConfirm')}
          onConfirm={async (proof) => {
            const d = await viewSharedJob(viewing.id, proof.reason)
            setViewing(null)
            setDetail(d)
          }}
        />
      )}

      <Dialog open={!!detail} onOpenChange={(open) => !open && setDetail(null)}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>{t('admin.sharedFleet.detailTitle')}</DialogTitle>
            <DialogDescription>
              {t('admin.sharedFleet.detailDesc', undefined, {
                org: detail?.job.tenant_name || detail?.job.tenant_id || '',
              })}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <section>
              <h3 className="text-sm font-medium">{t('admin.sharedFleet.targets')}</h3>
              <ul className="mt-1 space-y-0.5">
                {(detail?.targets ?? []).map((target) => (
                  <li key={target} className="font-mono text-xs break-all">
                    {target}
                  </li>
                ))}
              </ul>
            </section>
            <section>
              <h3 className="text-sm font-medium">{t('admin.sharedFleet.logs')}</h3>
              {(detail?.logs ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">{t('admin.sharedFleet.noLogs')}</p>
              ) : (
                <pre className="mt-1 max-h-80 overflow-auto rounded bg-muted p-2 text-xs whitespace-pre-wrap break-all">
                  {(detail?.logs ?? []).map((l) => `${l.ts} ${l.level} ${l.msg}`).join('\n')}
                </pre>
              )}
              {detail?.logs_truncated && (
                <p className="mt-1 text-xs text-muted-foreground">
                  {t('admin.sharedFleet.logsTruncated')}
                </p>
              )}
            </section>
          </DialogBody>
        </DialogContent>
      </Dialog>
    </>
  )
}
