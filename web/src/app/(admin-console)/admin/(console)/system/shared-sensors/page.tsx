'use client'

/**
 * System > Shared sensors (api docs/rfcs/RFC-100-shared-sensors.md §12): the
 * instance sensors with their state, queue aggregates per tool lane and per
 * organization, and job metadata. Any administrator reads. A job's targets
 * and logs need a reason (super or operations administrator; the API audits
 * the view); pause, resume and retire need a super admin, a reason and a
 * fresh authenticator code. Results and findings are never shown here.
 */

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Eye, Pause, Play, Power } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { DataTable, ErrorState, PageHeader, RelativeTime, StackedCell } from '@/features/shared'
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
} from '@/features/admin-console/api/use-shared-fleet'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { AdminConfirmDialog } from '@/features/admin-console/components/admin-confirm-dialog'
import { adminCan } from '@/features/admin-console/types'

const JOB_STATUSES = [
  'pending',
  'acknowledged',
  'running',
  'completed',
  'failed',
  'canceled',
  'expired',
]
const ALL = 'all'

export default function SharedSensorsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const isSuper = adminCan(me.role, 'super_admin')
  const canView = adminCan(me.role, 'ops_admin')
  const fleet = useSharedFleet()
  const queue = useSharedQueue()
  const [page, setPage] = useState(1)
  const [status, setStatus] = useState('')
  const jobs = useSharedJobs(page, status)
  const [acting, setActing] = useState<{
    sensor: SharedFleetSensor
    action: SharedSensorAction
  } | null>(null)
  const [viewing, setViewing] = useState<SharedJob | null>(null)
  const [detail, setDetail] = useState<SharedJobDetail | null>(null)

  const sensorColumns = useMemo<ColumnDef<SharedFleetSensor>[]>(
    () => [
      {
        accessorKey: 'name',
        header: t('admin.sharedFleet.col.sensor'),
        cell: ({ row }) => (
          <StackedCell
            primary={row.original.name}
            secondary={row.original.region || t('admin.sharedFleet.noRegion')}
          />
        ),
      },
      {
        accessorKey: 'status',
        header: t('admin.sharedFleet.col.status'),
        cell: ({ row }) => (
          <div className="flex flex-wrap gap-1">
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
        cell: ({ row }) => <span className="font-mono text-xs">{row.original.version || '-'}</span>,
      },
      {
        id: 'tools',
        header: t('admin.sharedFleet.col.tools'),
        cell: ({ row }) => (
          <div className="flex max-w-xs flex-wrap gap-1">
            {row.original.tools.length === 0 ? (
              <span className="text-xs text-muted-foreground">-</span>
            ) : (
              row.original.tools.map((tool) => (
                <span key={tool} className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                  {tool}
                </span>
              ))
            )}
          </div>
        ),
      },
      {
        accessorKey: 'current_jobs',
        header: t('admin.sharedFleet.col.jobs'),
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
        cell: ({ row }) =>
          row.original.last_seen_at ? (
            <RelativeTime date={row.original.last_seen_at} className="text-sm" />
          ) : (
            <span className="text-sm text-muted-foreground">{t('admin.sharedFleet.never')}</span>
          ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => {
          const s = row.original
          if (!isSuper || s.status === 'revoked') return null
          return (
            <div className="flex flex-wrap justify-end gap-1">
              {s.status === 'active' ? (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setActing({ sensor: s, action: 'pause' })}
                >
                  <Pause className="me-1 size-4" aria-hidden />
                  {t('admin.sharedFleet.pause')}
                </Button>
              ) : (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setActing({ sensor: s, action: 'resume' })}
                >
                  <Play className="me-1 size-4" aria-hidden />
                  {t('admin.sharedFleet.resume')}
                </Button>
              )}
              <Button
                size="sm"
                variant="outline"
                onClick={() => setActing({ sensor: s, action: 'retire' })}
              >
                <Power className="me-1 size-4" aria-hidden />
                {t('admin.sharedFleet.retire')}
              </Button>
            </div>
          )
        },
      },
    ],
    [t, isSuper]
  )

  const jobColumns = useMemo<ColumnDef<SharedJob>[]>(
    () => [
      {
        accessorKey: 'tenant_name',
        header: t('admin.sharedFleet.col.organization'),
        cell: ({ row }) => <span>{row.original.tenant_name || row.original.tenant_id}</span>,
      },
      {
        accessorKey: 'tool',
        header: t('admin.sharedFleet.col.tool'),
        cell: ({ row }) => (
          <span className="font-mono text-xs">{row.original.tool || row.original.type}</span>
        ),
      },
      {
        accessorKey: 'status',
        header: t('admin.sharedFleet.col.status'),
        cell: ({ row }) => (
          <Badge variant="outline">
            {t(`admin.sharedFleet.jobStatus.${row.original.status}`, row.original.status)}
          </Badge>
        ),
      },
      {
        accessorKey: 'sensor_name',
        header: t('admin.sharedFleet.col.sensor'),
        cell: ({ row }) => <span className="text-sm">{row.original.sensor_name || '-'}</span>,
      },
      {
        accessorKey: 'created_at',
        header: t('admin.sharedFleet.col.created'),
        cell: ({ row }) => <RelativeTime date={row.original.created_at} className="text-sm" />,
      },
      {
        id: 'view',
        header: '',
        cell: ({ row }) =>
          canView ? (
            <Button size="sm" variant="ghost" onClick={() => setViewing(row.original)}>
              <Eye className="me-1 size-4" aria-hidden />
              {t('admin.sharedFleet.viewJob')}
            </Button>
          ) : null,
      },
    ],
    [t, canView]
  )

  const actionText: Record<
    SharedSensorAction,
    { title: string; desc: string; confirm: string; done: string }
  > = {
    pause: {
      title: 'admin.sharedFleet.pauseTitle',
      desc: 'admin.sharedFleet.pauseDesc',
      confirm: 'admin.sharedFleet.pause',
      done: 'admin.sharedFleet.paused',
    },
    resume: {
      title: 'admin.sharedFleet.resumeTitle',
      desc: 'admin.sharedFleet.resumeDesc',
      confirm: 'admin.sharedFleet.resume',
      done: 'admin.sharedFleet.resumed',
    },
    retire: {
      title: 'admin.sharedFleet.retireTitle',
      desc: 'admin.sharedFleet.retireDesc',
      confirm: 'admin.sharedFleet.retire',
      done: 'admin.sharedFleet.retired',
    },
  }

  return (
    <Main>
      <PageHeader title={t('admin.sharedFleet.title')} description={t('admin.sharedFleet.desc')} />
      <div className="mt-5 space-y-5">
        <Card>
          <CardHeader>
            <CardTitle>{t('admin.sharedFleet.fleetTitle')}</CardTitle>
            <CardDescription>{t('admin.sharedFleet.fleetDesc')}</CardDescription>
          </CardHeader>
          <CardContent>
            {fleet.error ? (
              <ErrorState
                title={t('admin.sharedFleet.fleetTitle')}
                error={fleet.error}
                onRetry={() => void fleet.mutate()}
              />
            ) : (
              <DataTable
                columns={sensorColumns}
                data={fleet.data?.sensors ?? []}
                getRowId={(s) => s.id}
                isLoading={fleet.isLoading}
                showSearch={false}
                showColumnToggle={false}
                showSelectionCount={false}
                showPagination={false}
                mobileCards
                emptyMessage={t('admin.sharedFleet.noSensors')}
              />
            )}
          </CardContent>
        </Card>

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
            {jobs.error ? (
              <ErrorState
                title={t('admin.sharedFleet.jobsTitle')}
                error={jobs.error}
                onRetry={() => void jobs.mutate()}
              />
            ) : (
              <DataTable
                columns={jobColumns}
                data={jobs.data?.data ?? []}
                getRowId={(j) => j.id}
                isLoading={jobs.isLoading}
                showSearch={false}
                showColumnToggle={false}
                showSelectionCount={false}
                manualPagination
                pageCount={jobs.data?.total_pages ?? 1}
                rowCount={jobs.data?.total ?? 0}
                pagination={{ pageIndex: page - 1, pageSize: 20 }}
                onPaginationChange={(p) => setPage(p.pageIndex + 1)}
                pageSizeOptions={[20]}
                mobileCards
                toolbarStart={
                  <Select
                    value={status || ALL}
                    onValueChange={(v) => {
                      setStatus(v === ALL ? '' : v)
                      setPage(1)
                    }}
                  >
                    <SelectTrigger
                      className="w-44"
                      aria-label={t('admin.sharedFleet.statusFilter')}
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={ALL}>{t('admin.sharedFleet.allStatuses')}</SelectItem>
                      {JOB_STATUSES.map((s) => (
                        <SelectItem key={s} value={s}>
                          {t(`admin.sharedFleet.jobStatus.${s}`)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                }
                emptyMessage={t('admin.sharedFleet.noJobs')}
              />
            )}
          </CardContent>
        </Card>
      </div>

      {acting && (
        <AdminConfirmDialog
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

      {viewing && (
        <AdminConfirmDialog
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
    </Main>
  )
}
