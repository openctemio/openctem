'use client'

/**
 * The Sensors page in "All" mode: everything that scans for the
 * organization in one list (GET /api/v1/fleet): sensors in daemon mode and
 * CI pipelines in runner mode. Each mode keeps its own status: a daemon can
 * be offline, a CI pipeline is fresh or stale and never offline. The API
 * lists each mode only for the permission that reads it.
 */

import { Search } from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  DataTable,
  ErrorState,
  MetricStrip,
  RelativeTime,
  StackedCell,
  type MetricStripItem,
} from '@/features/shared'
import { TonePill } from '@/features/shared/components/tone-pill'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { cn } from '@/lib/utils'
import { useFleet } from '@/features/ci-runners/api/use-ci'
import {
  FleetModeBadge,
  PipelineStatusBadge,
} from '@/features/ci-runners/components/ci-pipeline-cells'
import type { FleetItem, FleetList } from '@/features/ci-runners/types'
import type { SensorState } from '@/lib/api/sensor-types'

import { SENSOR_STATE_META } from '../lib/sensor-state'

function DaemonStatus({ status }: { status?: string }) {
  const meta = SENSOR_STATE_META[status as SensorState]
  if (!meta) return <TonePill tone="muted" label={status || 'Unknown'} />
  return <TonePill tone={meta.tone} label={meta.label} title={meta.description} state={status} />
}

export function fleetColumns(): ColumnDef<FleetItem>[] {
  return [
    {
      id: 'name',
      header: 'Name',
      cell: ({ row }) => (
        <StackedCell
          truncate
          className={cn(row.original.inactive && 'opacity-60')}
          primary={row.original.name}
          secondary={row.original.description}
        />
      ),
    },
    {
      id: 'mode',
      header: 'Mode',
      cell: ({ row }) => <FleetModeBadge mode={row.original.mode} />,
    },
    {
      id: 'role',
      header: 'Role',
      cell: ({ row }) => (
        <span className="text-sm capitalize text-muted-foreground">{row.original.role}</span>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      cell: ({ row }) =>
        row.original.mode === 'runner' ? (
          <PipelineStatusBadge status={row.original.status} />
        ) : (
          <DaemonStatus status={row.original.status} />
        ),
    },
    {
      id: 'last_seen',
      header: 'Last seen',
      cell: ({ row }) => <RelativeTime date={row.original.last_seen_at} />,
    },
    {
      id: 'version',
      header: 'Version',
      cell: ({ row }) => (
        <span className="text-sm tabular-nums text-muted-foreground">
          {row.original.version || '—'}
        </span>
      ),
    },
  ]
}

/** Header counts per mode ("Daemons 3 online · CI 42 pipelines: 37 fresh"). */
export function fleetMetrics(
  data: FleetList | undefined,
  attention: boolean,
  onToggleAttention: () => void
): MetricStripItem[] {
  const d = data?.counts?.daemon
  const r = data?.counts?.runner
  const ds = d?.by_status ?? {}
  const rs = r?.by_status ?? {}
  const items: MetricStripItem[] = []
  if (d) {
    const online = (ds.online ?? 0) + (ds.degraded ?? 0) + (ds.late ?? 0)
    const offline = (ds.offline ?? 0) + (ds.stale ?? 0) + (ds.never_connected ?? 0)
    items.push({
      key: 'daemons',
      label: 'Daemons online',
      value: online,
      hint: `of ${(d.total ?? 0) - (d.inactive ?? 0)}`,
      detail: offline > 0 ? `${offline} offline or stale` : 'every daemon is heartbeating',
    })
  }
  if (r) {
    const active = (r.total ?? 0) - (r.inactive ?? 0)
    items.push({
      key: 'pipelines',
      label: 'CI pipelines fresh',
      value: (rs.fresh ?? 0) + (rs.running ?? 0),
      hint: `of ${active}`,
      detail: `${rs.failing ?? 0} failing · ${(rs.stale ?? 0) + (rs.degraded ?? 0)} stale or degraded`,
    })
  }
  items.push({
    key: 'attention',
    label: 'Needs attention',
    value: (d?.attention ?? 0) + (r?.attention ?? 0),
    tone: 'warning',
    detail: 'offline daemons; failing, stale or degraded pipelines',
    onClick: onToggleAttention,
    active: attention,
  })
  return items
}

export interface FleetAllViewProps {
  toolbarStart?: React.ReactNode
  onOpenDaemon: (id: string) => void
  onOpenRunner: (id: string) => void
}

export function FleetAllView({ toolbarStart, onOpenDaemon, onOpenRunner }: FleetAllViewProps) {
  const [q, setQ] = useUrlFilter('q', '')
  const [attentionParam, setAttention] = useUrlFilter('attention', '')
  const [inactiveParam, setInactive] = useUrlFilter('inactive', '')
  const { pagination, setPagination, setPage } = useListParams({ defaultPageSize: 20 })
  const attention = attentionParam === '1'
  const includeInactive = inactiveParam === '1'
  const { data, error, isLoading, mutate } = useFleet({
    mode: 'all',
    search: q,
    attention,
    includeInactive,
    page: pagination.pageIndex + 1,
    perPage: pagination.pageSize,
  })
  const resetPage = () => setPage(1)

  return (
    <div className="mt-5 space-y-5">
      <MetricStrip
        loading={isLoading && !data}
        items={fleetMetrics(data, attention, () => {
          setAttention(attention ? '' : '1')
          resetPage()
        })}
      />
      {error ? (
        <ErrorState title="the fleet" error={error} onRetry={() => mutate()} />
      ) : (
        <DataTable
          columns={fleetColumns()}
          data={data?.data ?? []}
          isLoading={isLoading}
          manualPagination
          pageCount={data?.total_pages ?? 1}
          rowCount={data?.total ?? 0}
          pagination={pagination}
          onPaginationChange={setPagination}
          getRowId={(it) => `${it.mode}:${it.id}`}
          onRowClick={(it) =>
            it.mode === 'runner' ? onOpenRunner(it.id ?? '') : onOpenDaemon(it.id ?? '')
          }
          showSearch={false}
          paginationNoun="rows"
          emptyMessage="Nothing matches"
          toolbarStart={
            <>
              {toolbarStart}
              <div className="relative min-w-0 flex-1 sm:max-w-xs">
                <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search name, repository or workflow…"
                  aria-label="Search the fleet"
                  value={q}
                  onChange={(e) => {
                    setQ(e.target.value)
                    resetPage()
                  }}
                  className="h-9 ps-9"
                />
              </div>
            </>
          }
          toolbarEnd={
            <div className="flex items-center gap-2">
              <Switch
                id="fleet-inactive"
                checked={includeInactive}
                onCheckedChange={(on) => {
                  setInactive(on ? '1' : '')
                  resetPage()
                }}
              />
              <Label htmlFor="fleet-inactive" className="text-sm font-normal">
                Show inactive
              </Label>
            </div>
          }
        />
      )}
    </div>
  )
}
