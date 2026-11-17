'use client'

import type { SensorGrantSummary } from '@/lib/api/sensor-grant-hooks'
import type * as React from 'react'
import { useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Progress } from '@/components/ui/progress'
import { useTranslation } from '@/context/i18n-provider'
import {
  DataTable,
  DataTableColumnHeader,
  type DataTableRowGroups,
  type DataTableSelectMode,
  type FilterPanelToggleProps,
  type DataTableSearch,
} from '@/features/shared'
import type { DataTableBulk } from '@/features/shared/components/data-table/data-table-selection'

import type { Sensor } from '@/lib/api/sensor-types'
import { sensorRoleOf } from '@/lib/api/sensor-types'
import { SensorStateBadge, sensorStateDetail } from './sensor-state-badge'
import {
  SensorHostCell,
  SensorJobsCell,
  SensorKeyCell,
  SensorNameCell,
  SensorOutboxCell,
  SensorToolsCell,
  SensorVersionCell,
} from './sensor-cells'
import { SensorMobileCard } from './sensor-mobile-card'
import { SensorRowMenu, type SensorRowHandlers } from './sensor-row-menu'
import { SensorContentCell } from './sensor-content-cells'
import { dispatchTools } from '../lib/capabilities'
import { worstContentState } from '../lib/content'
import { normalizeSensorVersion } from '../lib/sensor-version'
import { sensorState, SENSOR_STATES, type FleetThresholds } from '../lib/sensor-state'
import { sensorPolicyOf, type ReleaseChannel } from '../lib/fleet'
import { sensorFacts, sensorReason, VERSION_FACT_KEYS } from '../lib/sensor-facts'
import { cn } from '@/lib/utils'
import { SensorLocalPolicyBadge } from './sensor-local-policy-section'

interface SensorTableProps extends SensorRowHandlers {
  sensors: Sensor[]
  /**
   * The bulk actions of the page (Disable, Delete). Left out for a user who
   * may do neither: the table then has no checkbox column.
   */
  bulk?: DataTableBulk<Sensor>
  /** Phone select mode held by the page (Select is in the page's More). */
  selectMode?: DataTableSelectMode
  /** Bump to clear the selection (e.g. after a bulk delete). */
  resetSelectionKey?: number
  search?: DataTableSearch
  toolbarStart?: React.ReactNode
  toolbarEnd?: React.ReactNode
  /** The active filter chips, in their own row under the toolbar. */
  toolbarBelow?: React.ReactNode
  filterToggle?: FilterPanelToggleProps
  /** The fleet is being read for the first time: skeleton rows under the toolbar. */
  isLoading?: boolean
  /** The fleet read failed: the error takes the rows' place, with Retry. */
  error?: unknown
  onRetry?: () => void
  /** A search or a filter narrows the list (an empty list is then "no match"). */
  isFiltered?: boolean
  onClearFilters?: () => void
  /** State ladder thresholds from GET /sensors/stats. */
  thresholds?: FleetThresholds
  /** The current time (useNow). */
  now: number
  /** Release channel from GET /sensors/stats. */
  channel: ReleaseChannel
  /** Group header rows (zone, role, version). */
  rowGroups?: DataTableRowGroups<Sensor>
  /** Grant summaries by sensor id (GET /sensors/grant-summaries), for the grant flags. */
  grants?: Map<string, SensorGrantSummary>
}

/** CPU / memory as reported; a sensor that reports nothing shows a dash, not 0%. */
function UsageCell({ percent }: { percent: number }) {
  if (!percent) return <span className="text-sm text-muted-foreground">—</span>
  return (
    <div className="flex w-24 items-center gap-2">
      <span className="w-8 text-xs tabular-nums">{percent.toFixed(0)}%</span>
      <Progress value={percent} className="h-1.5 flex-1" />
    </div>
  )
}

/**
 * Off by default, available under Display: the outbox, key, local policy and
 * content columns (most rows read "not reported" or "never expires"; a
 * problem in any of them is the row's reason beside its state instead),
 * metrics most sensors do not report yet (CPU, memory, region) and the role,
 * which the Role filter and grouping carry.
 */
const HIDDEN_BY_DEFAULT = {
  outbox: false,
  key: false,
  policy: false,
  content: false,
  type: false,
  cpuUsage: false,
  memoryUsage: false,
  region: false,
}

/**
 * Column widths (px) and the table-frame width under which a column steps
 * aside (it stays under Display > Columns): Host first, then Tools. With the
 * checkbox column (40), the name's floor (200) and the row menu (48) the
 * default set needs 1104: it fits the frame of a 1440 screen (1114) and,
 * without Host (952), the frame of a 1280 screen (954).
 */
const SENSORS_WIDTH = {
  host: 152,
  status: 200,
  version: 232,
  jobs: 104,
  tools: 128,
  outbox: 152,
  key: 152,
  policy: 136,
  content: 168,
  role: 176,
  usage: 128,
  region: 128,
}
const SENSORS_HIDE_BELOW = { host: 1104, tools: 952 } as const

const STATE_RANK = new Map(SENSOR_STATES.map((s, i) => [s, i]))

const getSensorId = (a: Sensor) => a.id

export function SensorTable({
  sensors,
  onViewSensor,
  onEditSensor,
  onActivateSensor,
  onDeactivateSensor,
  onDeleteSensor,
  onRegenerateKey,
  onRevokeSensor,
  bulk,
  selectMode,
  resetSelectionKey,
  search,
  toolbarStart,
  toolbarEnd,
  toolbarBelow,
  filterToggle,
  isLoading,
  error,
  onRetry,
  isFiltered,
  onClearFilters,
  thresholds,
  now,
  channel,
  rowGroups,
  grants,
}: SensorTableProps) {
  const { t } = useTranslation()
  const handlers = useMemo<SensorRowHandlers>(
    () => ({
      onViewSensor,
      onEditSensor,
      onActivateSensor,
      onDeactivateSensor,
      onDeleteSensor,
      onRegenerateKey,
      onRevokeSensor,
    }),
    [
      onViewSensor,
      onEditSensor,
      onActivateSensor,
      onDeactivateSensor,
      onDeleteSensor,
      onRegenerateKey,
      onRevokeSensor,
    ]
  )
  const columns = useMemo<ColumnDef<Sensor>[]>(
    () => [
      // Rows are one line. The checkbox column is the table's own (`bulk`).
      {
        id: 'name',
        // The row's identity: frozen at the start while the table scrolls sideways.
        meta: { kind: 'name', pin: 'start', minWidth: 200, label: t('sensors.table.col.sensor') },
        enableHiding: false,
        accessorFn: (a) => a.name,
        sortingFn: (a, b) => a.original.name.localeCompare(b.original.name),
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.sensor')} />
        ),
        cell: ({ row }) => (
          <SensorNameCell sensor={row.original} grant={grants?.get(row.original.id)} inline />
        ),
      },
      {
        id: 'host',
        meta: {
          kind: 'text',
          width: SENSORS_WIDTH.host,
          hideBelow: SENSORS_HIDE_BELOW.host,
          label: t('sensors.table.col.host', 'Host'),
        },
        accessorFn: (a) => a.hostname || a.ip_address || '',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.host', 'Host')} />
        ),
        cell: ({ row }) => <SensorHostCell sensor={row.original} />,
      },
      {
        id: 'status',
        meta: { kind: 'text', width: SENSORS_WIDTH.status, label: t('sensors.table.col.status') },
        // Sort by the ladder (online first), not alphabetically.
        accessorFn: (a) => STATE_RANK.get(sensorState(a, now, thresholds)) ?? 0,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.status')} />
        ),
        cell: ({ row }) => {
          const reasons = row.original.health_reasons ?? []
          // The reason in plain words, beside the state: the same facts the
          // phone card lists (outbox, key, policy, version, content) so the
          // columns that hold them can stay hidden until they matter. A
          // sensor with nothing to say shows its heartbeat age there.
          const reason = sensorReason(
            sensorFacts(row.original, { now, thresholds, channel }, t),
            VERSION_FACT_KEYS
          )
          const detail = sensorStateDetail(row.original, now, thresholds, t)
          const hover = [
            ...(reasons.length ? reasons.map((r) => r.message) : reason ? [reason.text] : []),
            ...(detail ? [detail] : []),
          ].join('\n')
          return (
            <span className="flex min-w-0 items-center gap-2" title={hover || undefined}>
              <SensorStateBadge sensor={row.original} now={now} thresholds={thresholds} />
              {reason ? (
                <span
                  data-slot="sensor-reason"
                  className={cn(
                    'min-w-0 truncate text-xs',
                    reason.tone === 'destructive' ? 'text-destructive' : 'text-warning'
                  )}
                >
                  {reason.text}
                </span>
              ) : (
                detail && (
                  <span
                    data-slot="sensor-state-detail"
                    className="min-w-0 truncate text-xs text-muted-foreground"
                  >
                    {detail}
                  </span>
                )
              )}
            </span>
          )
        },
      },
      {
        id: 'version',
        meta: { kind: 'text', width: SENSORS_WIDTH.version, label: t('sensors.table.col.version') },
        accessorFn: (a) => normalizeSensorVersion(a.version) ?? '',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.version')} />
        ),
        cell: ({ row }) => <SensorVersionCell sensor={row.original} channel={channel} inline />,
      },
      {
        id: 'jobs',
        meta: { kind: 'text', width: SENSORS_WIDTH.jobs, label: t('sensors.table.col.jobs') },
        // current_jobs is what the API reports; it never sent active_jobs.
        accessorFn: (a) => a.current_jobs ?? 0,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.jobs')} />
        ),
        cell: ({ row }) => <SensorJobsCell sensor={row.original} />,
      },
      {
        id: 'outbox',
        meta: { kind: 'text', width: SENSORS_WIDTH.outbox, label: t('sensors.table.col.outbox') },
        accessorFn: (a) => a.outbox?.pending_count ?? -1,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.outbox')} />
        ),
        cell: ({ row }) => <SensorOutboxCell sensor={row.original} inline />,
      },
      {
        id: 'key',
        meta: { kind: 'text', width: SENSORS_WIDTH.key, label: t('sensors.table.col.key') },
        accessorFn: (a) =>
          a.key_expires_at ? new Date(a.key_expires_at).getTime() : Number.MAX_SAFE_INTEGER,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.key')} />
        ),
        cell: ({ row }) => (
          <span className="flex min-w-0 items-center whitespace-nowrap [&>span]:flex-nowrap">
            <SensorKeyCell sensor={row.original} now={now} />
          </span>
        ),
      },
      {
        id: 'tools',
        meta: {
          kind: 'text',
          width: SENSORS_WIDTH.tools,
          hideBelow: SENSORS_HIDE_BELOW.tools,
          label: t('sensors.table.col.tools'),
        },
        accessorFn: (a) => dispatchTools(a).join(', '),
        enableSorting: false,
        header: t('sensors.table.col.tools'),
        cell: ({ row }) => (
          <span className="block truncate">
            <SensorToolsCell tools={dispatchTools(row.original)} />
          </span>
        ),
      },
      {
        id: 'policy',
        meta: {
          kind: 'status',
          width: SENSORS_WIDTH.policy,
          label: t('sensors.table.col.localPolicy'),
        },
        accessorFn: (a) => sensorPolicyOf(a),
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.policy')} />
        ),
        cell: ({ row }) => <SensorLocalPolicyBadge sensor={row.original} />,
      },
      {
        id: 'content',
        meta: { kind: 'text', width: SENSORS_WIDTH.content, label: t('sensors.table.col.content') },
        accessorFn: (a) => worstContentState(a.content) ?? '',
        enableSorting: false,
        header: t('sensors.table.col.content'),
        cell: ({ row }) => <SensorContentCell sensor={row.original} now={now} />,
      },
      {
        id: 'type',
        meta: { kind: 'text', width: SENSORS_WIDTH.role, label: t('sensors.table.col.role') },
        accessorFn: (a) => a.type,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.role')} />
        ),
        cell: ({ row }) => (
          <span className="block truncate text-sm">
            {sensorRoleOf(row.original.type) === 'collector'
              ? t('sensors.table.roleCollector')
              : t('sensors.table.roleScanner')}
            <span className="text-muted-foreground">
              {', '}
              {t(`sensors.table.type.${row.original.type}`, row.original.type)}
            </span>
          </span>
        ),
      },
      {
        id: 'cpuUsage',
        meta: { kind: 'text', width: SENSORS_WIDTH.usage, label: t('sensors.table.col.cpu') },
        accessorFn: (a) => a.cpu_percent || 0,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.cpu')} />
        ),
        cell: ({ getValue }) => <UsageCell percent={getValue<number>()} />,
      },
      {
        id: 'memoryUsage',
        meta: { kind: 'text', width: SENSORS_WIDTH.usage, label: t('sensors.table.col.memory') },
        accessorFn: (a) => a.memory_percent || 0,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.memory')} />
        ),
        cell: ({ getValue }) => <UsageCell percent={getValue<number>()} />,
      },
      {
        id: 'region',
        meta: { kind: 'text', width: SENSORS_WIDTH.region, label: t('sensors.table.col.region') },
        // Only what the sensor reported; nothing invented.
        accessorFn: (a) => a.region || '',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.region')} />
        ),
        cell: ({ getValue }) =>
          getValue<string>() ? (
            <span className="block truncate text-sm">{getValue<string>()}</span>
          ) : (
            <span className="text-sm text-muted-foreground">—</span>
          ),
      },
      {
        id: 'actions',
        meta: { kind: 'actions' },
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => <SensorRowMenu sensor={row.original} {...handlers} />,
      },
    ],
    [handlers, thresholds, now, channel, grants, t]
  )

  return (
    <DataTable
      columns={columns}
      data={sensors}
      getRowId={getSensorId}
      showSearch={false}
      onRowClick={onViewSensor}
      // No bulk action for this user: no checkbox column either.
      bulk={bulk}
      selectMode={selectMode}
      resetSelectionKey={resetSelectionKey}
      showSelectionCount={false}
      filterToggle={filterToggle}
      search={search}
      toolbarStart={toolbarStart}
      toolbarEnd={toolbarEnd}
      toolbarBelow={toolbarBelow}
      // The first read: skeleton rows under a toolbar that stays mounted. A
      // failed read keeps the toolbar too; the error takes the rows' place.
      isLoading={isLoading}
      error={error}
      onRetry={onRetry}
      errorTitle={t('sensors.list.errorTitle')}
      isFiltered={isFiltered}
      onClearFilters={onClearFilters}
      // A fleet with no sensor at all is the page's own first-run block
      // (how to add one), so an empty table here is always "no match".
      emptyState={{
        nothingYet: null,
        noMatch: {
          title: t('sensors.table.emptyMessage'),
          hint: t('sensors.table.emptyDescription'),
        },
      }}
      initialColumnVisibility={HIDDEN_BY_DEFAULT}
      // A fleet is small; grouping reads best on one page.
      pageSize={50}
      paginationNoun={t('sensors.list.noun', 'sensors')}
      rowGroups={rowGroups}
      mobileRow={(sensor, selection) => (
        <SensorMobileCard
          sensor={sensor}
          now={now}
          thresholds={thresholds}
          channel={channel}
          onOpen={onViewSensor}
          grant={grants?.get(sensor.id)}
          selection={selection}
          actions={<SensorRowMenu sensor={sensor} {...handlers} />}
        />
      )}
    />
  )
}
