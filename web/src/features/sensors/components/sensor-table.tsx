'use client'

import type { SensorGrantSummary } from '@/lib/api/sensor-grant-hooks'
import type * as React from 'react'
import { useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Checkbox } from '@/components/ui/checkbox'
import { Progress } from '@/components/ui/progress'
import { Eye, Settings, KeyRound, Trash2, Power, PowerOff } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Permission } from '@/lib/permissions'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  type DataTableRowGroups,
  type FilterPanelToggleProps,
  type RowAction,
} from '@/features/shared'

import type { Sensor } from '@/lib/api/sensor-types'
import { sensorRoleOf } from '@/lib/api/sensor-types'
import { SENSOR_TYPE_LABELS } from './sensor-type-icon'
import { SensorStateBadge } from './sensor-state-badge'
import {
  SensorJobsCell,
  SensorKeyCell,
  SensorNameCell,
  SensorOutboxCell,
  SensorToolsCell,
  SensorVersionCell,
} from './sensor-cells'
import { SensorMobileCard } from './sensor-mobile-card'
import { SensorContentCell } from './sensor-content-cells'
import { dispatchTools } from '../lib/capabilities'
import { worstContentState } from '../lib/content'
import { normalizeSensorVersion } from '../lib/sensor-version'
import { sensorState, SENSOR_STATES, type FleetThresholds } from '../lib/sensor-state'
import { sensorPolicyOf, type ReleaseChannel } from '../lib/fleet'
import { SensorLocalPolicyBadge } from './sensor-local-policy-section'

interface SensorTableProps {
  sensors: Sensor[]
  onViewSensor: (sensor: Sensor) => void
  onEditSensor: (sensor: Sensor) => void
  onActivateSensor: (sensor: Sensor) => void
  onDeactivateSensor: (sensor: Sensor) => void
  onDeleteSensor: (sensor: Sensor) => void
  onRegenerateKey: (sensor: Sensor) => void
  /** Selected rows, for the page's bulk-action bar. */
  onSelectionChange?: (sensors: Sensor[]) => void
  /** Bump to clear the selection (e.g. after a bulk delete). */
  resetSelectionKey?: number
  toolbarStart?: React.ReactNode
  toolbarEnd?: React.ReactNode
  filterToggle?: FilterPanelToggleProps
  emptyMessage?: string
  emptyDescription?: string
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
 * Off by default, available under Columns: metrics most sensors do not report
 * yet (CPU, memory, region; showing 0% and an invented "local" for every
 * sensor said nothing) and the role, which the Role filter and grouping carry.
 */
const HIDDEN_BY_DEFAULT = { type: false, cpuUsage: false, memoryUsage: false, region: false }

const STATE_RANK = new Map(SENSOR_STATES.map((s, i) => [s, i]))

export function SensorTable({
  sensors,
  onViewSensor,
  onEditSensor,
  onActivateSensor,
  onDeactivateSensor,
  onDeleteSensor,
  onRegenerateKey,
  onSelectionChange,
  resetSelectionKey,
  toolbarStart,
  toolbarEnd,
  filterToggle,
  emptyMessage,
  emptyDescription,
  thresholds,
  now,
  channel,
  rowGroups,
  grants,
}: SensorTableProps) {
  const { t } = useTranslation()
  const columns = useMemo<ColumnDef<Sensor>[]>(
    () => [
      {
        id: 'select',
        header: ({ table }) => (
          <Checkbox
            checked={
              table.getIsAllPageRowsSelected() ||
              (table.getIsSomePageRowsSelected() && 'indeterminate')
            }
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
            aria-label={t('sensors.table.selectAll')}
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(!!value)}
            aria-label={t('sensors.table.selectRow')}
            onClick={(e) => e.stopPropagation()}
          />
        ),
        enableSorting: false,
        enableHiding: false,
      },
      {
        id: 'name',
        meta: { label: t('sensors.table.col.sensor') },
        accessorFn: (a) => a.name,
        sortingFn: (a, b) => a.original.name.localeCompare(b.original.name),
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.sensor')} />
        ),
        cell: ({ row }) => (
          <SensorNameCell sensor={row.original} grant={grants?.get(row.original.id)} />
        ),
      },
      {
        id: 'status',
        meta: { label: t('sensors.table.col.status') },
        // Sort by the ladder (online first), not alphabetically.
        accessorFn: (a) => STATE_RANK.get(sensorState(a, now, thresholds)) ?? 0,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.status')} />
        ),
        cell: ({ row }) => {
          const reasons = row.original.health_reasons ?? []
          return (
            <span title={reasons.length ? reasons.map((r) => r.message).join('\n') : undefined}>
              <SensorStateBadge
                sensor={row.original}
                now={now}
                thresholds={thresholds}
                withLastSeen
              />
            </span>
          )
        },
      },
      {
        id: 'version',
        meta: { label: t('sensors.table.col.version') },
        accessorFn: (a) => normalizeSensorVersion(a.version) ?? '',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.version')} />
        ),
        cell: ({ row }) => <SensorVersionCell sensor={row.original} channel={channel} />,
      },
      {
        id: 'jobs',
        meta: { label: t('sensors.table.col.jobs') },
        // current_jobs is what the API reports; it never sent active_jobs.
        accessorFn: (a) => a.current_jobs ?? 0,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.jobs')} />
        ),
        cell: ({ row }) => <SensorJobsCell sensor={row.original} />,
      },
      {
        id: 'outbox',
        meta: { label: t('sensors.table.col.outbox') },
        accessorFn: (a) => a.outbox?.pending_count ?? -1,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.outbox')} />
        ),
        cell: ({ row }) => <SensorOutboxCell sensor={row.original} />,
      },
      {
        id: 'key',
        meta: { label: t('sensors.table.col.key') },
        accessorFn: (a) =>
          a.key_expires_at ? new Date(a.key_expires_at).getTime() : Number.MAX_SAFE_INTEGER,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.key')} />
        ),
        cell: ({ row }) => <SensorKeyCell sensor={row.original} now={now} />,
      },
      {
        id: 'tools',
        meta: { label: t('sensors.table.col.tools') },
        accessorFn: (a) => dispatchTools(a).join(', '),
        enableSorting: false,
        header: t('sensors.table.col.tools'),
        cell: ({ row }) => <SensorToolsCell tools={dispatchTools(row.original)} />,
      },
      {
        id: 'policy',
        meta: { label: t('sensors.table.col.localPolicy') },
        accessorFn: (a) => sensorPolicyOf(a),
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.policy')} />
        ),
        cell: ({ row }) => <SensorLocalPolicyBadge sensor={row.original} />,
      },
      {
        id: 'content',
        meta: { label: t('sensors.table.col.content') },
        accessorFn: (a) => worstContentState(a.content) ?? '',
        enableSorting: false,
        header: t('sensors.table.col.content'),
        cell: ({ row }) => <SensorContentCell sensor={row.original} now={now} />,
      },
      {
        id: 'type',
        meta: { label: t('sensors.table.col.role') },
        accessorFn: (a) => SENSOR_TYPE_LABELS[a.type] ?? a.type,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.role')} />
        ),
        cell: ({ row }) => (
          <span className="text-sm">
            {sensorRoleOf(row.original.type) === 'collector'
              ? t('sensors.table.roleCollector')
              : t('sensors.table.roleScanner')}
            <span className="text-muted-foreground">
              {' · '}
              {t(
                `sensors.table.type.${row.original.type}`,
                SENSOR_TYPE_LABELS[row.original.type] ?? row.original.type
              )}
            </span>
          </span>
        ),
      },
      {
        id: 'cpuUsage',
        meta: { label: t('sensors.table.col.cpu') },
        accessorFn: (a) => a.cpu_percent || 0,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.cpu')} />
        ),
        cell: ({ getValue }) => <UsageCell percent={getValue<number>()} />,
      },
      {
        id: 'memoryUsage',
        meta: { label: t('sensors.table.col.memory') },
        accessorFn: (a) => a.memory_percent || 0,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.memory')} />
        ),
        cell: ({ getValue }) => <UsageCell percent={getValue<number>()} />,
      },
      {
        id: 'region',
        meta: { label: t('sensors.table.col.region') },
        // Only what the sensor reported; nothing invented.
        accessorFn: (a) => a.region || '',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sensors.table.col.region')} />
        ),
        cell: ({ getValue }) =>
          getValue<string>() ? (
            <span className="text-sm">{getValue<string>()}</span>
          ) : (
            <span className="text-sm text-muted-foreground">—</span>
          ),
      },
      {
        id: 'actions',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const sensor = row.original
          // Editing, keys and lifecycle are admin actions (sensors:write /
          // sensors:delete, admins and owners only since api#669).
          const actions: RowAction[] = [
            {
              label: t('sensors.table.action.viewDetails'),
              icon: Eye,
              onClick: () => onViewSensor(sensor),
            },
            {
              label: t('sensors.table.action.edit'),
              icon: Settings,
              onClick: () => onEditSensor(sensor),
              permission: Permission.SensorsWrite,
            },
            {
              label: t('sensors.table.action.rotateKey'),
              icon: KeyRound,
              onClick: () => onRegenerateKey(sensor),
              permission: Permission.SensorsWrite,
            },
          ]
          if (sensor.status === 'disabled' || sensor.status === 'revoked') {
            actions.push({
              label: t('sensors.table.action.enable'),
              icon: Power,
              onClick: () => onActivateSensor(sensor),
              separatorBefore: true,
              permission: Permission.SensorsWrite,
            })
          } else if (sensor.status === 'active') {
            actions.push({
              label: t('sensors.table.action.disable'),
              icon: PowerOff,
              onClick: () => onDeactivateSensor(sensor),
              separatorBefore: true,
              permission: Permission.SensorsWrite,
            })
          }
          actions.push({
            label: t('sensors.table.action.delete'),
            icon: Trash2,
            onClick: () => onDeleteSensor(sensor),
            destructive: true,
            separatorBefore: true,
            permission: Permission.SensorsDelete,
          })
          return <DataTableRowActions actions={actions} />
        },
      },
    ],
    [
      onViewSensor,
      onEditSensor,
      onActivateSensor,
      onDeactivateSensor,
      onDeleteSensor,
      onRegenerateKey,
      thresholds,
      now,
      channel,
      grants,
      t,
    ]
  )

  return (
    <DataTable
      columns={columns}
      data={sensors}
      getRowId={(a) => a.id}
      showSearch={false}
      onRowClick={onViewSensor}
      onSelectionChange={onSelectionChange}
      resetSelectionKey={resetSelectionKey}
      showSelectionCount={false}
      filterToggle={filterToggle}
      toolbarStart={toolbarStart}
      toolbarEnd={toolbarEnd}
      emptyMessage={emptyMessage ?? t('sensors.table.emptyMessage')}
      emptyDescription={emptyDescription ?? t('sensors.table.emptyDescription')}
      initialColumnVisibility={HIDDEN_BY_DEFAULT}
      // A fleet is small; grouping reads best on one page.
      pageSize={50}
      pageSizeOptions={[25, 50, 100]}
      rowGroups={rowGroups}
      mobileRow={(sensor) => (
        <SensorMobileCard
          sensor={sensor}
          now={now}
          thresholds={thresholds}
          channel={channel}
          onOpen={onViewSensor}
          grant={grants?.get(sensor.id)}
        />
      )}
    />
  )
}
