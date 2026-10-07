'use client'

/**
 * Shared pieces for a tool's availability (api tool-availability.md): the
 * status pill, the "n/m online" sensors cell with its sensor list, and the
 * sensor list itself. Used by the Tools page table and detail sheet; the
 * pickers use toolUnavailableReason from ../lib/availability.
 */

import { Server } from 'lucide-react'

import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { TonePill } from '@/features/shared'
import type { ToolAvailabilityItem, ToolAvailabilitySensor } from '@/lib/api/tool-types'
import { cn } from '@/lib/utils'

import {
  TOOL_EXCLUSION_LABEL,
  TOOL_STATUS_META,
  sensorsLabel,
  toolUnavailableReason,
} from '../lib/availability'

/** The derived status as a pill; the tooltip says what it means and why. */
export function ToolStatusBadge({
  item,
  className,
}: {
  item: ToolAvailabilityItem
  className?: string
}) {
  const meta = TOOL_STATUS_META[item.status]
  const reason = toolUnavailableReason(item)
  return (
    <TonePill
      tone={meta.tone}
      label={meta.label}
      title={reason ? `${meta.description} ${reason}.` : meta.description}
      state={item.status}
      className={className}
    />
  )
}

/** One sensor row: name, state, zones, version and why it may not run the tool. */
function SensorRow({ sensor }: { sensor: ToolAvailabilitySensor }) {
  return (
    <li className="flex items-start justify-between gap-3 py-1.5">
      <div className="min-w-0">
        <p className={cn('truncate text-sm', !sensor.online && 'text-muted-foreground')}>
          {sensor.name}
        </p>
        <p className="truncate text-xs text-muted-foreground">
          {sensor.online ? 'Online' : sensor.state.replace(/_/g, ' ')}
          {sensor.zones.length > 0 && ` · ${sensor.zones.map((z) => z.name).join(', ')}`}
        </p>
        {sensor.excluded && (
          <p className="text-xs text-warning" title={sensor.excluded_detail}>
            Has it, but {TOOL_EXCLUSION_LABEL[sensor.excluded]}
          </p>
        )}
      </div>
      {sensor.version && (
        <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
          {sensor.version}
        </span>
      )}
    </li>
  )
}

/** The sensors that report a tool, online first (as the API orders them). */
export function ToolSensorList({
  item,
  className,
}: {
  item: Pick<ToolAvailabilityItem, 'sensors' | 'sensors_total' | 'sensors_excluded'>
  className?: string
}) {
  if (item.sensors.length === 0) {
    const n = item.sensors_total + item.sensors_excluded
    return (
      <p className={cn('text-sm text-muted-foreground', className)}>
        {n === 0
          ? 'No sensor reports this tool.'
          : `${n} sensor(s) report this tool. Listing them needs permission to read sensors.`}
      </p>
    )
  }
  return (
    <ul className={cn('divide-y', className)} aria-label="Sensors with this tool">
      {item.sensors.map((s) => (
        <SensorRow key={s.id} sensor={s} />
      ))}
    </ul>
  )
}

/** "n/m online" with the sensor list in a popover. */
export function ToolSensorsCell({ item }: { item: ToolAvailabilityItem }) {
  const label = sensorsLabel(item)
  const reported = item.sensors_total + item.sensors_excluded
  if (reported === 0) {
    return <span className="text-xs text-muted-foreground">none</span>
  }
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="inline-flex items-center gap-1.5 rounded px-1 text-sm tabular-nums hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label={`Sensors with ${item.name}: ${label}`}
          onClick={(e) => e.stopPropagation()}
        >
          <Server className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
          <span className={cn(item.sensors_online === 0 && 'text-muted-foreground')}>{label}</span>
          {item.sensors_excluded > 0 && (
            <span className="text-xs text-warning">+{item.sensors_excluded} not allowed</span>
          )}
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 p-3" onClick={(e) => e.stopPropagation()}>
        <p className="mb-1 text-xs font-medium text-muted-foreground">Sensors with {item.name}</p>
        <ToolSensorList item={item} />
      </PopoverContent>
    </Popover>
  )
}
