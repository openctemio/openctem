'use client'

import type * as React from 'react'

import type { SensorGrantSummary } from '@/lib/api/sensor-grant-hooks'

import { Checkbox } from '@/components/ui/checkbox'
import { useTranslation } from '@/context/i18n-provider'
import type { MobileRowSelection } from '@/features/shared'
import { cn } from '@/lib/utils'
import type { Sensor } from '@/lib/api/sensor-types'

import { SensorStateBadge } from './sensor-state-badge'
import { SensorFlags, sensorFlags } from './sensor-cells'
import { sensorFacts } from '../lib/sensor-facts'
import type { FleetThresholds } from '../lib/sensor-state'
import type { ReleaseChannel } from '../lib/fleet'

/**
 * A sensor on a phone, in fixed slots so every card reads the same way:
 *
 *   [ ] Name ............................ State  [...]
 *       address or host
 *       marks (protocol, setup, posture, grant), only those that apply
 *       the facts that need attention, the heartbeat age and the jobs
 *
 * A tap on the card opens the sensor (the row menu's "View details" does the
 * same for a keyboard); the checkbox (in select mode) and the row menu act on
 * their own.
 */
export function SensorMobileCard({
  sensor,
  now,
  thresholds,
  channel,
  onOpen,
  grant,
  selection,
  actions,
}: {
  sensor: Sensor
  /** Grant flags (legacy broad, New). */
  grant?: SensorGrantSummary
  now: number
  thresholds?: FleetThresholds
  channel: ReleaseChannel
  onOpen: (sensor: Sensor) => void
  /** The table's selection for this row (select mode on a phone). */
  selection?: MobileRowSelection
  /** The row menu, the same one the table row has. */
  actions?: React.ReactNode
}) {
  const { t } = useTranslation()
  const facts = sensorFacts(sensor, { now, thresholds, channel }, t)

  return (
    <div
      data-slot="sensor-card"
      data-state={selection?.selected ? 'selected' : undefined}
      className="flex w-full min-w-0 cursor-pointer items-start gap-3 px-3 py-3 hover:bg-muted/50 data-[state=selected]:bg-muted"
      onClick={(e) => {
        if (
          (e.target as HTMLElement).closest('button, a[href], [role="checkbox"], [role="menuitem"]')
        )
          return
        onOpen(sensor)
      }}
    >
      {selection?.selectable && (
        <Checkbox
          className="mt-0.5 shrink-0"
          checked={selection.selected}
          onCheckedChange={(v) => selection.onSelectedChange(!!v)}
          aria-label={t('sensors.table.selectNamed', 'Select sensor {name}', { name: sensor.name })}
        />
      )}
      <div className="flex min-w-0 flex-1 flex-col gap-2">
        <div className="flex w-full items-start gap-2">
          <div data-slot="sensor-card-title" className="flex min-w-0 flex-1 flex-col">
            <span data-cut-tooltip title={sensor.name} className="max-w-full truncate font-medium">
              {sensor.name}
            </span>
            {sensor.ip_address || sensor.hostname ? (
              <span className="max-w-full font-mono text-xs text-muted-foreground [overflow-wrap:anywhere]">
                {sensor.ip_address || sensor.hostname}
              </span>
            ) : null}
          </div>
          <SensorStateBadge sensor={sensor} now={now} thresholds={thresholds} />
          {actions && <div className="-my-1 shrink-0">{actions}</div>}
        </div>
        {/* Every mark, in the list's one look, wrapping; no line when none applies. */}
        <SensorFlags flags={sensorFlags(sensor, grant, t)} />
        {facts.length > 0 && (
          <span className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
            {facts.map((f) => (
              <span
                key={`${f.key}:${f.text}`}
                className={cn(
                  f.tone === 'warning' && 'text-warning',
                  f.tone === 'destructive' && 'text-destructive'
                )}
              >
                {f.text}
              </span>
            ))}
          </span>
        )}
      </div>
    </div>
  )
}
