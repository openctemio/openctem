'use client'

import type { SensorGrantSummary } from '@/lib/api/sensor-grant-hooks'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { Sensor } from '@/lib/api/sensor-types'

import { SensorStateBadge } from './sensor-state-badge'
import { ConfigHealthTag, ProtocolTag, SensorGrantTags, SensorPostureTag } from './sensor-cells'
import { sensorFacts } from '../lib/sensor-facts'
import type { FleetThresholds } from '../lib/sensor-state'
import type { ReleaseChannel } from '../lib/fleet'

/**
 * A sensor on a phone: name and address, the state on the right, then the few
 * facts that need attention first (results waiting, version, key), the
 * heartbeat age and the jobs.
 */
export function SensorMobileCard({
  sensor,
  now,
  thresholds,
  channel,
  onOpen,
  grant,
}: {
  sensor: Sensor
  /** Grant flags (legacy broad, New). */
  grant?: SensorGrantSummary
  now: number
  thresholds?: FleetThresholds
  channel: ReleaseChannel
  onOpen: (sensor: Sensor) => void
}) {
  const { t } = useTranslation()
  const facts = sensorFacts(sensor, { now, thresholds, channel }, t)

  return (
    <button
      type="button"
      onClick={() => onOpen(sensor)}
      className="flex w-full flex-col gap-2 px-3 py-3 text-start hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
    >
      <span className="flex w-full items-start justify-between gap-2">
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-medium">{sensor.name}</span>
          {sensor.ip_address || sensor.hostname ? (
            <span className="truncate font-mono text-xs text-muted-foreground">
              {sensor.ip_address || sensor.hostname}
            </span>
          ) : null}
        </span>
        <SensorStateBadge sensor={sensor} now={now} thresholds={thresholds} />
      </span>
      {/* A tag, not a full-width bar: the card is a column flexbox. */}
      <span className="flex flex-wrap items-center gap-1.5 self-start">
        <ProtocolTag sensor={sensor} />
        <ConfigHealthTag health={sensor.config_health} />
        <SensorPostureTag sensor={sensor} />
        {sensor.status !== 'revoked' && <SensorGrantTags grant={grant} />}
      </span>
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
    </button>
  )
}
