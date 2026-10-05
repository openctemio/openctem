'use client'

import type { Sensor } from '@/lib/api/sensor-types'
import { TonePill } from '@/features/shared/components/tone-pill'

import { formatDurationShort } from '../lib/format'
import { SENSOR_STATE_META, sensorState, type FleetThresholds } from '../lib/sensor-state'

function ago(iso: string | undefined | null, now: number): string | null {
  if (!iso) return null
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return null
  // A heartbeat a few seconds "in the future" (clock skew) reads as just now.
  if (t >= now - 1000) return 'just now'
  return `${formatDurationShort((now - t) / 1000)} ago`
}

/**
 * The line under the state: how long ago, in the words that fit the state
 * ("heartbeat 4s ago", "last run 3h ago").
 */
export function sensorStateDetail(
  sensor: Pick<Sensor, 'last_seen_at' | 'created_at'> & Parameters<typeof sensorState>[0],
  now: number = Date.now(),
  thresholds?: FleetThresholds
): string | null {
  const state = sensorState(sensor, now, thresholds)
  const seen = ago(sensor.last_seen_at, now)
  switch (state) {
    case 'online':
    case 'degraded':
      return seen ? `heartbeat ${seen}` : null
    case 'late':
    case 'stale':
    case 'offline':
      return seen ? `last heartbeat ${seen}` : null
    case 'idle':
      return seen ? `last run ${seen}` : null
    case 'never_connected':
      return 'no heartbeat yet'
    default:
      return null
  }
}

interface SensorStateBadgeProps {
  sensor: Parameters<typeof sensorState>[0] & Pick<Sensor, 'last_seen_at' | 'created_at'>
  /** The current time (useNow), so the badge ages without impure renders. */
  now: number
  thresholds?: FleetThresholds
  /** Add the "heartbeat 4s ago" line under the pill. */
  withLastSeen?: boolean
  className?: string
}

/** The sensor's state as a pill: one vocabulary for the list, cards and drawer. */
export function SensorStateBadge({
  sensor,
  now,
  thresholds,
  withLastSeen = false,
  className,
}: SensorStateBadgeProps) {
  const state = sensorState(sensor, now, thresholds)
  const meta = SENSOR_STATE_META[state]
  const detail = withLastSeen ? sensorStateDetail(sensor, now, thresholds) : null
  return (
    <TonePill
      tone={meta.tone}
      label={meta.label}
      title={meta.description}
      state={state}
      detail={detail}
      className={className}
    />
  )
}
