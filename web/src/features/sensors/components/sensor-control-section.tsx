'use client'

import { DetailField, DetailFieldGrid, DetailSection } from '@/features/shared'
import type { Sensor } from '@/lib/api/sensor-types'
import { cn } from '@/lib/utils'

import { agoShort, exactTime, formatDurationShort } from '../lib/format'

/** A timer lag or report build above this is slow (the API's control_slow). */
export const CONTROL_SLOW_MS = 5000
/** A heartbeat gap above this many intervals is late (the API's heartbeat_late). */
export const CONTROL_LATE_GAP_FACTOR = 1.5

function seconds(v: number): string {
  if (v >= 60) return formatDurationShort(v)
  return `${Number.isInteger(v) ? v : v.toFixed(1)}s`
}

function millis(v: number): string {
  return v >= 1000 ? `${(v / 1000).toFixed(1)}s` : `${v} ms`
}

/**
 * The control channel: how well the sensor's heartbeat loop keeps time, as
 * the sensor last reported it (sdk-go, api RFC-035 §5.5). Rendered only when
 * the sensor reports it.
 */
export function SensorControlSection({
  sensor,
  now,
}: {
  sensor: Pick<Sensor, 'control' | 'heartbeat_due_at' | 'heartbeat_interval_seconds'>
  now: number
}) {
  const c = sensor.control
  if (!c) return null
  const gapLate = c.interval_s > 0 && c.gap_s > CONTROL_LATE_GAP_FACTOR * c.interval_s
  const lagSlow = c.lag_ms > CONTROL_SLOW_MS
  const buildSlow = c.build_ms > CONTROL_SLOW_MS
  return (
    <DetailSection title="Control channel">
      <DetailFieldGrid>
        <DetailField label="Heartbeat interval">
          <span className="tabular-nums">
            {seconds(c.interval_s)}
            {sensor.heartbeat_due_at && (
              <span
                className="block text-xs text-muted-foreground"
                title={exactTime(sensor.heartbeat_due_at)}
              >
                next due {dueLabel(sensor.heartbeat_due_at, now)}
              </span>
            )}
          </span>
        </DetailField>
        <DetailField label="Gap between heartbeats">
          <span
            className={cn('tabular-nums', gapLate && 'text-warning')}
            title="Time between the last two heartbeats that reached the platform"
          >
            {seconds(c.gap_s)}
            {gapLate && <span className="block text-xs">more than 1.5 intervals</span>}
          </span>
        </DetailField>
        <DetailField label="Timer lag">
          <span
            className={cn('tabular-nums', lagSlow && 'text-warning')}
            title="How late the heartbeat timer fired: the sensor waiting for a CPU"
          >
            {millis(c.lag_ms)}
          </span>
        </DetailField>
        <DetailField label="Report build">
          <span
            className={cn('tabular-nums', buildSlow && 'text-warning')}
            title="How long building the heartbeat report took (tool probes, snapshot)"
          >
            {millis(c.build_ms)}
          </span>
        </DetailField>
        <DetailField label="Round trip">
          <span className="tabular-nums">{millis(c.rtt_ms)}</span>
        </DetailField>
        <DetailField label="Heartbeats lost">
          <span className={cn('tabular-nums', c.failures > 0 && 'text-warning')}>
            {c.failures.toLocaleString()}
          </span>
        </DetailField>
      </DetailFieldGrid>
      {c.reported_at && (
        <p className="text-xs text-muted-foreground" title={exactTime(c.reported_at)}>
          Reported by the sensor {agoShort(c.reported_at, now)}.
        </p>
      )}
    </DetailSection>
  )
}

/** "in 12s", or "12s ago" once the deadline has passed. */
function dueLabel(iso: string, now: number): string {
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return ''
  const d = (t - now) / 1000
  if (d >= 1) return `in ${formatDurationShort(d)}`
  if (d > -1) return 'now'
  return `${formatDurationShort(-d)} ago`
}
