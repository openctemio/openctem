'use client'

import type { SensorHeartbeatBucket, SensorHeartbeatHistoryResponse } from '@/lib/api/sensor-types'
import { cn } from '@/lib/utils'

import { formatDurationShort } from '../lib/format'

/** A bucket whose largest gap is above this many intervals is late (as the card). */
const LATE_GAP_FACTOR = 1.5

/** One time slot of the sparkline; bucket is null when no heartbeat arrived. */
export interface HeartbeatSlot {
  start: number
  bucket: SensorHeartbeatBucket | null
}

/**
 * The time slots of the last `hours`, oldest first, aligned on the bucket
 * width, with the buckets the API returned placed in theirs. A slot without
 * a bucket had no heartbeat at all.
 */
export function heartbeatSlots(
  history: SensorHeartbeatHistoryResponse,
  now: number
): HeartbeatSlot[] {
  const width = Math.max(history.bucket_seconds, 60) * 1000
  const count = Math.max(1, Math.round((history.hours * 3_600_000) / width))
  const last = Math.floor(now / width) * width
  const byStart = new Map<number, SensorHeartbeatBucket>()
  for (const b of history.buckets) {
    const t = new Date(b.at).getTime()
    if (!Number.isNaN(t)) byStart.set(Math.floor(t / width) * width, b)
  }
  const slots: HeartbeatSlot[] = []
  for (let i = count - 1; i >= 0; i--) {
    const start = last - i * width
    slots.push({ start, bucket: byStart.get(start) ?? null })
  }
  return slots
}

/** Whether a bucket's largest gap made the sensor late. */
export function bucketIsLate(b: SensorHeartbeatBucket): boolean {
  return b.interval_s > 0 && b.max_gap_s > LATE_GAP_FACTOR * b.interval_s
}

function slotTitle(slot: HeartbeatSlot, widthMs: number): string {
  const from = new Date(slot.start)
  const to = new Date(slot.start + widthMs)
  const range = `${from.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}–${to.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
  const b = slot.bucket
  if (!b) return `${range}: no heartbeat`
  const parts = [`${range}: ${b.beats} heartbeat${b.beats === 1 ? '' : 's'}`]
  if (b.max_gap_s > 0) {
    parts.push(
      `largest gap ${formatDurationShort(b.max_gap_s)} (average ${formatDurationShort(b.avg_gap_s)})`
    )
  }
  if (b.interval_s > 0) parts.push(`interval ${formatDurationShort(b.interval_s)}`)
  if (b.max_lag_ms > 0) parts.push(`timer lag up to ${b.max_lag_ms} ms`)
  if (b.failures > 0) parts.push(`${b.failures} lost`)
  return parts.join(', ')
}

/**
 * The last 24 h of a sensor's heartbeats as bars, one per 15 minutes: the
 * height is the largest gap between two heartbeats in that slot, the dashed
 * line the interval the sensor followed, a warning bar a slot where it was
 * late, and an empty slot one without any heartbeat (the sensor was down or
 * unreachable). Inline SVG: theme-aware through currentColor, no chart
 * library.
 */
export function HeartbeatGapSparkline({
  history,
  now,
  className,
}: {
  history: SensorHeartbeatHistoryResponse
  now: number
  className?: string
}) {
  const slots = heartbeatSlots(history, now)
  const widthMs = Math.max(history.bucket_seconds, 60) * 1000
  const withData = slots.filter((s) => s.bucket)
  if (withData.length === 0) {
    return <p className="text-xs text-muted-foreground">No heartbeat history yet.</p>
  }
  const interval = Math.max(...withData.map((s) => s.bucket!.interval_s), 0)
  const top = Math.max(...withData.map((s) => s.bucket!.max_gap_s), interval * 2, 1)
  const barW = 3
  const step = 4
  const h = 40
  const w = slots.length * step
  const y = (v: number) => h - Math.max(1, (v / top) * (h - 2))
  const late = withData.filter((s) => bucketIsLate(s.bucket!)).length
  const empty = slots.length - withData.length
  const label =
    `Heartbeat gaps over the last ${history.hours} hours: ${withData.length} of ${slots.length} ` +
    `${Math.round(widthMs / 60000)}-minute slots had heartbeats` +
    (late > 0 ? `, ${late} late` : '') +
    (empty > 0 ? `, ${empty} without any` : '')
  return (
    <figure className={cn('space-y-1', className)}>
      <svg
        viewBox={`0 0 ${w} ${h}`}
        className="h-10 w-full overflow-visible"
        preserveAspectRatio="none"
        role="img"
        aria-label={label}
      >
        {slots.map((s, i) => {
          const x = i * step
          if (!s.bucket) {
            return (
              <rect
                key={s.start}
                x={x}
                y={h - 1}
                width={barW}
                height={1}
                className="fill-muted-foreground/30"
              >
                <title>{slotTitle(s, widthMs)}</title>
              </rect>
            )
          }
          const gap = s.bucket.max_gap_s > 0 ? s.bucket.max_gap_s : s.bucket.interval_s
          const top_ = y(gap)
          return (
            <rect
              key={s.start}
              x={x}
              y={top_}
              width={barW}
              height={h - top_}
              data-late={bucketIsLate(s.bucket) || undefined}
              className={bucketIsLate(s.bucket) ? 'fill-warning' : 'fill-primary/60'}
            >
              <title>{slotTitle(s, widthMs)}</title>
            </rect>
          )
        })}
        {interval > 0 && (
          <line
            x1={0}
            x2={w}
            y1={y(interval)}
            y2={y(interval)}
            className="stroke-muted-foreground"
            strokeDasharray="3 3"
            strokeWidth={0.75}
            vectorEffect="non-scaling-stroke"
          />
        )}
      </svg>
      <figcaption className="flex justify-between text-xs text-muted-foreground">
        <span>{history.hours}h ago</span>
        <span>
          Largest gap per {Math.round(widthMs / 60000)} min
          {interval > 0 && <> · dashed: {formatDurationShort(interval)} interval</>}
        </span>
        <span>now</span>
      </figcaption>
    </figure>
  )
}
