'use client'

/**
 * A run's timeline (research/62 P0-4): what happened to each of its tasks,
 * oldest first — queued, claimed, refused, handed back, started and how it
 * ended — from GET /api/v1/scan-runs/{id}/events. A platform scanning task
 * never names its sensor.
 */

import useSWR from 'swr'

import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { get } from '@/lib/api/client'
import { scanRunEndpoints } from '@/lib/api/endpoints'
import type { RunEvent, RunEventsResponse } from '@/lib/api/generated'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'

/** Each event in words. */
const EVENT_LABELS: Record<string, string> = {
  queued: 'Queued',
  claimed: 'Picked up by a sensor',
  started: 'Started',
  refused: 'Refused by the sensor',
  requeued: 'Handed back to the queue',
  completed: 'Completed',
  failed: 'Failed',
  canceled: 'Canceled',
  expired: 'Expired',
  changed: 'Changed',
}

const FAILURE_EVENTS = new Set(['failed', 'expired', 'refused'])

export function eventLabel(event?: string): string {
  return (event && EVENT_LABELS[event]) || event || 'Event'
}

/** Who handled the event: platform scanning is never named by sensor. */
export function eventActor(e: Pick<RunEvent, 'platform' | 'sensor_id'>): string | null {
  if (e.platform) return 'Platform scanning'
  return e.sensor_id ? `Sensor ${e.sensor_id.slice(0, 8)}` : null
}

/** How long a task can sit queued before the run says it waits for a sensor. */
export const WAITING_FOR_SENSOR_MS = 5 * 60 * 1000

/**
 * The tasks still waiting for a sensor: their last event is queued or
 * requeued, longer ago than WAITING_FOR_SENSOR_MS.
 */
export function tasksWaitingForSensor(events: RunEvent[], now = Date.now()): string[] {
  const last = new Map<string, RunEvent>()
  for (const e of events) {
    if (e.task_id) last.set(e.task_id, e)
  }
  const waiting: string[] = []
  for (const [task, e] of last) {
    if ((e.event === 'queued' || e.event === 'requeued') && e.at) {
      if (now - new Date(e.at).getTime() > WAITING_FOR_SENSOR_MS) waiting.push(task)
    }
  }
  return waiting
}

interface RunTimelineProps {
  runId: string
  refreshInterval?: number
}

export function RunTimeline({ runId, refreshInterval }: RunTimelineProps) {
  const { data, isLoading, error } = useSWR<RunEventsResponse>(
    scanRunEndpoints.events(runId),
    (url: string) => get<RunEventsResponse>(url),
    { revalidateOnFocus: false, refreshInterval }
  )
  if (isLoading) return <Skeleton className="h-24 w-full" />
  if (error) {
    return <p className="text-sm text-muted-foreground">Could not load the run timeline.</p>
  }
  const events = data?.events ?? []
  if (events.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No task events yet. Events are kept for 30 days.
      </p>
    )
  }
  const waiting = tasksWaitingForSensor(events)
  return (
    <div className="space-y-3">
      {waiting.length > 0 && (
        <p className="rounded-md border border-dashed p-2 text-sm">
          Waiting for a sensor: {waiting.length} task{waiting.length === 1 ? '' : 's'} queued for
          more than 5 minutes and not picked up. Check that a sensor with the tool is online (and in
          the right scan zone).
        </p>
      )}
      <ol className="space-y-2" aria-label="Run timeline">
        {events.map((e) => {
          const actor = eventActor(e)
          return (
            <li key={e.id} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-sm">
              <RelativeTime date={e.at ?? ''} className="w-24 shrink-0 text-xs" />
              <Badge
                variant="secondary"
                className={cn(
                  'font-normal',
                  FAILURE_EVENTS.has(e.event ?? '') && 'bg-destructive/10 text-destructive'
                )}
              >
                {eventLabel(e.event)}
              </Badge>
              <span className="font-mono text-xs text-muted-foreground">
                task {e.task_id?.slice(0, 8)}
                {(e.attempt ?? 0) > 1 ? ` · attempt ${e.attempt}` : ''}
              </span>
              {actor && <span className="text-xs text-muted-foreground">{actor}</span>}
              {(e.code || e.message) && (
                <span className="basis-full ps-26 text-xs text-muted-foreground [unicode-bidi:isolate]">
                  {e.code && <span className="font-mono">{toDisplayText(e.code, 100)} </span>}
                  {e.message && toDisplayText(e.message, 400)}
                </span>
              )}
            </li>
          )
        })}
      </ol>
      {data?.truncated && (
        <p className="text-xs text-muted-foreground">Showing the first 2000 events.</p>
      )}
    </div>
  )
}
