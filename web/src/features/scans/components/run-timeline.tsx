'use client'

/**
 * A run's timeline (research/62 P0-4): what happened to each of its tasks,
 * oldest first — queued, claimed, refused, handed back, started and how it
 * ended — from GET /api/v1/scan-runs/{id}/events. A platform scanning task
 * never names its sensor.
 */

import useSWR from 'swr'
import { useTranslation } from '@/context/i18n-provider'
import { enTranslate, type Translate } from '../lib/translate'

import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { get } from '@/lib/api/client'
import { scanRunEndpoints } from '@/lib/api/endpoints'
import type { RunEvent, RunEventsResponse } from '@/lib/api/generated'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'

/** Events with a translated label (scans.event.*). */
const EVENTS = new Set([
  'queued',
  'claimed',
  'started',
  'refused',
  'requeued',
  'completed',
  'failed',
  'canceled',
  'expired',
  'changed',
])

const FAILURE_EVENTS = new Set(['failed', 'expired', 'refused'])

export function eventLabel(event?: string, t: Translate = enTranslate): string {
  return (event && EVENTS.has(event) ? t(`scans.event.${event}`) : event) || t('scans.event.event')
}

/** Who handled the event: platform scanning is never named by sensor. */
export function eventActor(
  e: Pick<RunEvent, 'platform' | 'sensor_id'>,
  t: Translate = enTranslate
): string | null {
  if (e.platform) return t('scans.timeline.platform')
  return e.sensor_id ? t('scans.timeline.sensor', undefined, { id: e.sensor_id.slice(0, 8) }) : null
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
  const { t } = useTranslation()
  const { data, isLoading, error } = useSWR<RunEventsResponse>(
    scanRunEndpoints.events(runId),
    (url: string) => get<RunEventsResponse>(url),
    { revalidateOnFocus: false, refreshInterval }
  )
  if (isLoading) return <Skeleton className="h-24 w-full" />
  if (error) {
    return <p className="text-sm text-muted-foreground">{t('scans.timeline.loadFailed')}</p>
  }
  const events = data?.events ?? []
  if (events.length === 0) {
    return <p className="text-sm text-muted-foreground">{t('scans.timeline.none')}</p>
  }
  const waiting = tasksWaitingForSensor(events)
  return (
    <div className="space-y-3">
      {waiting.length > 0 && (
        <p className="rounded-md border border-dashed p-2 text-sm">
          {t(
            waiting.length === 1 ? 'scans.timeline.waitingOne' : 'scans.timeline.waitingMany',
            undefined,
            { count: waiting.length }
          )}
        </p>
      )}
      <ol className="space-y-2" aria-label={t('scans.timeline.label')}>
        {events.map((e) => {
          const actor = eventActor(e, t)
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
                {eventLabel(e.event, t)}
              </Badge>
              <span className="font-mono text-xs text-muted-foreground">
                {t('scans.timeline.task', undefined, { id: e.task_id?.slice(0, 8) ?? '' })}
                {(e.attempt ?? 0) > 1
                  ? t('scans.timeline.attempt', undefined, { count: e.attempt ?? 0 })
                  : ''}
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
        <p className="text-xs text-muted-foreground">{t('scans.timeline.truncated')}</p>
      )}
    </div>
  )
}
