/**
 * Schedule preview (research/20 §3 "Schedules"): the next occurrences of a
 * scan's schedule, in the scan's timezone.
 *
 * The occurrences come from POST /scans/schedule-preview, which runs the
 * scheduler's own code and the save validation. Nothing here evaluates a
 * cron expression or an RRULE: a second evaluator in the browser could
 * disagree with the scheduler (DST, BYSETPOS, month-end clamping).
 */

import type { components } from '@/lib/api/generated/api.types'
import type { ScanConfig } from '@/lib/api/scan-types'
import type { NewScanFormData } from '../types'
import { formDataToCreateRequest } from './scan-form'

export type SchedulePreviewRequest =
  components['schemas']['internal_infra_http_handler.SchedulePreviewRequest']
export type SchedulePreviewResponse =
  components['schemas']['internal_infra_http_handler.SchedulePreviewResponse']

export const DEFAULT_PREVIEW_COUNT = 5

/** The preview request for a saved scan, or null when it runs only on demand. */
export function schedulePreviewRequestFromConfig(
  config: Pick<
    ScanConfig,
    | 'schedule_type'
    | 'schedule_cron'
    | 'schedule_rrule'
    | 'schedule_day'
    | 'schedule_time'
    | 'schedule_timezone'
  >,
  count = DEFAULT_PREVIEW_COUNT
): SchedulePreviewRequest | null {
  if (!config.schedule_type || config.schedule_type === 'manual') return null
  const request: SchedulePreviewRequest = {
    schedule_type: config.schedule_type,
    timezone: config.schedule_timezone || 'UTC',
    count,
  }
  if (config.schedule_cron) request.schedule_cron = config.schedule_cron
  if (config.schedule_rrule) request.schedule_rrule = config.schedule_rrule
  if (config.schedule_day !== undefined && config.schedule_day !== null) {
    request.schedule_day = config.schedule_day
  }
  if (config.schedule_time) request.schedule_time = config.schedule_time.slice(0, 5)
  return request
}

/** A stable cache key for a request (field order does not matter). */
export function schedulePreviewKey(request: SchedulePreviewRequest): string {
  const r = request
  return JSON.stringify([
    r.schedule_type ?? '',
    r.schedule_cron ?? '',
    r.schedule_rrule ?? '',
    r.schedule_day ?? null,
    r.schedule_time ?? '',
    r.timezone ?? '',
    r.count ?? DEFAULT_PREVIEW_COUNT,
  ])
}

/** The viewer's IANA timezone, or UTC when the browser does not say. */
export function viewerTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

/**
 * "Mon, 12 Oct 2026, 09:00 GMT-4" in timeZone. An unknown zone falls back to
 * UTC rather than throwing (the API has already validated it).
 */
export function formatOccurrence(iso: string, timeZone: string, locale = 'en-GB'): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  const options: Intl.DateTimeFormatOptions = {
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    timeZoneName: 'short',
  }
  try {
    return new Intl.DateTimeFormat(locale, { ...options, timeZone }).format(date)
  } catch {
    return new Intl.DateTimeFormat(locale, { ...options, timeZone: 'UTC' }).format(date)
  }
}

/** "in 3 days", "in 5 hours", "in 12 minutes" relative to now. */
export function formatRelativeFuture(iso: string, now: Date = new Date()): string {
  const ms = new Date(iso).getTime() - now.getTime()
  if (Number.isNaN(ms)) return ''
  const minutes = Math.round(ms / 60_000)
  const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
  if (Math.abs(minutes) < 60) return rtf.format(minutes, 'minute')
  const hours = Math.round(minutes / 60)
  if (Math.abs(hours) < 48) return rtf.format(hours, 'hour')
  return rtf.format(Math.round(hours / 24), 'day')
}

/**
 * The preview request for the wizard form: the schedule fields of exactly the
 * request Create/Save would send, so the preview cannot describe a schedule
 * other than the one saved. null while the scan runs only on demand.
 */
export function schedulePreviewRequestFromForm(
  form: NewScanFormData,
  count = DEFAULT_PREVIEW_COUNT
): SchedulePreviewRequest | null {
  const request = formDataToCreateRequest(form)
  if (!request.schedule_type || request.schedule_type === 'manual') return null
  return schedulePreviewRequestFromConfig(
    {
      schedule_type: request.schedule_type,
      schedule_cron: request.schedule_cron,
      schedule_rrule: request.schedule_rrule,
      schedule_day: request.schedule_day,
      schedule_time: request.schedule_time,
      schedule_timezone: request.timezone ?? 'UTC',
    },
    count
  )
}
