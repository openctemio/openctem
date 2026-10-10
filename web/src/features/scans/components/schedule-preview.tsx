'use client'

/**
 * The next runs of a schedule, in the scan's timezone (research/20 §3).
 * Used by the scan page, the scan drawer and the wizard's schedule step.
 */

import { CalendarClock } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { useMemo } from 'react'

import { Skeleton } from '@/components/ui/skeleton'
import { useSchedulePreview } from '../hooks/use-schedule-preview'
import {
  formatOccurrence,
  formatRelativeFuture,
  viewerTimeZone,
  type SchedulePreviewRequest,
} from '../lib/schedule-preview'

interface SchedulePreviewProps {
  /** The schedule to preview; null renders nothing (manual scan). */
  request: SchedulePreviewRequest | null
  /** The scan is paused: the dates apply once it is resumed. */
  paused?: boolean
  /** Title above the list. */
  title?: string
}

export function SchedulePreview({ request, paused = false, title }: SchedulePreviewProps) {
  const { t, locale } = useTranslation()
  const { preview, isLoading, errorMessage } = useSchedulePreview(request)
  const intlLocale = locale === 'en' ? undefined : locale
  const viewerZone = useMemo(() => viewerTimeZone(), [])

  if (!request) return null

  const zone = preview?.timezone ?? request.timezone ?? 'UTC'
  const occurrences = preview?.occurrences ?? []
  const runCount = occurrences.length || request.count
  const heading =
    title ??
    (runCount ? t('scans.preview.nextN', undefined, { count: runCount }) : t('scans.preview.next'))

  return (
    <section
      aria-label={t('scans.preview.upcoming')}
      className="space-y-2"
      aria-busy={isLoading || undefined}
    >
      <div className="flex items-center gap-2 text-sm font-medium">
        <CalendarClock className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
        <span>{heading}</span>
        <span className="text-xs font-normal text-muted-foreground">({zone})</span>
        {paused && (
          <span className="text-xs font-normal text-muted-foreground">
            {t('scans.preview.ifResumed')}
          </span>
        )}
      </div>

      <div aria-live="polite">
        {errorMessage ? (
          <p className="text-sm text-destructive" data-testid="schedule-preview-error">
            {errorMessage}
          </p>
        ) : isLoading && occurrences.length === 0 ? (
          <div className="space-y-1.5" aria-label={t('scans.preview.loading')}>
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-4 w-64" />
            ))}
          </div>
        ) : occurrences.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('scans.preview.none')}</p>
        ) : (
          <ol className="space-y-1 text-sm">
            {occurrences.map((iso) => (
              <li key={iso} className="flex flex-wrap items-baseline gap-x-2">
                <time dateTime={iso} className="tabular-nums">
                  {formatOccurrence(iso, zone, intlLocale)}
                </time>
                <span className="text-xs text-muted-foreground">
                  {formatRelativeFuture(iso, undefined, locale)}
                </span>
                {viewerZone !== zone && (
                  <span className="text-xs text-muted-foreground">
                    {t('scans.preview.yourTime', undefined, {
                      time: formatOccurrence(iso, viewerZone, intlLocale),
                    })}
                  </span>
                )}
              </li>
            ))}
          </ol>
        )}
      </div>
    </section>
  )
}
