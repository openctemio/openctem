'use client'

import { formatDistanceToNow } from 'date-fns'
import { useTranslation } from '@/context/i18n-provider'
import { dateFnsLocaleFor } from '@/lib/format-date'
import { formatAbsoluteTime } from '@/lib/format-metric'
import { EmptyCell } from './empty-cell'

interface RelativeTimeProps {
  /** ISO string, Date, or nullish. Nullish / invalid renders the kit's empty cell. */
  date: string | Date | null | undefined
  /** Append "ago"/"in" (default true). */
  addSuffix?: boolean
  className?: string
}

/**
 * The last minute reads "just now": "less than a minute ago" was the longest
 * relative time and was cut in a date column (/exposures, 1024 px). Read
 * against the clock like `formatDistanceToNow`.
 */
function withinLastMinute(d: Date, addSuffix: boolean): boolean {
  const age = Date.now() - d.getTime()
  return addSuffix && age >= 0 && age < 60_000
}

/**
 * Muted relative timestamp ("3 days ago", "3 ngày trước") with the absolute
 * date and time on hover, both in the console language. The language comes
 * from the i18n context, so no caller can forget it.
 */
export function RelativeTime({ date, addSuffix = true, className }: RelativeTimeProps) {
  const { locale, t } = useTranslation()
  const d = date == null ? null : typeof date === 'string' ? new Date(date) : date
  if (!d || Number.isNaN(d.getTime())) {
    // No date: the kit's empty cell (muted dash, hover text), never a bare dash.
    return <EmptyCell className={className} title={t('common.notRecorded', 'Not recorded')} />
  }
  const text = withinLastMinute(d, addSuffix)
    ? t('common.justNow', 'just now')
    : formatDistanceToNow(d, { addSuffix, locale: dateFnsLocaleFor(locale) })
  return (
    // Size and colour come from the surrounding line (one size per line of
    // metadata, research/244); the absolute time is the tooltip.
    <time className={className} dateTime={d.toISOString()} title={formatAbsoluteTime(d, locale)}>
      {text}
    </time>
  )
}
