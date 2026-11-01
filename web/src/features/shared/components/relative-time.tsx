'use client'

import { formatDistanceToNow } from 'date-fns'
import { useTranslation } from '@/context/i18n-provider'
import { dateFnsLocaleFor } from '@/lib/format-date'
import { formatAbsoluteTime } from '@/lib/format-metric'

interface RelativeTimeProps {
  /** ISO string, Date, or nullish. Nullish / invalid renders an em-dash. */
  date: string | Date | null | undefined
  /** Append "ago"/"in" (default true). */
  addSuffix?: boolean
  className?: string
}

/**
 * Muted relative timestamp ("3 days ago", "3 ngày trước") with the absolute
 * date and time on hover, both in the console language. The language comes
 * from the i18n context, so no caller can forget it.
 */
export function RelativeTime({ date, addSuffix = true, className }: RelativeTimeProps) {
  const { locale } = useTranslation()
  const d = date == null ? null : typeof date === 'string' ? new Date(date) : date
  if (!d || Number.isNaN(d.getTime())) {
    return <span className={className}>—</span>
  }
  return (
    // Size and colour come from the surrounding line (one size per line of
    // metadata, research/244); the absolute time is the tooltip.
    <time className={className} dateTime={d.toISOString()} title={formatAbsoluteTime(d, locale)}>
      {formatDistanceToNow(d, { addSuffix, locale: dateFnsLocaleFor(locale) })}
    </time>
  )
}
