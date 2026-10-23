'use client'

import { formatDistanceToNow, type Locale } from 'date-fns'

interface RelativeTimeProps {
  /** ISO string, Date, or nullish. Nullish / invalid renders an em-dash. */
  date: string | Date | null | undefined
  /** Append "ago"/"in" (default true). */
  addSuffix?: boolean
  className?: string
  /** date-fns locale for the words ("5 phút trước"); English when absent. */
  locale?: Locale
}

/**
 * Muted relative timestamp ("3 days ago") with the absolute date on hover.
 * Replaces the `formatDistanceToNow(new Date(x), { addSuffix: true })` snippet
 * that was hand-rolled in ~every table's "created/first seen/flagged" column.
 */
export function RelativeTime({ date, addSuffix = true, className, locale }: RelativeTimeProps) {
  const d = date == null ? null : typeof date === 'string' ? new Date(date) : date
  if (!d || Number.isNaN(d.getTime())) {
    return <span className={className}>—</span>
  }
  return (
    // Size and colour come from the surrounding line (one size per line of
    // metadata, research/244); the absolute time is the tooltip.
    <span className={className} title={d.toLocaleString()}>
      {formatDistanceToNow(d, { addSuffix, locale })}
    </span>
  )
}
