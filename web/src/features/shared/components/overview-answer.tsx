'use client'

import type * as React from 'react'
import Link from '@/components/link'
import { safeHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'

/**
 * The overview template's two blocks (research/374 section 3.3): the page's
 * ONE answer, and the "where to act" list. Together with one `MetricStrip`
 * they replace a wall of per-metric cards.
 *
 * The answer is the only 44px number on the page, which is why it lives here
 * (an owner of check-page-anatomy rule 2) and not in the page. An unmeasured
 * answer is muted body text with the reason, never a big dash that reads as a
 * value. `tone` colours the number only when the answer is a problem.
 */
export function OverviewAnswer({
  question,
  value,
  sentence,
  notMeasured,
  tone = 'default',
  children,
  className,
}: {
  /** The question the page answers ("P0 fixed within target"). */
  question: string
  /** The answer, already formatted ("86%"). Ignored when `notMeasured` is set. */
  value?: string
  /** One sentence with the counts behind the answer and its target. */
  sentence?: string
  /** Set when there is nothing to measure: the reason, shown in place of the number. */
  notMeasured?: { label: string; reason: string }
  tone?: 'default' | 'danger' | 'warning'
  /** The trend, under the sentence. Omit when the API has no series. */
  children?: React.ReactNode
  className?: string
}) {
  return (
    <section
      data-slot="overview-answer"
      data-state={notMeasured ? 'not-measured' : undefined}
      className={cn('flex min-w-0 flex-col gap-2 rounded-lg border bg-card p-4 sm:p-5', className)}
    >
      <h2 className="text-sm font-medium text-muted-foreground">{question}</h2>
      {notMeasured ? (
        <div>
          <p className="text-sm text-muted-foreground">{notMeasured.label}</p>
          <p className="mt-1 text-sm text-muted-foreground">{notMeasured.reason}</p>
        </div>
      ) : (
        <>
          <p
            data-slot="overview-answer-value"
            className={cn(
              'text-4xl font-semibold tabular-nums tracking-tight',
              tone === 'danger' && 'text-destructive',
              tone === 'warning' && 'text-warning'
            )}
          >
            {value}
          </p>
          {sentence ? <p className="text-sm">{sentence}</p> : null}
        </>
      )}
      {children}
    </section>
  )
}

export interface OverviewActItem {
  key: string
  label: string
  /** The count or figure behind the row, in words ("3 open"). */
  detail?: string
  /** The filtered list behind the problem. */
  href: string
  /** `crit` = off track, `warn` = watch. */
  status: 'crit' | 'warn'
  /** The status word, translated ("Off track"). */
  statusLabel: string
}

/** The most rows the list shows: a longer list is a list page, not a summary. */
export const OVERVIEW_ACT_MAX = 5

/**
 * "Where to act": up to five links, each to the filtered list behind an
 * off-track figure. The status is a short word on the row (destructive for
 * off track, warning for watch), not a pill. `empty` is shown when nothing is
 * off track.
 */
export function OverviewActList({
  title,
  items,
  empty,
  className,
}: {
  title: string
  items: OverviewActItem[]
  empty: string
  className?: string
}) {
  const rows = items.filter((i) => safeHref(i.href)).slice(0, OVERVIEW_ACT_MAX)
  return (
    <section
      data-slot="overview-act-list"
      className={cn('flex min-w-0 flex-col rounded-lg border bg-card', className)}
    >
      <h2 className="px-4 pt-4 text-sm font-medium text-muted-foreground sm:px-5 sm:pt-5">
        {title}
      </h2>
      {rows.length === 0 ? (
        <p className="px-4 py-3 text-sm text-muted-foreground sm:px-5">{empty}</p>
      ) : (
        <ul className="mt-2 divide-y">
          {rows.map((row) => (
            <ActRow key={row.key} row={row} />
          ))}
        </ul>
      )}
    </section>
  )
}

function ActRow({ row }: { row: OverviewActItem }) {
  const href = safeHref(row.href)
  if (!href) return null
  return (
    <li>
      <Link
        href={href}
        data-slot="overview-act-row"
        className="flex min-w-0 items-baseline justify-between gap-3 px-4 py-2.5 text-sm transition-colors hover:bg-accent/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring sm:px-5"
      >
        <span className="min-w-0">
          <span className="block truncate font-medium">{row.label}</span>
          {row.detail ? <span className="block text-muted-foreground">{row.detail}</span> : null}
        </span>
        <span
          className={cn('shrink-0', row.status === 'crit' ? 'text-destructive' : 'text-warning')}
        >
          {row.statusLabel}
        </span>
      </Link>
    </li>
  )
}
