'use client'

import * as React from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * The list's one count: the results of the view as the list shows it (its
 * filters and search applied), beside the view name in the title row. A list
 * says its count here and nowhere else (the pager's "1 to 25 of N" is
 * navigation, and tab counts are other queues'); the page-anatomy check
 * fails a list page with more than one `data-slot="list-count"`.
 *
 * - `capped`: the server stopped counting; the count reads "1,000+".
 * - `label`: the full sentence for assistive technology ("26 findings"); the
 *   region is polite and atomic, so a new count is announced once.
 * - While the count is not known yet the slot stays, empty.
 */
export function ListCount({
  total,
  capped = false,
  loading = false,
  label,
  className,
}: {
  total: number
  capped?: boolean
  loading?: boolean
  /** "26 findings": read instead of the bare number. */
  label?: string
  className?: string
}) {
  const { t, locale } = useTranslation()
  const n = new Intl.NumberFormat(locale).format(total)
  const text = capped ? t('common.listCount.capped', '{count}+', { count: n }) : n
  return (
    <span
      data-slot="list-count"
      role="status"
      aria-live="polite"
      aria-atomic="true"
      title={capped ? t('common.listCount.cappedHint', 'Counted up to this number') : undefined}
      className={cn('shrink-0 text-sm tabular-nums text-muted-foreground', className)}
    >
      {loading ? null : label ? (
        <>
          <span aria-hidden="true">{text}</span>
          <span className="sr-only">{label}</span>
        </>
      ) : (
        text
      )}
    </span>
  )
}

/**
 * The title row of a list (above its toolbar): the view or list name and its
 * one count at the start, the list's own actions (Refresh, Export, More) at
 * the end. Page-level actions (Add, the list or grid switch) stay in the page
 * header.
 */
export function ListTitleRow({
  title,
  count,
  start,
  children,
  className,
  'data-testid': testId,
}: {
  title: React.ReactNode
  /** The list's `ListCount`. */
  count?: React.ReactNode
  /** More after the count (a description, Modified, Save view). */
  start?: React.ReactNode
  /** The list's actions, pinned to the row's end. */
  children?: React.ReactNode
  className?: string
  'data-testid'?: string
}) {
  return (
    <div
      data-slot="list-title-row"
      data-testid={testId}
      className={cn('flex min-h-control items-center gap-2', className)}
    >
      <div className="flex min-w-0 items-center gap-3">
        <h2 className="min-w-0 truncate text-sm font-medium">{title}</h2>
        {count}
        {start}
      </div>
      {children ? <div className="ms-auto flex shrink-0 items-center gap-2">{children}</div> : null}
    </div>
  )
}
