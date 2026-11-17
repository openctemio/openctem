'use client'

import * as React from 'react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * The list's one count: the results of the view as the list shows it (its
 * filters and search applied), beside the view name in the title row. A list
 * says its count here and nowhere else (the pager's "1 to 25 of N" is
 * navigation, and tab counts are other queues'); the page-anatomy check
 * fails a list page with more than one `data-slot="list-count"`.
 *
 * A pill (20 px, 12/16 medium, muted text on the raised surface) whose
 * tooltip says what was counted: the viewer's own data scope.
 *
 * - `capped`: the server stopped counting; the count reads "1,000+" and the
 *   tooltip says so too.
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
  const scopeHint = t('common.listCount.scopeHint', 'Counted in your data scope')
  const hint = capped
    ? t('common.listCount.hints', '{first}. {second}.', {
        first: scopeHint,
        second: t('common.listCount.cappedHint', 'Counted up to this number'),
      })
    : scopeHint
  return (
    <span
      data-slot="list-count"
      role="status"
      aria-live="polite"
      aria-atomic="true"
      title={loading ? undefined : hint}
      className={cn(
        'inline-flex h-5 shrink-0 items-center rounded-full text-cap-m tabular-nums text-muted-foreground',
        // The pill is drawn once there is a number in it.
        !loading && 'bg-surface-raised px-2',
        className
      )}
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
 * "Modified": the list is its view plus something (a filter, search text,
 * unsaved changes to a saved view). A dashed lozenge, 20 px tall with its
 * border, 12/16, muted: a state of the view, never a status.
 */
export function ListModified({ title, className }: { title?: string; className?: string }) {
  const { t } = useTranslation()
  return (
    <span
      data-slot="list-modified"
      title={title}
      className={cn(
        'inline-flex h-5 shrink-0 items-center rounded-md border border-dashed border-border px-1.5 text-cap text-muted-foreground',
        className
      )}
    >
      {t('common.listView.modified', 'Modified')}
    </span>
  )
}

/**
 * What a changed view offers, right after the count: the Modified lozenge,
 * then Save view and Reset. Nothing is drawn while the view is unchanged.
 *
 * - `onSave`: opens the list's save-view dialog; `save` replaces that button
 *   (a menu with "Save changes" and "Save as new view" on a view the viewer
 *   owns). Leave both out for someone who may not save views.
 * - `onReset`: back to the exact base view.
 * - `actionsClassName`: where the row is too narrow for the two buttons, the
 *   page hides them here and offers them in the row's More instead; the
 *   lozenge stays.
 */
export function ListViewChanged({
  changed,
  summary,
  onSave,
  save,
  onReset,
  actionsClassName,
}: {
  changed: boolean
  /** What differs ("2 filters added, sort changed"): the lozenge's tooltip. */
  summary?: string
  onSave?: () => void
  save?: React.ReactNode
  onReset?: () => void
  actionsClassName?: string
}) {
  const { t } = useTranslation()
  if (!changed) return null
  return (
    <>
      <ListModified title={summary} />
      {(save || onSave || onReset) && (
        <div
          data-slot="list-view-actions"
          className={cn('flex shrink-0 items-center gap-2', actionsClassName)}
        >
          {save ??
            (onSave && (
              <Button data-slot="list-view-save" variant="outline" size="sm" onClick={onSave}>
                {t('common.listView.save', 'Save view')}
              </Button>
            ))}
          {onReset && (
            <Button data-slot="list-view-reset" variant="ghost" size="sm" onClick={onReset}>
              {t('common.listView.reset', 'Reset')}
            </Button>
          )}
        </div>
      )}
    </>
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
  titleTestId,
  ref,
  'data-testid': testId,
}: {
  title: React.ReactNode
  /** The list's `ListCount`. */
  count?: React.ReactNode
  /** More after the count (a description, `ListViewChanged`). */
  start?: React.ReactNode
  /** The list's actions, pinned to the row's end. */
  children?: React.ReactNode
  /** The row's own classes (a size container for its actions). */
  className?: string
  /** A test id for the view name. */
  titleTestId?: string
  /** The row element (a page reads its width to fold its actions). */
  ref?: React.Ref<HTMLDivElement>
  'data-testid'?: string
}) {
  return (
    <div
      ref={ref}
      data-slot="list-title-row"
      data-testid={testId}
      className={cn('flex min-h-control items-center gap-2', className)}
    >
      <div data-slot="list-title-start" className="flex min-w-0 items-center gap-3">
        {/* The name gives way first: what follows it keeps its width. */}
        <h2
          data-testid={titleTestId}
          className="min-w-0 truncate text-sm font-medium"
          title={typeof title === 'string' ? title : undefined}
        >
          {title}
        </h2>
        {count}
        {start}
      </div>
      {children ? (
        <div data-slot="list-title-end" className="ms-auto flex shrink-0 items-center gap-2">
          {children}
        </div>
      ) : null}
    </div>
  )
}
