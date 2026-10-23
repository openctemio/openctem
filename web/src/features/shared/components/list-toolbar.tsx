import type * as React from 'react'
import { cn } from '@/lib/utils'

/**
 * The one toolbar row above a list (research/244). `DataTable` renders it
 * through its `filterToggle` / `toolbarStart` / `toolbarEnd` props; a list
 * that is not a table (a card grid) renders it directly so both look and wrap
 * the same.
 *
 * Order, the same on every page:
 * - start: Filters toggle, search, then at most two status/kind selects when
 *   the list has no "Add filter" yet;
 * - end: saved views, group, export, refresh, then the View menu (density,
 *   columns), always last.
 *
 * One row where it fits. The start group asks for at least 12rem; when it and
 * the end group do not fit on one line the whole end group moves to its own
 * line, so the search box is never squeezed under a lone button. The row is a
 * size container: controls switch their labels to icons by the toolbar's own
 * width (`@xl/toolbar:`).
 */
export function ListToolbar({
  start,
  search,
  end,
  className,
}: {
  /** Filters toggle, search, selects. */
  start?: React.ReactNode
  /** A search field that sits after the start group (the table's own search). */
  search?: React.ReactNode
  /** Saved views, group, export, refresh, View menu. */
  end?: React.ReactNode
  className?: string
}) {
  return (
    <div
      data-testid="data-table-toolbar"
      data-slot="list-toolbar"
      className={cn('@container/toolbar flex flex-wrap items-center gap-2', className)}
    >
      {start ? (
        // No min-w-0: the group must not shrink below its widest control, or a
        // button spills over the search box beside it. It wraps instead.
        <div className="flex flex-[1_1_12rem] flex-wrap items-center gap-2 [&>.relative:has(input)]:min-w-36">
          {start}
        </div>
      ) : null}
      {search}
      {end ? <div className="ms-auto flex shrink-0 items-center gap-2">{end}</div> : null}
    </div>
  )
}
