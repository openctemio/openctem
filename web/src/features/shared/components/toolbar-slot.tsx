import * as React from 'react'
import { cn } from '@/lib/utils'

/**
 * A value shown inside a toolbar control (a select's value, a view's name)
 * in a box of a fixed width: as wide as the longest of `options` (every value
 * the control can show, in the current language), within the min / max the
 * caller's classes set. The value shown never changes the width: a longer one
 * (a saved view's own name) ends in an ellipsis, its full text in `title`.
 *
 * The options are laid out invisibly in the same grid cell, as generated
 * content (`::before`), so they size the cell without being text of the page
 * (not read out, not found by the browser's find, not matched twice by
 * tests); the value itself takes no width of its own and fills the cell.
 * Pure CSS: no measuring, so the width is right on the first paint.
 *
 * `reserveClassName` caps what the other options reserve (a max width on
 * their invisible copies) while the value shown takes its own whole width up
 * to the slot's max: short values keep one width, a long one (a status such
 * as "Awaiting approval") is shown whole instead of cut to the reserve. The
 * slot still shrinks, ending in an ellipsis, when its row has no room.
 */
export function ToolbarSlot({
  options,
  children,
  title,
  className,
  reserveClassName,
}: {
  /** Every text the slot can show; the longest sets its width. */
  options: readonly string[]
  /** The text shown now. */
  children: React.ReactNode
  /** The full text, for a value that may be cut. */
  title?: string
  className?: string
  /** Caps the width the options reserve; the value shown may take more. */
  reserveClassName?: string
}) {
  return (
    <span
      data-slot="toolbar-slot"
      className={cn('inline-grid min-w-0 grid-cols-[minmax(0,1fr)] text-start', className)}
    >
      {options.map((o, i) => (
        <span
          key={`${i}:${o}`}
          aria-hidden="true"
          data-label={o}
          className={cn(
            'invisible col-start-1 row-start-1 truncate select-none before:content-[attr(data-label)]',
            reserveClassName
          )}
        />
      ))}
      <span
        className={cn(
          'col-start-1 row-start-1 truncate',
          // Without a reserve cap the value takes no width of its own; with
          // one it sizes the slot too (whole, up to the slot's max).
          !reserveClassName && 'w-0 min-w-full'
        )}
        title={title}
      >
        {children}
      </span>
    </span>
  )
}
