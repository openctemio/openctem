import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { plainText } from './cell-text'

interface StackedCellProps {
  /** Bold top line (name, title, id…). */
  primary: ReactNode
  /** Muted second line (count, subtitle, code…). Hidden when nullish/empty. */
  secondary?: ReactNode
  /**
   * Hold each line to two lines (long values in narrow columns): a longer one
   * ends in an ellipsis with its full text as the title. A line that is not
   * plain text gets no title; in a name column the cell's own title holds it.
   */
  truncate?: boolean
  /**
   * Let the secondary line wrap onto a second line (then end in the
   * ellipsis) instead of being cut on its first: for a reason or a time that
   * must be read whole in a narrow column. The full text belongs in a title.
   */
  secondaryLines?: 1 | 2
  className?: string
}

/**
 * Two-line table cell: a bold primary over a muted secondary. Replaces the
 * `<div><div className="font-medium">…</div><div className="text-xs
 * text-muted-foreground">…</div></div>` block hand-rolled across most tables.
 */
export function StackedCell({
  primary,
  secondary,
  truncate,
  secondaryLines,
  className,
}: StackedCellProps) {
  const hasSecondary = secondary !== null && secondary !== undefined && secondary !== ''
  // A clamped line is cut on purpose only with its full text as the title.
  const clamp = (value: ReactNode) =>
    truncate
      ? {
          title: plainText(value),
          'data-cut-tooltip': plainText(value) !== undefined ? '' : undefined,
          className: 'line-clamp-2 break-words',
        }
      : { className: undefined }
  const top = clamp(primary)
  const bottom = clamp(secondary)
  return (
    <div className={cn('min-w-0', className)}>
      <div {...top} className={cn('font-medium', top.className)}>
        {primary}
      </div>
      {hasSecondary && (
        <div
          {...bottom}
          data-slot="stacked-cell-secondary"
          className={cn(
            'text-xs text-muted-foreground',
            secondaryLines === 2
              ? 'line-clamp-2 break-words whitespace-normal'
              : secondaryLines === 1
                ? 'line-clamp-1'
                : bottom.className
          )}
        >
          {secondary}
        </div>
      )}
    </div>
  )
}
