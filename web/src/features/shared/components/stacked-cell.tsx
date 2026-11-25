import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

interface StackedCellProps {
  /** Bold top line (name, title, id…). */
  primary: ReactNode
  /** Muted second line (count, subtitle, code…). Hidden when nullish/empty. */
  secondary?: ReactNode
  /** Clamp both lines to one row with ellipsis (for long titles in narrow columns). */
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
  return (
    <div className={cn('min-w-0', className)}>
      <div className={cn('font-medium', truncate && 'line-clamp-1')}>{primary}</div>
      {hasSecondary && (
        <div
          data-slot="stacked-cell-secondary"
          className={cn(
            'text-xs text-muted-foreground',
            secondaryLines === 2
              ? 'line-clamp-2 break-words whitespace-normal'
              : (truncate || secondaryLines === 1) && 'line-clamp-1'
          )}
        >
          {secondary}
        </div>
      )}
    </div>
  )
}
