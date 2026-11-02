/**
 * A part-to-whole bar: one horizontal bar split into parts in a fixed order,
 * each part as wide as its share. Parts with no value are left out; a part
 * with a value stays at least a few pixels wide so a small P0 or critical
 * count never disappears. The bar is decorative: the figures it shows are
 * always printed (and linked) next to it, so it is hidden from screen readers
 * unless `ariaLabel` names it as one image. Every part-to-whole bar in the
 * dashboard kit is this component (shared-patterns.test.ts).
 */

import { cn } from '@/lib/utils'

export interface StackedBarPart {
  key: string
  value: number
  /** A CSS colour (a chart token such as PRIORITY_CHART_COLORS[key]). */
  color: string
}

export function StackedBar({
  parts,
  className,
  testId,
  ariaLabel,
}: {
  parts: StackedBarPart[]
  /** Height and radius, e.g. "h-2 rounded-full" (default) or "h-[3px] rounded-sm". */
  className?: string
  testId?: string
  /** Names the bar as one image (role="img") when no figures sit beside it. */
  ariaLabel?: string
}) {
  const shown = parts.filter((p) => p.value > 0)
  if (shown.length === 0) return null
  return (
    <span
      className={cn('flex h-2 w-full gap-0.5 overflow-hidden rounded-full', className)}
      {...(ariaLabel ? { role: 'img', 'aria-label': ariaLabel } : { 'aria-hidden': true })}
      data-testid={testId}
    >
      {shown.map((p) => (
        <span
          key={p.key}
          data-part={p.key}
          className="min-w-1"
          style={{ flex: `${p.value} 1 0`, background: p.color }}
        />
      ))}
    </span>
  )
}
