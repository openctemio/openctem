import { cn } from '@/lib/utils'

/**
 * How a fact that was not collected is shown (ui-style-contract §7,
 * "Unknown facts"):
 *
 * - in a list cell: nothing. A cell left with no content at all shows one
 *   muted `—` (`EmptyCell`), the house empty-cell style;
 * - in a drawer or detail page: one muted line at the end of the facts,
 *   "Not collected yet: port, HTTP status, …" (`NotCollectedNote`);
 * - in filters: the facets that have a "Not collected" value keep it, so
 *   coverage gaps stay findable.
 *
 * A known negative ("No TLS", "No open ports", "No technologies detected")
 * is data, not a gap, and is always shown.
 */

/** The muted `—` of a list cell with nothing known to show. */
export function EmptyCell({
  title = 'Not collected',
  className,
}: {
  title?: string
  className?: string
}) {
  return (
    <span className={cn('text-muted-foreground', className)} title={title}>
      —
    </span>
  )
}

/** "Not collected yet: port, HTTP status" for the facts in `items`, or nothing. */
export function notCollectedText(items: readonly string[]): string | null {
  const unique = Array.from(new Set(items.filter(Boolean)))
  return unique.length > 0 ? `Not collected yet: ${unique.join(', ')}` : null
}

/** The single drawer line naming the facts no scan has recorded. */
export function NotCollectedNote({
  items,
  className,
}: {
  items: readonly string[]
  className?: string
}) {
  const text = notCollectedText(items)
  if (!text) return null
  return (
    <p data-slot="not-collected" className={cn('text-xs text-muted-foreground', className)}>
      {text}
    </p>
  )
}
