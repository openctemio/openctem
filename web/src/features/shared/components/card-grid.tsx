import type { ComponentProps } from 'react'
import { cn } from '@/lib/utils'

/**
 * A list of cards (templates, connections, capabilities): as many columns as
 * fit, each at least 22rem, so a wide screen shows four or five cards per row
 * instead of three stretched ones, and a phone shows one.
 * web/docs/ui-style-contract.md, "Card grids".
 *
 * `CARD_GRID` is the same tracks for a grid the page draws itself (with its
 * own gap); `CardGrid` adds a 16 px gap, which a `gap-*` class replaces.
 */
export const CARD_GRID = 'grid grid-cols-[repeat(auto-fill,minmax(min(100%,22rem),1fr))]'

export function CardGrid({ className, ...props }: ComponentProps<'div'>) {
  return <div data-slot="card-grid" className={cn(CARD_GRID, 'gap-4', className)} {...props} />
}
