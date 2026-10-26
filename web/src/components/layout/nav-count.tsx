import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

/**
 * The one count style of the sidebar (menu items and quick views): a plain
 * number at the end of the row, never a filled pill. `action` is a queue that
 * waits for this person (teal, the brand's act-here accent), `danger` a
 * problem to fix, `muted` a plain total.
 */
export function NavCount({
  children,
  tone = 'muted',
}: {
  children: ReactNode
  tone?: 'muted' | 'action' | 'danger'
}) {
  return (
    <span
      data-slot="nav-count"
      className={cn(
        'ms-auto shrink-0 text-xs tabular-nums',
        tone === 'action' && 'font-semibold text-signal-text',
        tone === 'danger' && 'font-medium text-destructive',
        tone === 'muted' && 'text-muted-foreground'
      )}
    >
      {children}
    </span>
  )
}
