'use client'

/**
 * The phone card of a scope list row (entries and exclusions), as the Scope
 * board draws a row: the pattern (up to two lines) with the status and the
 * row menu on its line, a muted line saying what it covers, then one line of
 * plain facts (kind, probe level, who authorized it). No label/value grid:
 * each fact reads on its own.
 */

import { Checkbox } from '@/components/ui/checkbox'
import type { MobileRowSelection } from '@/features/shared/components/data-table/data-table'
import { BreakText } from '@/features/shared/components/break-text'

export interface ScopeRowCardProps {
  pattern: string
  /** The status chip (and its expiry), beside the pattern. */
  status: React.ReactNode
  /** What it covers or does, one muted line. */
  summary?: React.ReactNode
  /** Plain facts, one line that wraps between facts, never inside one. */
  facts: React.ReactNode[]
  /** The row menu, the same one the table row has. */
  actions?: React.ReactNode
  selection?: MobileRowSelection
  selectLabel?: string
}

export function ScopeRowCard({
  pattern,
  status,
  summary,
  facts,
  actions,
  selection,
  selectLabel,
}: ScopeRowCardProps) {
  return (
    <div
      data-slot="scope-row-card"
      data-state={selection?.selected ? 'selected' : undefined}
      className="flex w-full min-w-0 items-start gap-3 px-3 py-3 data-[state=selected]:bg-muted"
    >
      {selection?.selectable && (
        <Checkbox
          className="mt-0.5 shrink-0"
          checked={selection.selected}
          onCheckedChange={(v) => selection.onSelectedChange(!!v)}
          aria-label={selectLabel}
        />
      )}
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <div className="flex w-full min-w-0 items-start gap-2">
          <code className="line-clamp-2 min-w-0 flex-1 break-words font-mono text-sm font-medium">
            <BreakText>{pattern}</BreakText>
          </code>
          <div className="flex shrink-0 items-center gap-1">
            {status}
            {actions}
          </div>
        </div>
        {summary && <p className="truncate text-xs text-muted-foreground">{summary}</p>}
        {facts.length > 0 && (
          <p className="flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-muted-foreground">
            {facts.map((f, i) => (
              <span key={i} className="min-w-0 max-w-full truncate">
                {f}
              </span>
            ))}
          </p>
        )}
      </div>
    </div>
  )
}
