'use client'

import * as React from 'react'
import { X, type LucideIcon } from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { toDisplayText } from '@/lib/untrusted-text'

/**
 * Context filters: the filters a list receives from a deep link (an asset's
 * "View findings", a scan run's "View all findings"), as opposed to the facets
 * the user picks in the filter panel.
 *
 * They render INLINE in the table toolbar (pass the element in `toolbarStart`,
 * after the search box), never as a row of their own above the table: a row
 * that exists only when a chip does pushes the whole table down the moment the
 * page is opened with the parameter.
 *
 * Layout rules that keep the page still:
 * - The chips sit in the toolbar's existing row, after the search box. Where
 *   the row has room (desktop) they add no height at all. Where it has not (a
 *   phone, or a narrow table beside an open filter panel), the toolbar's own
 *   wrapping moves them to its next line, with readable chips rather than
 *   chips squeezed to nothing. Either way the chips come from the URL, so they
 *   are there from the first frame (also in the page's loading skeleton):
 *   nothing pops in after load.
 * - A chip whose label resolves later (an asset name fetched by id) has a FIXED
 *   label width, filled by a placeholder of exactly that width while loading,
 *   so the chip does not resize or flicker when the name arrives.
 * - Labels are attacker-influenced (an asset name can come from a scanned
 *   system), so they go through `toDisplayText` (React text only; control,
 *   line-break and bidi characters shown as escapes; length capped), render
 *   with `dir="auto"` and bidi isolation, and are truncated, with the full text
 *   in a tooltip and in the remove button's accessible name.
 */

/** Longest label kept for the tooltip / accessible name; the rest is cut. */
const MAX_LABEL_LENGTH = 200

export interface ContextFilterChip {
  /** The URL parameter this chip stands for; removing the chip removes only it. */
  param: string
  /** What the value is, shown before it: "Asset", "Scan", "CVE", "Rule". */
  kind: string
  /** The human label. Ignored while `loading`. */
  label?: string
  /** True while the label is being resolved (renders a same-size placeholder). */
  loading?: boolean
  /**
   * Give the label a fixed width. Set it for any chip whose label resolves
   * asynchronously, so the chip keeps one size from the first frame on.
   */
  fixedWidth?: boolean
  /** Monospace label (identifiers such as a CVE id). */
  mono?: boolean
  icon?: LucideIcon
}

export interface ContextFilterChipsProps {
  chips: ContextFilterChip[]
  /** Remove one chip: drop its URL parameter and keep every other filter. */
  onRemove: (param: string) => void
  className?: string
}

function clampLabel(label: string): string {
  return toDisplayText(label.trim(), MAX_LABEL_LENGTH)
}

function Chip({ chip, onRemove }: { chip: ContextFilterChip; onRemove: (param: string) => void }) {
  const Icon = chip.icon
  // "asset filter", but "CVE filter": acronyms keep their case.
  const kindLower = chip.kind === chip.kind.toUpperCase() ? chip.kind : chip.kind.toLowerCase()
  const label = chip.loading ? '' : clampLabel(chip.label ?? '')
  const removeLabel = chip.loading
    ? `Remove ${kindLower} filter`
    : `Remove ${kindLower} filter: ${label}`

  const body = (
    <li
      data-testid={`context-chip-${chip.param}`}
      aria-busy={chip.loading || undefined}
      className="inline-flex h-7 min-w-0 max-w-full items-center gap-1.5 rounded-md border bg-secondary ps-2 pe-0.5 text-xs text-secondary-foreground"
    >
      {Icon && <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />}
      <span className="shrink-0 text-muted-foreground">{chip.kind}</span>
      <span
        data-testid={`context-chip-${chip.param}-label`}
        dir="auto"
        className={cn(
          'min-w-0 truncate font-medium [unicode-bidi:isolate]',
          chip.fixedWidth ? 'w-32' : 'max-w-40',
          chip.mono && 'font-mono'
        )}
      >
        {chip.loading ? (
          <>
            <span
              data-testid={`context-chip-${chip.param}-placeholder`}
              className="block h-3 w-full animate-pulse rounded-sm bg-muted-foreground/20 motion-reduce:animate-none"
              aria-hidden
            />
            <span className="sr-only">Loading</span>
          </>
        ) : (
          label
        )}
      </span>
      <button
        type="button"
        onClick={() => onRemove(chip.param)}
        aria-label={removeLabel}
        className="relative inline-flex h-6 w-6 shrink-0 cursor-pointer items-center justify-center rounded-sm text-muted-foreground transition-colors duration-150 after:absolute after:-inset-1 hover:bg-background/70 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <X className="h-3.5 w-3.5" aria-hidden />
      </button>
    </li>
  )

  // Always wrapped (also while loading): swapping the wrapper when the label
  // arrives would remount the chip and drop keyboard focus from its button.
  // The tooltip also opens when that button takes focus (focus bubbles to the
  // trigger), so the full name is reachable without a mouse.
  return (
    <Tooltip>
      <TooltipTrigger asChild>{body}</TooltipTrigger>
      <TooltipContent className="max-w-sm break-words">
        {chip.kind}: {chip.loading ? 'loading…' : label}
      </TooltipContent>
    </Tooltip>
  )
}

/**
 * Inline, removable context-filter chips for a table toolbar. Renders nothing
 * when there are no chips.
 */
export function ContextFilterChips({ chips, onRemove, className }: ContextFilterChipsProps) {
  if (chips.length === 0) return null
  return (
    <ul
      aria-label="Context filters"
      data-testid="context-filter-chips"
      className={cn(
        // Natural width, never wider than the toolbar: inline in the toolbar
        // row where it fits; where it does not, the toolbar's wrap carries the
        // whole list to its next line (and chips wrap among themselves on a
        // phone) instead of squeezing labels to nothing or scrolling sideways.
        'flex min-w-0 max-w-full flex-wrap items-center gap-1.5',
        className
      )}
    >
      {chips.map((chip) => (
        <Chip key={chip.param} chip={chip} onRemove={onRemove} />
      ))}
    </ul>
  )
}
