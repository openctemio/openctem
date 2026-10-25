'use client'

import * as React from 'react'
import { Lock } from 'lucide-react'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * The active-filter row under a list toolbar (research/267, research/266 §5),
 * passed as `ListToolbar`'s / `DataTable`'s `below`. One line that never wraps,
 * with fixed places:
 *
 *   [locked chip] [chip] [chip] [+N more] [+ Add filter] [Clear filters] ...... [count]
 *
 * - `leading`: what the list always hides (`LockedChip`), first, never folded.
 * - `chips`: the removable filter chips, one element each (keyed). The ones
 *   that do not fit fold into "+N more", a popover listing them, each still
 *   removable there.
 * - `trailing`: Add filter, then Clear filters; right after the visible chips.
 * - `end`: the result count, pinned to the far end so it never moves when a
 *   chip comes or goes.
 *
 * Widths are measured on the row (ResizeObserver); each chip's width is cached
 * by its key while it is shown, so folding never re-renders in a loop. Where
 * nothing can be measured (jsdom) every chip shows.
 */
export interface FilterChipsRowProps {
  chips: React.ReactElement[]
  leading?: React.ReactNode
  trailing?: React.ReactNode
  end?: React.ReactNode
  /** Accessible name of the chip list, e.g. "Active filters". */
  label?: string
  className?: string
  'data-testid'?: string
}

const GAP = 6 // gap-1.5 between chips
const MORE_WIDTH = 88 // room kept for the "+N more" chip

function keyOf(el: React.ReactElement, i: number): string {
  return el.key != null ? String(el.key) : `#${i}`
}

export function FilterChipsRow({
  chips,
  leading,
  trailing,
  end,
  label,
  className,
  'data-testid': testId,
}: FilterChipsRowProps) {
  const { t } = useTranslation()
  const rowRef = React.useRef<HTMLDivElement>(null)
  const listRef = React.useRef<HTMLUListElement>(null)
  const leadRef = React.useRef<HTMLDivElement>(null)
  const trailRef = React.useRef<HTMLDivElement>(null)
  const endRef = React.useRef<HTMLDivElement>(null)
  const widths = React.useRef(new Map<string, number>())
  const [fit, setFit] = React.useState(chips.length)
  const [tick, setTick] = React.useState(0)
  const keys = chips.map(keyOf)
  const keySig = keys.join('|')

  // Re-measure when the row changes size.
  React.useEffect(() => {
    const row = rowRef.current
    if (!row || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => setTick((n) => n + 1))
    ro.observe(row)
    return () => ro.disconnect()
  }, [])

  React.useLayoutEffect(() => {
    const row = rowRef.current
    const list = listRef.current
    if (!row || !list) return
    // Cache the width of every chip on screen.
    Array.from(list.children).forEach((li) => {
      const k = (li as HTMLElement).dataset.chipKey
      const w = (li as HTMLElement).offsetWidth
      if (k && w > 0) widths.current.set(k, w)
    })
    const total = row.clientWidth
    if (total === 0) {
      if (fit !== chips.length) setFit(chips.length)
      return
    }
    // A chip never measured yet: show them all once to measure.
    if (keys.some((k) => !widths.current.has(k))) {
      if (fit !== chips.length) setFit(chips.length)
      return
    }
    const fixed = [leadRef.current, trailRef.current, endRef.current].reduce(
      (sum, el) => sum + (el ? el.offsetWidth + 8 : 0), // + gap-2 to the next block
      0
    )
    const avail = total - fixed
    const w = keys.map((k) => widths.current.get(k) ?? 0)
    const all = w.reduce((s, x) => s + x, 0) + GAP * Math.max(0, w.length - 1)
    let next = chips.length
    if (all > avail) {
      next = 0
      let used = MORE_WIDTH
      for (const x of w) {
        if (used + x + GAP > avail) break
        used += x + GAP
        next += 1
      }
    }
    if (next !== fit) setFit(next)
    // keySig and tick are the triggers; fit is read, not a dependency loop.
  }, [keySig, tick, fit, chips.length]) // eslint-disable-line react-hooks/exhaustive-deps

  const shown = chips.slice(0, fit)
  const hidden = chips.slice(fit)

  return (
    <div
      ref={rowRef}
      data-slot="filter-chips-row"
      data-testid={testId}
      className={cn('flex min-w-0 flex-nowrap items-center gap-2 overflow-hidden', className)}
    >
      {leading ? (
        <div ref={leadRef} className="flex min-w-0 shrink items-center">
          {leading}
        </div>
      ) : null}
      {chips.length > 0 ? (
        <ul
          ref={listRef}
          aria-label={label ?? t('common.filterChips.label', 'Active filters')}
          className="flex shrink-0 flex-nowrap items-center gap-1.5"
        >
          {shown.map((chip, i) => (
            <li key={keys[i]} data-chip-key={keys[i]} className="flex shrink-0">
              {chip}
            </li>
          ))}
        </ul>
      ) : null}
      {hidden.length > 0 ? (
        <Popover>
          <PopoverTrigger asChild>
            <button
              type="button"
              data-slot="filter-chips-more"
              className="inline-flex h-7 shrink-0 items-center rounded-full border border-dashed px-2.5 text-xs font-medium text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            >
              {t('common.filterChips.more', '+{count} more', { count: hidden.length })}
            </button>
          </PopoverTrigger>
          <PopoverContent align="start" className="w-auto max-w-sm p-2">
            <ul
              aria-label={t('common.filterChips.moreLabel', 'More filters')}
              className="flex flex-col items-start gap-1.5"
            >
              {hidden.map((chip, i) => (
                <li key={keys[fit + i]} className="flex max-w-full">
                  {chip}
                </li>
              ))}
            </ul>
          </PopoverContent>
        </Popover>
      ) : null}
      {trailing ? (
        <div ref={trailRef} className="flex shrink-0 items-center gap-2">
          {trailing}
        </div>
      ) : null}
      {end ? (
        <div
          ref={endRef}
          data-slot="filter-chips-end"
          className="ms-auto flex shrink-0 items-center text-xs tabular-nums text-muted-foreground"
        >
          {end}
        </div>
      ) : null}
    </div>
  )
}

/**
 * What a list always leaves out, as a quiet chip first in the filter row: a
 * lock, the sentence, and an optional action ("Show"). Not removable, because
 * it states a rule of the list rather than a filter the viewer set.
 */
export function LockedChip({
  children,
  hint,
  actionLabel,
  onAction,
  'data-testid': testId,
}: {
  children: React.ReactNode
  /** Why the list hides it (tooltip). */
  hint?: React.ReactNode
  actionLabel?: string
  onAction?: () => void
  'data-testid'?: string
}) {
  const body = (
    <span className="inline-flex min-w-0 items-center gap-1.5" tabIndex={hint ? 0 : undefined}>
      <Lock className="size-3.5 shrink-0" aria-hidden="true" />
      <span className="truncate">{children}</span>
    </span>
  )
  return (
    <span
      data-slot="locked-chip"
      data-testid={testId}
      className="inline-flex h-7 max-w-full min-w-0 items-center gap-1.5 rounded-full border border-dashed ps-2.5 pe-1 text-xs text-muted-foreground"
    >
      {hint ? (
        <Tooltip>
          <TooltipTrigger asChild>{body}</TooltipTrigger>
          <TooltipContent className="max-w-xs">{hint}</TooltipContent>
        </Tooltip>
      ) : (
        body
      )}
      {actionLabel && onAction ? (
        <button
          type="button"
          onClick={onAction}
          className="inline-flex h-5 shrink-0 items-center rounded-full px-2 font-medium text-foreground hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          {actionLabel}
        </button>
      ) : null}
    </span>
  )
}
