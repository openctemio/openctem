'use client'

import * as React from 'react'
import { Lock, type LucideIcon } from 'lucide-react'
import Link from '@/components/link'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { foldToFit } from '@/lib/fit-row'

/**
 * The active-filter row under a list toolbar (research/267, research/266 §5),
 * passed as `ListToolbar`'s / `DataTable`'s `below`. One line with fixed
 * places:
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
 * Nothing in the row shrinks under its content, so no element is ever drawn
 * over its neighbour. When the leading chip, the trailing actions, the count
 * and at least "+N more" do not fit on one line (a phone), the leading chip
 * takes a line of its own above the rest (`data-stacked`), where it truncates
 * its text only if even that line is too narrow.
 *
 * Widths are measured on the row (ResizeObserver on the row and on each fixed
 * block); each chip's width is cached by its key while it is shown, so
 * folding never re-renders in a loop. Where nothing can be measured (jsdom)
 * every chip shows.
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
const BLOCK_GAP = 8 // gap-2 between the row's blocks
const MORE_WIDTH = 88 // room kept for the "+N more" chip

export interface ChipsRowWidths {
  /** The row's inner width. */
  total: number
  /** Natural width of the leading block (0 when there is none). */
  lead: number
  /** Width of the trailing actions (0 when there are none). */
  trail: number
  /** Width of the count (0 when there is none). */
  end: number
  /** Width of each chip, in order. */
  chips: number[]
}

export interface ChipsRowFit {
  /** How many chips show; the rest fold into "+N more". */
  fit: number
  /** The leading block takes its own line above the chips. */
  stacked: boolean
}

/**
 * How the row lays out at these widths. Pure, so the folding rules are tested
 * without a layout engine.
 */
export function fitChipsRow({ total, lead, trail, end, chips }: ChipsRowWidths): ChipsRowFit {
  const n = chips.length
  const chipsWidth = chips.reduce((s, x) => s + x, 0) + GAP * Math.max(0, n - 1)
  // Room left for the chips block on a line that also holds `blocks`, each
  // separated from the chips block by one gap.
  const room = (blocks: number[]) => {
    const present = blocks.filter((w) => w > 0)
    return total - present.reduce((s, w) => s + w + BLOCK_GAP, 0)
  }
  const fold = (avail: number) => foldToFit(avail, chips, GAP, MORE_WIDTH)

  if (lead > 0) {
    const oneLine = room([lead, trail, end])
    // With no chips there is no chips block, and so one gap fewer.
    const fits = n === 0 ? oneLine + BLOCK_GAP >= 0 : oneLine >= Math.min(chipsWidth, MORE_WIDTH)
    if (fits) return { fit: fold(oneLine), stacked: false }
    return { fit: fold(room([trail, end])), stacked: true }
  }
  return { fit: fold(room([trail, end])), stacked: false }
}

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
  const [layout, setLayout] = React.useState<ChipsRowFit>({ fit: chips.length, stacked: false })
  const [tick, setTick] = React.useState(0)
  const keys = chips.map(keyOf)
  const hasLead = !!leading
  const hasTrail = !!trailing
  const hasEnd = !!end

  // Re-measure when the row or a fixed block changes size (the leading chip's
  // count arrives after its own request, without re-rendering this row).
  React.useEffect(() => {
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => setTick((n) => n + 1))
    for (const el of [rowRef.current, leadRef.current, trailRef.current, endRef.current]) {
      if (el) ro.observe(el)
    }
    return () => ro.disconnect()
  }, [hasLead, hasTrail, hasEnd])

  React.useLayoutEffect(() => {
    const row = rowRef.current
    if (!row) return
    const set = (next: ChipsRowFit) => {
      if (next.fit !== layout.fit || next.stacked !== layout.stacked) setLayout(next)
    }
    // Cache the width of every chip on screen.
    Array.from(listRef.current?.children ?? []).forEach((li) => {
      const k = (li as HTMLElement).dataset.chipKey
      const w = (li as HTMLElement).offsetWidth
      if (k && w > 0) widths.current.set(k, w)
    })
    const total = row.clientWidth
    if (total === 0) return set({ fit: chips.length, stacked: false })
    // A chip never measured yet: show them all once to measure.
    if (keys.some((k) => !widths.current.has(k))) {
      return set({ fit: chips.length, stacked: layout.stacked })
    }
    set(
      fitChipsRow({
        total,
        // The leading block is `w-max`: its natural width, whatever line it is on.
        lead: leadRef.current?.offsetWidth ?? 0,
        trail: trailRef.current?.offsetWidth ?? 0,
        end: endRef.current?.offsetWidth ?? 0,
        chips: keys.map((k) => widths.current.get(k) ?? 0),
      })
    )
    // Runs after every render that changes the chips (a new array each
    // render); it only sets state when the layout changes, and the layout
    // does not change the widths it reads, so it settles.
  }, [keys, tick, layout, chips.length])

  const { fit, stacked } = layout
  const shown = chips.slice(0, fit)
  const hidden = chips.slice(fit)

  return (
    <div
      ref={rowRef}
      data-slot="filter-chips-row"
      data-testid={testId}
      data-stacked={stacked ? '' : undefined}
      className={cn(
        'flex w-full min-w-0 items-center gap-2 overflow-hidden',
        stacked ? 'flex-wrap' : 'flex-nowrap',
        className
      )}
    >
      {leading ? (
        <div
          data-slot="filter-chips-leading"
          className={cn('flex min-w-0 max-w-full', stacked ? 'basis-full' : 'shrink-0')}
        >
          <div ref={leadRef} className="flex w-max max-w-full min-w-0 items-center gap-2">
            {leading}
          </div>
        </div>
      ) : null}
      {chips.length > 0 ? (
        <ul
          ref={listRef}
          aria-label={label ?? t('common.filterChips.label', 'Active filters')}
          className="flex shrink-0 flex-nowrap items-center gap-1.5 empty:hidden"
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
        <div
          ref={trailRef}
          data-slot="filter-chips-trailing"
          className="flex shrink-0 items-center gap-2"
        >
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
 * What a list always leaves out, as a quiet chip first in the filter row: an
 * icon (a lock by default), the sentence, and optional actions ("Show"). Not
 * removable, because it states a rule of the list rather than a filter the
 * viewer set. Its text truncates; the icon and the actions never do.
 */
export function LockedChip({
  children,
  hint,
  icon: Icon = Lock,
  actionLabel,
  onAction,
  actions,
  'data-testid': testId,
  'data-state': state,
}: {
  children: React.ReactNode
  /** Why the list hides it (tooltip). */
  hint?: React.ReactNode
  /** The leading icon; null for none. */
  icon?: LucideIcon | null
  actionLabel?: string
  onAction?: () => void
  /** More than one action (each a `LockedChipAction`), after `actionLabel`'s. */
  actions?: React.ReactNode
  'data-testid'?: string
  'data-state'?: string
}) {
  const body = (
    <span className="inline-flex min-w-0 items-center gap-1.5" tabIndex={hint ? 0 : undefined}>
      {Icon ? <Icon className="size-3.5 shrink-0" aria-hidden="true" /> : null}
      <span className="truncate">{children}</span>
    </span>
  )
  return (
    <span
      data-slot="locked-chip"
      data-testid={testId}
      data-state={state}
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
        <LockedChipAction onClick={onAction}>{actionLabel}</LockedChipAction>
      ) : null}
      {actions}
    </span>
  )
}

/** An action inside a `LockedChip` ("Show", "Hide"); a link when `href` is set. */
export function LockedChipAction({
  children,
  onClick,
  href,
  disabled,
}: {
  children: React.ReactNode
  onClick?: () => void
  href?: string
  disabled?: boolean
}) {
  const className =
    'inline-flex h-5 shrink-0 items-center rounded-full px-2 font-medium whitespace-nowrap text-foreground hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-50'
  if (href) {
    return (
      <Link href={href} className={className}>
        {children}
      </Link>
    )
  }
  return (
    <button type="button" onClick={onClick} disabled={disabled} className={className}>
      {children}
    </button>
  )
}
