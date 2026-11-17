'use client'

import * as React from 'react'
import { Lock, type LucideIcon } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { EDGE_FADE_X_CLASS, useTabStripScroll } from '@/components/ui/tabs'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { useIsMobile } from '@/hooks/use-mobile'
import { foldToFit } from '@/lib/fit-row'
import { safeInternalHref } from '@/lib/safe-href'

/**
 * The active-filter row under a list toolbar (research/267, research/266 §5),
 * passed as `ListToolbar`'s / `DataTable`'s `below`. Exactly one line, of one
 * height, with fixed places:
 *
 *   [locked chip] [chip] [chip] [+N more] ...... [Reset to view] [Clear filters]
 *
 * - `leading`: what the list always hides (`LockedChip`), first, never folded;
 *   at most half the row (its text shortens, in full in its title).
 * - `chips`: the removable filter chips, one element each (keyed). The ones
 *   that do not fit fold into "+N more", a popover listing them, each still
 *   removable there. Never a second line.
 * - `trailing`: the list's own actions (Reset to view), then Clear filters
 *   (`onClearAll`), drawn by the row so it sits in the same place, with the
 *   same look, on every list: pinned to the row's end, so nothing to its
 *   right can move it, and a chip coming or going never moves them.
 *
 * The row carries no count: a list says its count once, in its title row
 * (`ListCount`).
 *
 * On a phone (under 768px) nothing folds: the chips scroll sideways in their
 * own strip, with a fade on an edge that has more chips past it, so a chip is
 * never cut without a cue and never hidden behind "+N more". At rest the strip
 * starts at its first chip (scrolled back to the start whenever the chips
 * change), so only its end can fade; a leading chip wider than the strip
 * shortens its text (ellipsis, full text in its title) and keeps its icon and
 * actions. The row clips (`overflow: clip`) rather than hides: a hidden box is
 * still a scroll container that focus or `scrollIntoView` can shift sideways,
 * which cut the first chip at the start with no fade.
 *
 * Nothing in the row shrinks under its content, so no element is ever drawn
 * over its neighbour: what does not fit folds into "+N more".
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
  /**
   * Remove every filter the viewer set. Pass it while two or more can be
   * removed (one chip has its own X); the row draws "Clear filters" after
   * `trailing`.
   */
  onClearAll?: () => void
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
  /** Width of the end block: count, list actions, Clear (0 when empty). */
  end: number
  /** Width of each chip, in order. */
  chips: number[]
}

export interface ChipsRowFit {
  /** How many chips show; the rest fold into "+N more". */
  fit: number
}

/**
 * How the row lays out at these widths. Pure, so the folding rules are tested
 * without a layout engine.
 */
export function fitChipsRow({ total, lead, end, chips }: ChipsRowWidths): ChipsRowFit {
  // Room left for the chips block beside the leading block and the end
  // block, each separated from it by one gap.
  const room = total - [lead, end].filter((w) => w > 0).reduce((s, w) => s + w + BLOCK_GAP, 0)
  return { fit: foldToFit(room, chips, GAP, MORE_WIDTH) }
}

function keyOf(el: React.ReactElement, i: number): string {
  return el.key != null ? String(el.key) : `#${i}`
}

export function FilterChipsRow({
  chips,
  leading,
  trailing: trailingProp,
  onClearAll,
  label,
  className,
  'data-testid': testId,
}: FilterChipsRowProps) {
  const { t } = useTranslation()
  const rowRef = React.useRef<HTMLDivElement>(null)
  const listRef = React.useRef<HTMLUListElement>(null)
  const leadRef = React.useRef<HTMLDivElement>(null)
  const endRef = React.useRef<HTMLDivElement>(null)
  const widths = React.useRef(new Map<string, number>())
  const trailing =
    trailingProp || onClearAll ? (
      <>
        {trailingProp}
        {onClearAll ? (
          <Button variant="ghost" size="sm" data-slot="filter-chips-clear" onClick={onClearAll}>
            {t('common.filterChips.clear', 'Clear filters')}
          </Button>
        ) : null}
      </>
    ) : null
  const [fit, setFit] = React.useState(chips.length)
  const [tick, setTick] = React.useState(0)
  const keys = chips.map(keyOf)
  const hasLead = !!leading
  const hasEnd = !!trailing
  // A phone scrolls the chips sideways instead of folding them.
  const scroll = useIsMobile()
  const stripRef = React.useRef<HTMLDivElement>(null)
  useTabStripScroll(stripRef, scroll)

  // At rest a phone strip starts at its first chip: a new chip set (a filter
  // added or removed, the leading chip arriving) scrolls it back to the start.
  const chipSet = JSON.stringify([hasLead, keys])
  React.useLayoutEffect(() => {
    const strip = stripRef.current
    if (scroll && strip && strip.scrollLeft !== 0) strip.scrollLeft = 0
  }, [scroll, chipSet])

  // Re-measure when the row or a fixed block changes size (the leading chip's
  // count arrives after its own request, without re-rendering this row).
  React.useEffect(() => {
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => setTick((n) => n + 1))
    for (const el of [rowRef.current, leadRef.current, endRef.current]) {
      if (el) ro.observe(el)
    }
    return () => ro.disconnect()
  }, [hasLead, hasEnd])

  React.useLayoutEffect(() => {
    const row = rowRef.current
    if (!row) return
    const set = (next: ChipsRowFit) => {
      if (next.fit !== fit) setFit(next.fit)
    }
    // Cache the width of every chip on screen.
    Array.from(listRef.current?.children ?? []).forEach((li) => {
      const k = (li as HTMLElement).dataset.chipKey
      const w = (li as HTMLElement).offsetWidth
      if (k && w > 0) widths.current.set(k, w)
    })
    const total = row.clientWidth
    if (total === 0) return set({ fit: chips.length })
    // A phone: every chip shows, the leading chip first, in one strip that
    // scrolls.
    if (scroll) return set({ fit: chips.length })
    // A chip never measured yet: show them all once to measure (the row
    // clips, so this never takes a second line).
    if (keys.some((k) => !widths.current.has(k))) return set({ fit: chips.length })
    set(
      fitChipsRow({
        total,
        // The leading block is `w-max` up to half the row: the same width
        // whatever the chips.
        lead: leadRef.current?.offsetWidth ?? 0,
        end: endRef.current?.offsetWidth ?? 0,
        chips: keys.map((k) => widths.current.get(k) ?? 0),
      })
    )
    // Runs after every render that changes the chips (a new array each
    // render); it only sets state when the fit changes, and the fit does not
    // change the widths it reads, so it settles.
  }, [keys, tick, fit, chips.length, scroll])

  // Nothing but (maybe) the leading chip: the toolbar hides the row while
  // that chip renders nothing (ListToolbar's `below`), so no empty line shows.
  const bare = chips.length === 0 && !trailing
  if (bare && !leading) return null
  const shown = chips.slice(0, fit)
  const hidden = chips.slice(fit)

  return (
    <div
      ref={rowRef}
      data-slot="filter-chips-row"
      data-testid={testId}
      data-bare={bare ? '' : undefined}
      className={cn(
        // One line of one height: it never wraps and never grows.
        'flex h-control w-full min-w-0 flex-nowrap items-center gap-2 overflow-clip max-md:h-control-touch',
        className
      )}
    >
      {/* The strip: on a phone the leading chip and the chips scroll sideways
          together (fade on an edge with more past it); elsewhere it draws no
          box and the row folds. Always mounted, so the fade attaches once. */}
      <div
        ref={stripRef}
        data-slot="filter-chips-strip"
        data-scroll={scroll ? '' : undefined}
        className={
          scroll
            ? cn(
                // The padding keeps focus rings inside the scroll box.
                'no-scrollbar -my-1 flex min-w-0 flex-1 flex-nowrap items-center gap-2 overflow-x-auto overflow-y-hidden overscroll-x-contain py-1',
                EDGE_FADE_X_CLASS
              )
            : 'contents'
        }
      >
        {leading ? (
          <div
            data-slot="filter-chips-leading"
            className={cn(
              'flex',
              // In the phone strip it keeps its width up to the strip's, then
              // its text shortens (never cut at either edge).
              scroll ? 'max-w-full shrink-0' : 'max-w-[50%] min-w-0 shrink-0'
            )}
          >
            <div
              ref={leadRef}
              data-slot="filter-chips-lead"
              className="flex w-max max-w-full min-w-0 items-center gap-2"
            >
              {leading}
            </div>
          </div>
        ) : null}
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
      </div>
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
          <PopoverContent className="w-auto max-w-sm p-2">
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
          ref={endRef}
          data-slot="filter-chips-end"
          className="ms-auto flex shrink-0 items-center gap-2"
        >
          <div data-slot="filter-chips-trailing" className="flex items-center gap-2">
            {trailing}
          </div>
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
      <span className="truncate" title={typeof children === 'string' ? children : undefined}>
        {children}
      </span>
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
  const safe = safeInternalHref(href)
  if (safe) {
    return (
      <Link href={safe} className={className}>
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
