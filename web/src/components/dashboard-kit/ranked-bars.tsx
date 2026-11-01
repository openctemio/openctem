'use client'

/**
 * A ranked bar list: one row per item (name, a kind chip, a bar scaled to the
 * largest value in view, the value), the largest first. When the data
 * refreshes and an item changes place, rows slide to their new place (FLIP,
 * 220 ms ease-out; none under reduced motion) and the item that moved shows
 * a small rank-change marker until the next refresh; one polite live message
 * names the biggest climber. Rows are keyed by item, never by position.
 *
 * Folding: healthy items with nothing in the window fold into one line that
 * expands on tap; an unhealthy item stays in view at 0 (health matters more
 * than volume). Above `limit` rows with a value, "Show all" expands the rest.
 * Every row is a link to its list (FlowLink: plain text without a safe
 * same-origin path) at least 44 px tall. Colours: the bar is the item's own
 * colour when the visual draws the item elsewhere too (a ring segment), else
 * the brand marker (teal), on a muted track; health is a dot plus words that
 * wrap under the name (never cut off), never colour alone.
 */

import { useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { FlowLink, tCount } from './flow-parts'
import { usePrefersReducedMotion } from './viz-parts'
import type { SourceHealth } from './types'

export interface RankedBarRow {
  /** Stable identity (keeps rank changes and screen readers stable). */
  key: string
  label: string
  /** A short kind chip ("Sensor", "CI", "Platform"). */
  chip?: string
  value: number
  /** The value as shown (formatted); defaults to the number. */
  display?: string
  href?: string | null
  /** The item's colour where it is drawn elsewhere too (CSS colour); default teal. */
  color?: string
  health?: SourceHealth
  /** Words for an unhealthy item ("Stale, last receipt 3 days ago"). */
  note?: string | null
  /**
   * The figure with its unit ("26 findings"), read in place of the bare figure.
   * The row's link is named by its own text (label, chip, figure, note), so the
   * name always holds what is visible; an aria-label that rewrote it would not.
   */
  unit?: string
}

/** Rows in rank order: value descending, then label, then key (stable). */
export function rankRows<T extends RankedBarRow>(rows: T[]): T[] {
  return [...rows].sort(
    (a, b) => b.value - a.value || a.label.localeCompare(b.label) || a.key.localeCompare(b.key)
  )
}

/**
 * Which rows show and which fold: `zeros` are healthy rows with nothing,
 * `rest` the rows with a value past `limit`. An unhealthy row is never folded
 * as a zero.
 */
export function splitRanked<T extends RankedBarRow>(
  ranked: T[],
  limit: number
): { shown: T[]; rest: T[]; zeros: T[] } {
  const zeros = ranked.filter((r) => r.value === 0 && (r.health ?? 'ok') === 'ok')
  const live = ranked.filter((r) => !zeros.includes(r))
  return { shown: live.slice(0, limit), rest: live.slice(limit), zeros }
}

/** Rank changes between two orders: key -> places climbed (positive) or fell. */
export function rankMoves(before: string[], after: string[]): Record<string, number> {
  const out: Record<string, number> = {}
  const was = new Map(before.map((k, i) => [k, i]))
  after.forEach((k, i) => {
    const w = was.get(k)
    if (w != null && w !== i) out[k] = w - i
  })
  return out
}

const MOVE_MS = 220

export function RankedBars({
  rows,
  limit,
  label,
  zeroLabel,
  resetKey,
  rowProps,
  className,
  listClassName,
  testId = 'ranked-bars',
}: {
  rows: RankedBarRow[]
  /** Rows with a value shown before "Show all". */
  limit: number
  /** The list's accessible name. */
  label: string
  /** The fold line for healthy zeros, given their count ("+5 with nothing in 30 days"). */
  zeroLabel: (count: number) => string
  /** Changes when the user switches what is ranked (measure, grouping): re-sort without rank markers. */
  resetKey?: string
  /** Extra props for a row's link (focus/tooltip binding, wire anchors). */
  rowProps?: (row: RankedBarRow) => Record<string, unknown>
  className?: string
  /** Classes of the list itself (columns at a width). */
  listClassName?: string
  testId?: string
}) {
  const { t } = useTranslation()
  const reduced = usePrefersReducedMotion()
  const [showRest, setShowRest] = useState(false)
  const [showZeros, setShowZeros] = useState(false)
  const ranked = useMemo(() => rankRows(rows), [rows])
  const { shown, rest, zeros } = useMemo(() => splitRanked(ranked, limit), [ranked, limit])
  const visible = useMemo(
    () => [...shown, ...(showRest ? rest : []), ...(showZeros ? zeros : [])],
    [shown, rest, zeros, showRest, showZeros]
  )
  const max = Math.max(1, ...visible.map((r) => r.value))
  const order = ranked.map((r) => r.key)
  const orderSig = order.join('\u0000')

  const nodes = useRef(new Map<string, HTMLElement>())
  const rects = useRef(new Map<string, DOMRect>())
  const prev = useRef<{ order: string[]; reset: string | undefined } | null>(null)
  const [moves, setMoves] = useState<Record<string, number>>({})
  const [announce, setAnnounce] = useState('')

  // FLIP: rows that changed place start from where they were and slide in.
  useLayoutEffect(() => {
    const before = prev.current
    const userSwitch = before != null && before.reset !== resetKey
    if (before && before.order.join('\u0000') !== orderSig) {
      if (!userSwitch) {
        const m = rankMoves(before.order, order)
        setMoves(m)
        const best = Object.entries(m).sort((a, b) => b[1] - a[1])[0]
        if (best && best[1] > 0) {
          const row = ranked.find((r) => r.key === best[0])
          const rank = order.indexOf(best[0]) + 1
          if (row) {
            setAnnounce(
              t('dashboardKit.ranked.moved', '{name} moved to number {rank}', {
                name: row.label,
                rank,
              })
            )
          }
        }
      } else {
        setMoves({})
      }
      if (!reduced) {
        nodes.current.forEach((el, key) => {
          const from = rects.current.get(key)
          if (!from || typeof el.animate !== 'function') return
          const to = el.getBoundingClientRect()
          const dx = from.left - to.left
          const dy = from.top - to.top
          if (Math.abs(dy) < 1 && Math.abs(dx) < 1) return
          el.animate([{ transform: `translate(${dx}px, ${dy}px)` }, { transform: 'none' }], {
            duration: MOVE_MS,
            easing: 'cubic-bezier(0.2, 0, 0, 1)',
          })
        })
      }
    }
    prev.current = { order, reset: resetKey }
    const next = new Map<string, DOMRect>()
    nodes.current.forEach((el, key) => next.set(key, el.getBoundingClientRect()))
    rects.current = next
    // order is derived from orderSig; ranked/t only label the message.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orderSig, resetKey, reduced])

  const row = (r: RankedBarRow): ReactNode => {
    const { className: extraClass, ...extra } = (rowProps?.(r) ?? {}) as { className?: string }
    const move = moves[r.key]
    const display = r.display ?? String(r.value)
    const pct = r.value > 0 ? Math.max(2, (100 * r.value) / max) : 0
    return (
      <li
        key={r.key}
        ref={(el) => {
          if (el) nodes.current.set(r.key, el)
          else nodes.current.delete(r.key)
        }}
        data-key={r.key}
      >
        <FlowLink
          to={r.href}
          className={cn(
            'grid min-h-11 grid-cols-[minmax(0,1fr)_auto] content-center items-center gap-x-2 gap-y-1 rounded-md px-2 py-1.5 hover:bg-muted/60 focus-visible:bg-muted/60',
            extraClass
          )}
          data-health={r.health ?? 'ok'}
          {...extra}
        >
          <span className="flex min-w-0 items-center gap-1.5">
            {r.health && r.health !== 'ok' && (
              <span
                className={cn(
                  'size-2 shrink-0 rounded-full',
                  r.health === 'failed' ? 'bg-destructive' : 'bg-warning'
                )}
                aria-hidden
              />
            )}
            <span className="truncate text-sm font-medium">{r.label}</span>
            {r.chip && ' '}
            {r.chip && (
              <span className="shrink-0 rounded border px-1 text-xs leading-4 text-muted-foreground">
                {r.chip}
              </span>
            )}
            {move != null && (
              <span
                className={cn(
                  'inline-flex shrink-0 items-center text-xs tabular-nums',
                  move > 0 ? 'text-signal-text' : 'text-muted-foreground'
                )}
                data-testid="rank-move"
                aria-hidden
              >
                {move > 0 ? (
                  <ChevronUp className="size-3" aria-hidden />
                ) : (
                  <ChevronDown className="size-3" aria-hidden />
                )}
                {Math.abs(move)}
              </span>
            )}
          </span>{' '}
          <span className="text-right text-base font-semibold tabular-nums leading-none">
            <span aria-hidden={r.unit ? true : undefined}>{display}</span>
            {r.unit && <span className="sr-only"> {r.unit}</span>}
          </span>
          <span className="col-span-2 flex h-1.5 overflow-hidden rounded-full bg-muted" aria-hidden>
            <span
              className={cn('rounded-full', !r.color && 'bg-signal')}
              style={{ width: `${pct}%`, background: r.color }}
              data-testid="ranked-bar"
            />
          </span>
          {r.note && (
            <span
              className={cn(
                'col-span-2 text-xs text-pretty break-words',
                r.health === 'failed' ? 'text-destructive' : 'text-warning'
              )}
            >
              {r.note}
            </span>
          )}
        </FlowLink>
      </li>
    )
  }

  return (
    <div className={cn('grid gap-1', className)} data-testid={testId}>
      <ol className={cn('grid gap-0.5', listClassName)} aria-label={label}>
        {visible.map(row)}
      </ol>
      {(rest.length > 0 || zeros.length > 0) && (
        <div className="flex flex-wrap gap-x-3">
          {rest.length > 0 && (
            <button
              type="button"
              className="min-h-11 px-2 text-left text-xs font-medium text-signal-text hover:underline"
              aria-expanded={showRest}
              onClick={() => setShowRest((v) => !v)}
            >
              {showRest
                ? t('dashboardKit.ranked.showFewer', 'Show fewer')
                : t('dashboardKit.ranked.showAll', 'Show all {count}', {
                    count: shown.length + rest.length,
                  })}
            </button>
          )}
          {zeros.length > 0 && (
            <button
              type="button"
              className="min-h-11 px-2 text-left text-xs text-muted-foreground hover:text-foreground hover:underline"
              aria-expanded={showZeros}
              onClick={() => setShowZeros((v) => !v)}
              data-testid="ranked-zeros"
            >
              {showZeros
                ? tCount(
                    t,
                    'dashboardKit.ranked.hideZeros',
                    'Hide {count} with nothing',
                    'Hide {count} with nothing',
                    zeros.length,
                    { count: zeros.length }
                  )
                : zeroLabel(zeros.length)}
            </button>
          )}
        </div>
      )}
      <p className="sr-only" aria-live="polite" data-testid="ranked-announce">
        {announce}
      </p>
    </div>
  )
}
