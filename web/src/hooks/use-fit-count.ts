'use client'

import * as React from 'react'
import { foldToFit } from '@/lib/fit-row'

/**
 * How many items of a one-line row fit in the row, measured. The row is
 * `rowRef`; every item rendered in it carries `data-fit-key` with its key.
 * Each item's width is cached by key the first time it is on screen (so all
 * items show once, then the row folds), and the row re-folds when it is
 * resized. Where nothing can be measured (jsdom, a hidden row) every item
 * shows. The fold rule is `foldToFit`: whole items in order, the rest in
 * "+N".
 */
export function useFitCount<T extends HTMLElement>(
  keys: readonly string[],
  { gap, more }: { gap: number; more: number }
): { rowRef: React.RefObject<T | null>; fit: number } {
  const rowRef = React.useRef<T>(null)
  const widths = React.useRef(new Map<string, number>())
  const [fit, setFit] = React.useState(keys.length)
  const [tick, setTick] = React.useState(0)
  // A new array with the same keys (every render) is the same list: the fold
  // re-runs only when the keys themselves change.
  const signature = keys.join('\u0000')
  const list = React.useMemo(() => (signature ? signature.split('\u0000') : []), [signature])

  React.useEffect(() => {
    const row = rowRef.current
    if (!row || typeof ResizeObserver === 'undefined') return
    let width = row.clientWidth
    const ro = new ResizeObserver(() => {
      // Only a change of the row's own width can change the fold.
      if (row.clientWidth === width) return
      width = row.clientWidth
      setTick((n) => n + 1)
    })
    ro.observe(row)
    // Widths measured in a fallback font are wrong once the web font loads.
    let live = true
    document.fonts?.ready.then(() => {
      if (!live) return
      widths.current.clear()
      setTick((n) => n + 1)
    })
    return () => {
      live = false
      ro.disconnect()
    }
  }, [])

  React.useLayoutEffect(() => {
    const row = rowRef.current
    if (!row) return
    row.querySelectorAll<HTMLElement>('[data-fit-key]').forEach((el) => {
      const key = el.dataset.fitKey
      const w = el.offsetWidth
      if (key && w > 0) widths.current.set(key, w)
    })
    const total = row.clientWidth
    const unmeasured = list.some((k) => !widths.current.has(k))
    const next =
      total === 0 || unmeasured
        ? list.length
        : foldToFit(
            total,
            list.map((k) => widths.current.get(k) ?? 0),
            gap,
            more
          )
    if (next !== fit) setFit(next)
    // The fold settles: it only reads cached widths and the row's own width,
    // which folding does not change.
  }, [list, tick, fit, gap, more])

  return { rowRef, fit: Math.min(fit, keys.length) }
}
