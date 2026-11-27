'use client'

import * as React from 'react'

/** Where a list's rows are drawn: table body rows and phone cards. */
const ROW_SELECTOR = 'tbody tr, [data-slot="mobile-card"]'

/**
 * Rows of a list that refreshes on its own (a poll, a change notice) hold
 * their places while the pointer is on them: a re-read that adds, removes or
 * reorders rows would otherwise move another row under the pointer between
 * aiming and clicking.
 *
 * While held, the rows on screen keep their order and each takes its fresh
 * values (a status, a count); a row the re-read no longer returns stays as it
 * was, and new rows wait. Leaving the list shows the list as read. A change
 * of the view itself (`viewKey`: page, filters, sort) is the user's own act
 * and always shows the new rows at once.
 *
 * Spread `bind` on the element that wraps the list.
 */
export function useHeldRows<T>(
  rows: T[],
  getId: (row: T) => string,
  viewKey: string
): {
  rows: T[]
  held: boolean
  bind: {
    onPointerOver: (e: React.PointerEvent<HTMLElement>) => void
    onPointerLeave: () => void
  }
} {
  const [frozen, setFrozen] = React.useState<{ key: string; rows: T[] } | null>(null)
  const holding = frozen !== null && frozen.key === viewKey

  const shown = React.useMemo(() => {
    if (!frozen || frozen.key !== viewKey) return rows
    const fresh = new Map(rows.map((r) => [getId(r), r]))
    return frozen.rows.map((r) => fresh.get(getId(r)) ?? r)
  }, [frozen, viewKey, rows, getId])

  const onPointerOver = React.useCallback(
    (e: React.PointerEvent<HTMLElement>) => {
      if (holding) return
      const target = e.target as HTMLElement | null
      if (!target?.closest?.(ROW_SELECTOR)) return
      setFrozen({ key: viewKey, rows })
    },
    [holding, viewKey, rows]
  )
  const onPointerLeave = React.useCallback(() => setFrozen(null), [])

  return { rows: shown, held: holding, bind: { onPointerOver, onPointerLeave } }
}
