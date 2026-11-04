'use client'

import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

/**
 * The Findings filter layout, shared by every list page with a facet panel:
 *  - `useFilterPanelOpen` holds whether the side panel is open. Closed by
 *    default so the table gets the width; the viewer's choice is remembered per
 *    browser and per page (`storageKey`), a convenience that is safe to lose.
 *  - `FilterPanelSlot` is the floating card beside the table from `lg` up.
 *    Pair it with `FilterPanelToggle` (or `DataTable`'s `filterToggle`) and a
 *    `FilterSheet` for narrower screens.
 */
export function useFilterPanelOpen(
  storageKey: string
): [boolean, (next: boolean | ((open: boolean) => boolean)) => void] {
  const [open, setOpenState] = useState(false)
  useEffect(() => {
    try {
      if (window.localStorage.getItem(storageKey) === '1') setOpenState(true)
    } catch {
      // storage unavailable: stay closed
    }
  }, [storageKey])
  const setOpen = useCallback(
    (next: boolean | ((open: boolean) => boolean)) => {
      setOpenState((prev) => {
        const value = typeof next === 'function' ? next(prev) : next
        try {
          window.localStorage.setItem(storageKey, value ? '1' : '0')
        } catch {
          // best-effort
        }
        return value
      })
    },
    [storageKey]
  )
  return [open, setOpen]
}

export interface FilterPanelSlotProps {
  open: boolean
  /** `id` the page's `FilterPanelToggle` points `controlsId` at. */
  id: string
  /** Accessible name of the panel (translated). */
  label: string
  children: ReactNode
}

/**
 * Always mounted so opening and closing can animate: the slot's width (and the
 * gap after it) eases between 0 and the card's width while the card fades, and
 * the table beside it resizes in step. The card keeps its own width, so its
 * contents never reflow mid-animation. `inert` while closed keeps the hidden
 * controls out of the tab order.
 */
export function FilterPanelSlot({ open, id, label, children }: FilterPanelSlotProps) {
  // The panel's contents mount the first time it opens and stay mounted after,
  // so closing can animate. A panel that never opens costs no requests (the
  // facets load their own data).
  const [everOpened, setEverOpened] = useState(open)
  if (open && !everOpened) setEverOpened(true)
  return (
    <div
      inert={!open}
      className={cn(
        'sticky top-4 hidden shrink-0 overflow-hidden transition-[width,margin-inline-end,opacity] duration-300 ease-in-out motion-reduce:transition-none lg:block',
        open ? 'me-5 w-64 opacity-100' : 'me-0 w-0 opacity-0'
      )}
    >
      <aside
        id={id}
        aria-label={label}
        // A self-contained floating card, as tall as the viewport and pinned
        // while the page scrolls: long filter lists scroll inside it.
        className="flex h-[calc(100svh-7.5rem)] w-64 flex-col rounded-lg border bg-card p-4"
      >
        <div className="flex min-h-0 flex-1 flex-col">{everOpened ? children : null}</div>
      </aside>
    </div>
  )
}
