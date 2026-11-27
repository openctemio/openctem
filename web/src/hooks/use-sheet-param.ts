'use client'

/**
 * A list's quick-view sheet kept in the URL (`?task=<id>`, `?campaign=<id>`):
 *
 * - opening a row pushes a history entry, so Back closes the sheet and the
 *   address can be shared; a reload reopens it;
 * - moving to the previous / next row replaces the entry (Back still leaves
 *   the sheet in one step);
 * - closing goes back when this page pushed the entry, and otherwise (a shared
 *   link, a reload) removes the parameter in place.
 *
 * Only an id-shaped value opens a sheet: the id goes into an API path, so a
 * crafted link cannot smuggle a path segment or query into the request.
 *
 * `useSheetListNav` adds the keys while the sheet is open: ArrowDown or `j`
 * opens the next row, ArrowUp or `k` the previous one (ignored while typing,
 * inside a menu, a picker or another dialog on top).
 */

import type React from 'react'
import { useCallback, useEffect, useRef } from 'react'
import { pushUrlSearch, replaceUrlSearch, useUrlParam } from '@/hooks/use-url-param'

const ID_RE = /^[0-9a-zA-Z_-]{1,64}$/

/** The value as a sheet id, or null when it is missing or not id-shaped. */
export function sheetIdOf(value: string | null | undefined): string | null {
  return value && ID_RE.test(value) ? value : null
}

export interface SheetParam {
  /** The open record's id, or null. */
  id: string | null
  /** Opens a record from the list (new history entry). */
  open: (id: string) => void
  /** Shows another record in the open sheet (same history entry). */
  move: (id: string) => void
  close: () => void
}

function withParam(key: string, id: string | null) {
  const q = new URLSearchParams(window.location.search)
  if (id) q.set(key, id)
  else q.delete(key)
  return q
}

export function useSheetParam(key: string): SheetParam {
  const id = sheetIdOf(useUrlParam(key))
  // True while the open sheet's entry is one this page pushed.
  const pushed = useRef(false)
  useEffect(() => {
    if (!id) pushed.current = false
  }, [id])

  const open = useCallback(
    (next: string) => {
      if (!sheetIdOf(next)) return
      if (id) {
        replaceUrlSearch(withParam(key, next))
        return
      }
      pushUrlSearch(withParam(key, next))
      pushed.current = true
    },
    [id, key]
  )
  const move = useCallback(
    (next: string) => {
      if (sheetIdOf(next)) replaceUrlSearch(withParam(key, next))
    },
    [key]
  )
  const close = useCallback(() => {
    if (pushed.current) {
      pushed.current = false
      window.history.back()
      return
    }
    replaceUrlSearch(withParam(key, null))
  }, [key])
  return { id, open, move, close }
}

const TYPING_TARGETS =
  'input, textarea, select, [contenteditable="true"], [role="combobox"], [role="listbox"], [role="menu"], [role="menuitem"]'

/** The row a key moves to from `currentId`, or undefined. */
export function sheetNeighbour(
  ids: readonly string[],
  currentId: string | null | undefined,
  key: string
): string | undefined {
  const i = currentId ? ids.indexOf(currentId) : -1
  if (i < 0) return undefined
  if (key === 'ArrowDown' || key === 'j') return ids[i + 1]
  if (key === 'ArrowUp' || key === 'k') return ids[i - 1]
  return undefined
}

export function useSheetListNav({
  ids,
  currentId,
  onMove,
}: {
  /** The rows of the list as shown, in order. */
  ids: readonly string[]
  currentId: string | null
  onMove: (id: string) => void
}) {
  useEffect(() => {
    if (!currentId) return
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || e.shiftKey) return
      const el = e.target as HTMLElement | null
      if (el?.closest?.(TYPING_TARGETS)) return
      // A dialog opened from the sheet (a confirmation) owns the keys.
      if (document.querySelectorAll('[role="dialog"][data-state="open"]').length > 1) return
      const next = sheetNeighbour(ids, currentId, e.key)
      if (next) {
        e.preventDefault()
        onMove(next)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [ids, currentId, onMove])
}

/**
 * Where focus returns when the sheet closes: the row's link to `href` (the
 * record's title; a table row and a phone card both have one), else the row.
 */
export function rowFocusTarget(id: string | null, href: string): HTMLElement | null {
  // Ids are id-shaped (sheetIdOf), so they are safe inside a selector string.
  if (!sheetIdOf(id) || typeof document === 'undefined' || /["\\]/.test(href)) return null
  const row = document.querySelector<HTMLElement>(`[data-row-id="${id}"]`)
  return (
    row?.querySelector<HTMLElement>(`a[href="${href}"]`) ??
    document.querySelector<HTMLElement>(`a[href="${href}"]`) ??
    row
  )
}

/**
 * A row title's link opens the quick view on a plain click and stays a real
 * link for ctrl/cmd/shift/middle click (a new tab gets the full page).
 */
export function opensSheet(e: React.MouseEvent, open: () => void) {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey)
    return
  e.preventDefault()
  open()
}
