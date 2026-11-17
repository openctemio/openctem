'use client'

/**
 * Keyboard and link navigation for the findings drawer:
 *
 * - `j` / `k` open the next / previous finding of the current list while the
 *   drawer is open (ignored while typing or inside a menu or picker);
 * - the drawer's header shows the open finding's place in the list ("3 of
 *   418") with previous / next buttons that make the same moves;
 * - the open finding lives in the URL hash (`#finding=<id>`), so the address
 *   can be shared and a reload reopens it. The hash, not a query parameter:
 *   the list's filters are the query and must not change.
 */

import { useEffect } from 'react'

const HASH_KEY = 'finding'
const ID_RE = /^[0-9a-f-]{8,64}$/i

/** The finding id in the URL hash, or null. */
export function readFindingHash(
  hash: string = typeof window === 'undefined' ? '' : window.location.hash
): string | null {
  const params = new URLSearchParams(hash.replace(/^#/, ''))
  const id = params.get(HASH_KEY)
  return id && ID_RE.test(id) ? id : null
}

/** Writes (or clears) the finding id in the hash without a navigation. */
export function writeFindingHash(id: string | null) {
  if (typeof window === 'undefined') return
  const { pathname, search } = window.location
  const hash = id ? `#${HASH_KEY}=${encodeURIComponent(id)}` : ''
  if (window.location.hash === hash) return
  window.history.replaceState(window.history.state, '', `${pathname}${search}${hash}`)
}

export const TYPING_TARGETS =
  'input, textarea, select, [contenteditable="true"], [role="combobox"], [role="listbox"], [role="menu"], [role="menuitem"]'

/** The neighbour of `currentId` in `items` for a j/k key, or undefined. */
export function neighbour<T extends { id: string }>(
  items: T[],
  currentId: string | undefined,
  key: string
): T | undefined {
  const i = items.findIndex((f) => f.id === currentId)
  if (i < 0) return undefined
  if (key === 'j') return items[i + 1]
  if (key === 'k') return items[i - 1]
  return undefined
}

/** The open finding's place in the list it was opened from. */
export interface FindingListPosition {
  /** 1-based place among every finding of the list (page offset + row). */
  index: number
  /** The list's total, as its title row counts it. */
  total: number
  /** Absent at the first / last row of the page shown. */
  onPrev?: () => void
  onNext?: () => void
}

/**
 * The place of `currentId` in the list and the moves to its neighbours on
 * the page shown (the same moves as `k` / `j`), or undefined when it is not
 * a row of that page: opened from a shared link or outside the list.
 */
export function findingListPosition<T extends { id: string }>({
  items,
  currentId,
  page,
  perPage,
  total,
  onSelect,
}: {
  items: T[]
  currentId: string | undefined
  /** 1-based page of `items`. */
  page?: number
  perPage?: number
  total?: number
  onSelect: (item: T) => void
}): FindingListPosition | undefined {
  const i = currentId ? items.findIndex((f) => f.id === currentId) : -1
  if (i < 0) return undefined
  const offset = Math.max(0, ((page || 1) - 1) * (perPage || items.length))
  const prev = neighbour(items, currentId, 'k')
  const next = neighbour(items, currentId, 'j')
  return {
    index: offset + i + 1,
    total: Math.max(total ?? 0, offset + items.length),
    onPrev: prev ? () => onSelect(prev) : undefined,
    onNext: next ? () => onSelect(next) : undefined,
  }
}

export function useDrawerKeyboardNav<T extends { id: string }>({
  open,
  items,
  currentId,
  onSelect,
}: {
  open: boolean
  items: T[]
  currentId: string | undefined
  onSelect: (item: T) => void
}) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || (e.key !== 'j' && e.key !== 'k')) return
      const el = e.target as HTMLElement | null
      if (el?.closest?.(TYPING_TARGETS)) return
      const next = neighbour(items, currentId, e.key)
      if (next) {
        e.preventDefault()
        onSelect(next)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, items, currentId, onSelect])
}
