'use client'

/**
 * Keyboard and link navigation for the findings drawer:
 *
 * - `j` / `k` open the next / previous finding of the current list while the
 *   drawer is open (ignored while typing or inside a menu or picker);
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

const TYPING =
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
      if (el?.closest?.(TYPING)) return
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
