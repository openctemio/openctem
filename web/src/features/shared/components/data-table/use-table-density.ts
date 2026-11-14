'use client'

/**
 * Table density: `compact` (32px rows), `default` (40px) or `comfortable`
 * (52px, room for a second line). A per-user preference, not URL state: one
 * choice applies to every table, remembered in this browser. Until the user
 * picks one, each table uses its own default (`defaultDensity`).
 *
 * Stored values (this browser, the URL `density=` and saved views on the
 * server) keep the words written before the third level existed: `compact`
 * is 32, `comfortable` is 40 and the 52 px level is written `spacious`. So a
 * value the earlier console stored still means what it meant, and the earlier
 * console ignores a value it does not know. `decodeDensity` / `encodeDensity`
 * convert between the stored word and the level.
 *
 * Browser storage can be unavailable (private window, blocked site data):
 * every read and write is guarded, and the table then simply uses its
 * default.
 */

import { useCallback, useSyncExternalStore } from 'react'

export type TableDensity = 'compact' | 'default' | 'comfortable'

export const TABLE_DENSITIES: readonly TableDensity[] = ['compact', 'default', 'comfortable']

export const TABLE_DENSITY_STORAGE_KEY = 'openctem:table-density'
const DENSITY_CHANGED = 'openctem:table-density-changed'

const STORED: Record<TableDensity, string> = {
  compact: 'compact',
  default: 'comfortable',
  comfortable: 'spacious',
}

/** The level a stored word stands for; undefined for anything else. */
export function decodeDensity(v: unknown): TableDensity | undefined {
  if (v === 'compact') return 'compact'
  if (v === 'comfortable') return 'default'
  if (v === 'spacious') return 'comfortable'
  return undefined
}

/** The word stored for a level (URL, saved view, this browser). */
export function encodeDensity(d: TableDensity): string {
  return STORED[d]
}

function isDensity(v: unknown): v is TableDensity {
  return v === 'compact' || v === 'default' || v === 'comfortable'
}

// The choice of this page load, for when storage cannot keep it.
let memoryDensity: TableDensity | null = null

function readStored(): TableDensity | null {
  try {
    const v = decodeDensity(window.localStorage.getItem(TABLE_DENSITY_STORAGE_KEY))
    if (v) return v
  } catch {
    // storage unavailable
  }
  return memoryDensity
}

function subscribe(cb: () => void) {
  window.addEventListener(DENSITY_CHANGED, cb)
  // Another tab changed it.
  const onStorage = (e: StorageEvent) => {
    if (e.key === TABLE_DENSITY_STORAGE_KEY) cb()
  }
  window.addEventListener('storage', onStorage)
  return () => {
    window.removeEventListener(DENSITY_CHANGED, cb)
    window.removeEventListener('storage', onStorage)
  }
}

/** The density to draw with, and a setter that every table follows. */
export function useTableDensity(
  defaultDensity: TableDensity = 'default'
): [TableDensity, (next: TableDensity) => void] {
  const stored = useSyncExternalStore(subscribe, readStored, () => null)
  const setDensity = useCallback((next: TableDensity) => {
    if (!isDensity(next)) return
    memoryDensity = next
    try {
      window.localStorage.setItem(TABLE_DENSITY_STORAGE_KEY, encodeDensity(next))
    } catch {
      // Not remembered across reloads; this page load keeps it in memory.
    }
    window.dispatchEvent(new Event(DENSITY_CHANGED))
  }, [])
  return [stored ?? defaultDensity, setDensity]
}
