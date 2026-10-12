'use client'

/**
 * Table density (UI style contract D14): `compact` (32px rows) or
 * `comfortable` (40px). A per-user preference, not URL state: one choice
 * applies to every table, remembered in this browser. Until the user picks
 * one, each table uses its own default (`defaultDensity`).
 *
 * Browser storage can be unavailable (private window, blocked site data):
 * every read and write is guarded, and the table then simply uses its
 * default.
 */

import { useCallback, useSyncExternalStore } from 'react'

export type TableDensity = 'compact' | 'comfortable'

export const TABLE_DENSITIES: readonly TableDensity[] = ['compact', 'comfortable']

export const TABLE_DENSITY_STORAGE_KEY = 'openctem:table-density'
const DENSITY_CHANGED = 'openctem:table-density-changed'

function isDensity(v: unknown): v is TableDensity {
  return v === 'compact' || v === 'comfortable'
}

// The choice of this page load, for when storage cannot keep it.
let memoryDensity: TableDensity | null = null

function readStored(): TableDensity | null {
  try {
    const v = window.localStorage.getItem(TABLE_DENSITY_STORAGE_KEY)
    if (isDensity(v)) return v
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
  defaultDensity: TableDensity = 'comfortable'
): [TableDensity, (next: TableDensity) => void] {
  const stored = useSyncExternalStore(subscribe, readStored, () => null)
  const setDensity = useCallback((next: TableDensity) => {
    if (!isDensity(next)) return
    memoryDensity = next
    try {
      window.localStorage.setItem(TABLE_DENSITY_STORAGE_KEY, next)
    } catch {
      // Not remembered across reloads; this page load keeps it in memory.
    }
    window.dispatchEvent(new Event(DENSITY_CHANGED))
  }, [])
  return [stored ?? defaultDensity, setDensity]
}
