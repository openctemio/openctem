'use client'

/**
 * A page names the records in its URL for the header breadcrumb.
 *
 * The breadcrumb lives in the app header and only sees the URL, so a record
 * id in it has no name. A detail page calls
 * `useBreadcrumbTitle("CVE-2024-21538 · cross-spawn")` once its record has
 * loaded; a sub-page names its parent record with
 * `useBreadcrumbTitle(template.name, "/settings/pentest/templates/<id>")`.
 * The breadcrumb shows that name for the path, and a short label for the
 * record kind ("Finding", "Scan") before then; never the raw id.
 */

import { useEffect, useSyncExternalStore } from 'react'
import { usePathname } from 'next/navigation'

type Entry = { path: string; title: string }

// One entry per mounted caller; a new Map on every change so the snapshot
// identity changes for useSyncExternalStore.
let entries: ReadonlyMap<symbol, Entry> = new Map()
const listeners = new Set<() => void>()

function emit() {
  for (const l of listeners) l()
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

const EMPTY: ReadonlyMap<symbol, Entry> = new Map()

/**
 * Name a path in the breadcrumb: the current page (default) or `path`, an
 * ancestor of it. null/empty keeps the default label.
 */
export function useBreadcrumbTitle(title: string | null | undefined, path?: string) {
  const pathname = usePathname()
  const target = path ?? pathname
  useEffect(() => {
    if (!title) return
    const key = Symbol(target)
    const next = new Map(entries)
    next.set(key, { path: target, title })
    entries = next
    emit()
    return () => {
      const rest = new Map(entries)
      rest.delete(key)
      entries = rest
      emit()
    }
  }, [target, title])
}

/** The names pages set, by path (the latest caller wins for a path). */
export function useBreadcrumbTitles(): ReadonlyMap<string, string> {
  const snapshot = useSyncExternalStore(
    subscribe,
    () => entries,
    () => EMPTY
  )
  const byPath = new Map<string, string>()
  for (const e of snapshot.values()) byPath.set(e.path, e.title)
  return byPath
}
