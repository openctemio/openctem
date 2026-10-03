'use client'

/**
 * A detail page names itself in the header breadcrumb.
 *
 * The breadcrumb lives in the app header and only sees the URL, so a detail
 * page showed its raw ID ("Findings › dcdc3001..."). The page now calls
 * `useBreadcrumbTitle("CVE-2024-21538 · cross-spawn")` once its record has
 * loaded; the breadcrumb shows that for the page's path and falls back to the
 * shortened ID before then and after the page unmounts.
 */

import { useEffect, useSyncExternalStore } from 'react'
import { usePathname } from 'next/navigation'

type Entry = { path: string; title: string } | null

let current: Entry = null
const listeners = new Set<() => void>()

function emit() {
  for (const l of listeners) l()
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** Name the current page in the breadcrumb (null/empty: keep the default). */
export function useBreadcrumbTitle(title: string | null | undefined) {
  const pathname = usePathname()
  useEffect(() => {
    if (!title) return
    const entry = { path: pathname, title }
    current = entry
    emit()
    return () => {
      if (current === entry) {
        current = null
        emit()
      }
    }
  }, [pathname, title])
}

/** The title a page set for `pathname`, or null. */
export function useBreadcrumbTitleFor(pathname: string): string | null {
  const entry = useSyncExternalStore(
    subscribe,
    () => current,
    () => null
  )
  return entry && entry.path === pathname ? entry.title : null
}
