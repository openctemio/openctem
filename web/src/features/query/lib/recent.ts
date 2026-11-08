/**
 * Recent search box queries, per entity and tab, in this browser only.
 * localStorage outlives the session and is shared by everyone using the
 * browser, so the list is cleared at sign-out, when the session ends and
 * when the user switches organization (clearRecentQueries). There is no
 * server copy; saved views are the shared, server-side form.
 */

const PREFIX = 'recent-queries:'
export const MAX_RECENT = 20

function key(scope: string): string {
  return PREFIX + scope
}

/** The recent queries of a scope ("findings", "assets:ip_address"), newest first. */
export function readRecent(scope: string): string[] {
  if (typeof window === 'undefined') return []
  try {
    const raw = window.localStorage.getItem(key(scope))
    const list: unknown = raw ? JSON.parse(raw) : []
    return Array.isArray(list)
      ? list.filter((x): x is string => typeof x === 'string').slice(0, MAX_RECENT)
      : []
  } catch {
    return []
  }
}

/** Puts text first in the scope's list (no duplicates, at most MAX_RECENT). */
export function pushRecent(scope: string, text: string): void {
  const t = text.trim()
  if (!t || typeof window === 'undefined') return
  const next = [t, ...readRecent(scope).filter((x) => x !== t)].slice(0, MAX_RECENT)
  try {
    window.localStorage.setItem(key(scope), JSON.stringify(next))
  } catch {
    // Storage unavailable or full: recent queries are a convenience.
  }
}

/** Removes every recent query list. Never throws. */
export function clearRecentQueries(): void {
  if (typeof window === 'undefined') return
  try {
    const keys: string[] = []
    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i)
      if (k?.startsWith(PREFIX)) keys.push(k)
    }
    for (const k of keys) window.localStorage.removeItem(k)
  } catch {
    // Storage unavailable: nothing was saved either.
  }
}
