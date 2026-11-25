/**
 * The pages recently opened in this browser, for the command palette's
 * "Recent" group.
 *
 * Only a page's path is kept, and only a path made of plain words
 * ("/findings", "/settings/members"): a path with an id, a CVE or a number in
 * it (an entity's own page) is never written, so the list holds no
 * organization data. It lives in the recent-queries store
 * (features/query/lib/recent.ts), which is cleared at sign-out and on an
 * organization switch. The palette shows a path only while the current
 * sidebar or settings navigation (already filtered by permission and module)
 * still offers it, under that navigation's own label.
 */
import { pushRecent, readRecent } from '@/features/query/lib/recent'

export const RECENT_PAGES_SCOPE = 'palette:pages'
/** Rows in the palette's Recent group. */
export const RECENT_PAGES_SHOWN = 5

const PLAIN_PATH = /^\/(?:[a-z]+(?:-[a-z]+)*(?:\/[a-z]+(?:-[a-z]+)*)*)?$/

/** A path the list may keep: "/" or lower-case words joined by "-" and "/", at most 80 characters. */
export function isRecordablePath(path: string | null | undefined): path is string {
  return !!path && path.length <= 80 && PLAIN_PATH.test(path)
}

/** Records an opened page; anything but a plain path is ignored. */
export function recordRecentPage(path: string | null | undefined): void {
  if (isRecordablePath(path)) pushRecent(RECENT_PAGES_SCOPE, path)
}

/** Recently opened paths, newest first. */
export function readRecentPages(): string[] {
  return readRecent(RECENT_PAGES_SCOPE).filter(isRecordablePath)
}

/**
 * The recent pages the palette can show: known to `index` (the pages the
 * caller may open now), the current page left out, at most `limit`.
 */
export function pickRecentPages<T>(
  paths: readonly string[],
  index: ReadonlyMap<string, T>,
  current: string | null | undefined,
  limit = RECENT_PAGES_SHOWN
): (T & { url: string })[] {
  const out: (T & { url: string })[] = []
  for (const url of paths) {
    if (url === current) continue
    const entry = index.get(url)
    if (entry) out.push({ ...entry, url })
    if (out.length >= limit) break
  }
  return out
}
