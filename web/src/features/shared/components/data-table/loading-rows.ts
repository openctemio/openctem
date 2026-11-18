/**
 * How many placeholder rows a list draws while it loads. A fixed five made
 * every list jump when its real rows arrived (a list of 25 grew by 20 rows,
 * a list of 1 shrank by 4). The rule:
 *
 * - the last row count this list showed in this browser session (same page,
 *   same table), so a reload or a return to the list keeps its height;
 * - else five rows (a list never shown before: five placeholders that settle
 *   to one real row move less than a full page of them);
 * - never more than the page size, never more rows than fit in the viewport
 *   (the rest would be off screen), and at least one.
 */
import type { TableDensity } from './use-table-density'

const STORAGE_PREFIX = 'openctem:table-rows:'
const remembered = new Map<string, number>()

/** Placeholder rows of a list with no remembered count. */
export const DEFAULT_LOADING_ROWS = 5

/** Row height in px of each density (`use-table-density.ts`). */
export const ROW_HEIGHT: Record<TableDensity, number> = {
  compact: 32,
  default: 40,
  comfortable: 52,
}

/** The last row count recorded for this list, if any. */
export function knownRowCount(key: string): number | undefined {
  const inMemory = remembered.get(key)
  if (inMemory !== undefined) return inMemory
  try {
    const raw = window.sessionStorage.getItem(STORAGE_PREFIX + key)
    if (raw === null) return undefined
    const n = Number(raw)
    return Number.isInteger(n) && n >= 0 ? n : undefined
  } catch {
    return undefined
  }
}

/** Records the row count a list showed once loaded. */
export function rememberRowCount(key: string, count: number): void {
  if (remembered.get(key) === count) return
  remembered.set(key, count)
  try {
    window.sessionStorage.setItem(STORAGE_PREFIX + key, String(count))
  } catch {
    // Storage blocked: the in-memory value still serves this page view.
  }
}

/** Placeholder rows: last known count, else five, capped to the page size and the viewport. */
export function loadingRowCount(
  known: number | undefined,
  pageSize: number,
  viewportHeight: number,
  rowHeight: number
): number {
  const fit = rowHeight > 0 && viewportHeight > 0 ? Math.ceil(viewportHeight / rowHeight) : pageSize
  return Math.max(1, Math.min(known ?? DEFAULT_LOADING_ROWS, pageSize, fit))
}

/** Forget every recorded count (tests). */
export function resetRowCounts(): void {
  remembered.clear()
}
