import type { VisibilityState } from '@tanstack/react-table'

/**
 * Which columns the findings list shows. Finding (the title) and Priority are
 * always shown; the others are the person's choice and are saved with a view.
 * The URL holds the choice as `columns=<ids>` (the visible optional columns)
 * only when it differs from what the view, or the list's default, would show.
 */

/** Column ids a person can hide, in table order. */
export const OPTIONAL_COLUMNS = [
  'asset',
  'severity',
  'status',
  'slaStatus',
  'source',
  'createdAt',
] as const

export type OptionalColumn = (typeof OPTIONAL_COLUMNS)[number]

/** Always shown: the finding and its priority. */
export const LOCKED_COLUMNS = ['title', 'priorityClass'] as const

/**
 * What the list shows with no choice made: the asset, severity, status and
 * due date beside the always-shown priority, title and signals. The scanner
 * and first-seen date stay in the detail. On a narrow frame the table drops
 * Severity, then Signals, then Due (column priority), so the title keeps its
 * room; `activeView` no longer changes the set (the width decides).
 */
const BASE_VISIBLE: readonly OptionalColumn[] = ['asset', 'severity', 'status', 'slaStatus']

/** The default columns (the same for every view). */
export function defaultColumns(): OptionalColumn[] {
  return [...BASE_VISIBLE]
}

const isOptional = (id: string): id is OptionalColumn =>
  (OPTIONAL_COLUMNS as readonly string[]).includes(id)

/** The optional columns named in `ids`, in table order, ignoring anything else. */
export function normalizeColumns(ids: readonly string[] | undefined | null): OptionalColumn[] {
  const set = new Set(ids ?? [])
  return OPTIONAL_COLUMNS.filter((c) => set.has(c))
}

/** The `columns` URL param as a list, or undefined when it is absent. */
export function parseColumnsParam(raw: string | null | undefined): OptionalColumn[] | undefined {
  if (raw === null || raw === undefined) return undefined
  // An explicit empty value means "no optional column at all".
  return normalizeColumns(raw.split(',').filter(isOptional))
}

export const serializeColumns = (cols: readonly OptionalColumn[]) => cols.join(',')

export function sameColumns(a: readonly string[], b: readonly string[]): boolean {
  const x = normalizeColumns(a)
  const y = normalizeColumns(b)
  return x.length === y.length && x.every((c, i) => c === y[i])
}

/** The visibility map the table takes: every optional column on or off. */
export function visibilityOf(visible: readonly string[]): VisibilityState {
  const on = new Set(visible)
  return Object.fromEntries(OPTIONAL_COLUMNS.map((c) => [c, on.has(c)]))
}

/** The optional columns a visibility map shows, in table order. */
export function visibleFrom(state: VisibilityState): OptionalColumn[] {
  return OPTIONAL_COLUMNS.filter((c) => state[c] !== false)
}

/**
 * The columns a view saves: its optional columns plus the two locked ones, so
 * what is stored says everything the list showed.
 */
export function columnsToSave(visible: readonly string[]): string[] {
  return ['title', 'priorityClass', ...normalizeColumns(visible)]
}
