import { NON_FILTER_PARAMS, type ActiveFilter } from '@/features/findings/filters/model'
import { sameColumns } from '@/features/findings/lib/list-columns'

/**
 * What differs between the open saved view and the list on screen, for the
 * unsaved-changes dot and the menu's "2 filters added". The view's stored form
 * is the API's filter document; the list is the page URL, whose filters sit on
 * top of the view (a request filter replaces the view's own condition on that
 * field), so a URL filter the view already has is no change.
 */
export type ViewChange =
  | { kind: 'filters'; count: number }
  | { kind: 'search' }
  | { kind: 'sort' }
  | { kind: 'group' }
  | { kind: 'columns' }
  | { kind: 'density' }

interface StoredView {
  filter: Record<string, unknown>
  group_by?: string
  density?: string
}

export interface ViewChangeInput {
  view: StoredView
  /** The page URL's query. */
  search: URLSearchParams
  /** The view's own locked conditions, as chips. */
  viewFilters: readonly ActiveFilter[]
  /** The optional columns the baseline (the view's, or the list's default) shows. */
  baselineColumns: readonly string[]
  /** The optional columns on screen. */
  columns: readonly string[]
  /** The density on screen, or undefined when the person's own preference applies. */
  density: string | undefined
}

/** Params that are not conditions of the view and are compared on their own. */
const OWN_PARAMS = NON_FILTER_PARAMS

const sameList = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every((v, i) => v === b[i])

export function viewChanges(input: ViewChangeInput): ViewChange[] {
  const { view, search, viewFilters, baselineColumns, columns, density } = input
  const changes: ViewChange[] = []

  // Filters: a URL param is a change unless the view sets the same param to the same values.
  const stored = new Map(viewFilters.map((f) => [f.param, f.values]))
  let added = 0
  const seen = new Set<string>()
  for (const [param, raw] of search.entries()) {
    if (OWN_PARAMS.has(param) || seen.has(param) || raw === '') continue
    seen.add(param)
    const values = raw
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean)
    const have = stored.get(param)
    if (have && sameList(have, values)) continue
    added += 1
  }
  if (added > 0) changes.push({ kind: 'filters', count: added })

  const doc = view.filter as { q?: unknown; sort?: unknown }
  const storedQ = typeof doc.q === 'string' ? doc.q : ''
  const q = search.get('q') ?? ''
  if (q !== '' && q !== storedQ) changes.push({ kind: 'search' })

  const storedSort = Array.isArray(doc.sort)
    ? doc.sort.filter((s) => typeof s === 'string').join(',')
    : ''
  const sort = search.get('sort') ?? ''
  if (sort !== '' && sort !== storedSort) changes.push({ kind: 'sort' })

  const group = search.get('group') ?? ''
  if (group !== (view.group_by ?? '')) changes.push({ kind: 'group' })

  if (!sameColumns(columns, baselineColumns)) changes.push({ kind: 'columns' })

  if (density !== undefined && density !== (view.density ?? '')) changes.push({ kind: 'density' })

  return changes
}
