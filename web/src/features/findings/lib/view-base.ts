/**
 * Which view the findings list is, for its title row. The title is always a
 * real view's name: the open saved view, the built-in quick view the URL is
 * exactly, or the base view the URL was derived from (the quick view whose
 * own params are all in the URL with the same values, the most specific
 * first; otherwise All findings). A list that is its base view plus more
 * (filters, search text, unsaved changes to a saved view) is `modified`.
 */
import {
  INFORMATIONAL_PARAM,
  PRESENTATION_PARAMS,
  quickViewHref,
  quickViewIsActive,
  type QuickView,
} from './quick-views'

/** Every state, no filter: the list the "All findings" title names. */
export const ALL_FINDINGS_PARAMS = 'state=all'

export type ListBaseView =
  | { kind: 'saved'; modified: boolean }
  | { kind: 'quick'; view: QuickView; modified: boolean }
  | { kind: 'all'; modified: boolean }

export interface BaseViewInput {
  search: string | URLSearchParams
  /** The built-in views, in the API's order. */
  views: readonly QuickView[]
  includeInformational?: boolean
  /** A saved view is open (its id is in the URL and the view is known). */
  savedView?: boolean
  /** The open saved view differs from what is stored. */
  savedViewChanged?: boolean
}

/** The filter params of a URL (what the list holds, not how it shows). */
function filterScope(search: URLSearchParams): Map<string, string> {
  const scope = new Map<string, string>()
  for (const [k, v] of search.entries())
    if (!PRESENTATION_PARAMS.has(k) && k !== INFORMATIONAL_PARAM && k !== 'practice' && v !== '')
      scope.set(k, v)
  return scope
}

/** A view's own params as its link carries them (a view without a state opens with state=all). */
function viewScope(params: string, includeInformational: boolean): Map<string, string> {
  return filterScope(
    new URLSearchParams(quickViewHref(params, includeInformational).split('?')[1] ?? '')
  )
}

export function deriveBaseView({
  search,
  views,
  includeInformational = false,
  savedView = false,
  savedViewChanged = false,
}: BaseViewInput): ListBaseView {
  if (savedView) return { kind: 'saved', modified: savedViewChanged }
  const q = typeof search === 'string' ? new URLSearchParams(search) : search
  const searched = (q.get('q') ?? '').trim() !== ''

  const exact = views.find((v) => quickViewIsActive(q, v, includeInformational))
  if (exact) return { kind: 'quick', view: exact, modified: searched }

  const current = filterScope(q)
  // The page defaults to the Open lens when the URL names no state.
  if (!current.has('state') && !current.has('status')) current.set('state', 'open')

  if (current.size === 1 && current.get('state') === 'all' && !q.has(INFORMATIONAL_PARAM)) {
    return { kind: 'all', modified: searched }
  }

  // The base: every param of the view is in the URL with the same value. The
  // informational default is an effect of the other params, so it is not
  // compared. The view with the most params of its own wins; ties keep the
  // API's order.
  let base: QuickView | undefined
  let baseSize = 0
  for (const v of views) {
    const wanted = viewScope(v.params, includeInformational)
    if (wanted.size <= baseSize) continue
    let held = true
    for (const [k, value] of wanted) if (current.get(k) !== value) held = false
    if (held) {
      base = v
      baseSize = wanted.size
    }
  }
  return base ? { kind: 'quick', view: base, modified: true } : { kind: 'all', modified: true }
}

/**
 * The URL search that is exactly the base view (the title row's Reset). The
 * practice is the list's scope, not a filter, so it is kept.
 */
export function baseViewSearch(
  base: Exclude<ListBaseView, { kind: 'saved' }>,
  current: string | URLSearchParams,
  includeInformational = false
): URLSearchParams {
  const q = typeof current === 'string' ? new URLSearchParams(current) : current
  const params = base.kind === 'quick' ? base.view.params : ALL_FINDINGS_PARAMS
  const out = new URLSearchParams(quickViewHref(params, includeInformational).split('?')[1] ?? '')
  const practice = q.get('practice')
  if (practice) out.set('practice', practice)
  return out
}
