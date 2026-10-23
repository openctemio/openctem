/**
 * Quick views of the findings list (built-in, in the sidebar under Findings).
 * The API owns the definitions: each view's `params` is the exact
 * `GET /findings` query string, so a view's count equals the total of the list
 * it opens, and the web never keeps a second copy of what a view means.
 */

export const QUICK_VIEW_KEYS = [
  'active',
  'needs_triage',
  'my_queue',
  'sla_breached',
  'pending_approval',
  'accepted_expiring',
  'closed',
] as const

export type QuickViewKey = (typeof QUICK_VIEW_KEYS)[number]

export interface QuickView {
  key: string
  count: number
  params: string
}

export interface QuickViewsResponse {
  views: QuickView[]
  as_of?: string
}

/** English fallbacks; the i18n key is `findings.quickView.<key>`. */
export const QUICK_VIEW_LABELS: Record<QuickViewKey, string> = {
  active: 'Active',
  needs_triage: 'Needs triage',
  my_queue: 'My queue',
  sla_breached: 'SLA breached',
  pending_approval: 'Pending approval',
  accepted_expiring: 'Accepted · expiring',
  closed: 'Closed',
}

export const quickViewLabelKey = (key: string) => `findings.quickView.${key}`

/** Views the console knows how to label, in the API's order; an unknown key is dropped. */
export function knownQuickViews(views: readonly QuickView[] | undefined): QuickView[] {
  return (views ?? []).filter((v): v is QuickView =>
    (QUICK_VIEW_KEYS as readonly string[]).includes(v.key)
  )
}

/**
 * The page link of a view. A view that names no `state` opens across every
 * state (the API list without a state filter), so the page, which defaults to
 * the Open lens, is told `state=all` to show the same rows the count counted.
 */
export function quickViewHref(params: string): string {
  const q = new URLSearchParams(params)
  if (!q.has('state')) q.set('state', 'all')
  return `/findings?${q.toString()}`
}

/** Params that shape how a list shows, not which findings it holds. */
const PRESENTATION_PARAMS = new Set([
  'page',
  'per_page',
  'sort',
  'group',
  'density',
  'tab',
  'q',
  'view',
])

function scopeOf(search: string | URLSearchParams): Map<string, string> {
  const q = typeof search === 'string' ? new URLSearchParams(search) : search
  const scope = new Map<string, string>()
  for (const [k, v] of q.entries()) if (!PRESENTATION_PARAMS.has(k) && v !== '') scope.set(k, v)
  return scope
}

/**
 * Whether the list in `search` is exactly this view: the same filter params
 * and nothing more. Page, sort, search text and grouping do not count. A list
 * with no params at all is the Open lens, i.e. the Active view.
 */
export function quickViewIsActive(search: string | URLSearchParams, view: QuickView): boolean {
  const current = scopeOf(search)
  const wanted = scopeOf(quickViewHref(view.params).split('?')[1] ?? '')
  // The page defaults to the Open lens when the URL names no state.
  if (!current.has('state') && !current.has('status')) current.set('state', 'open')
  if (!wanted.has('state') && !wanted.has('status')) wanted.set('state', 'open')
  // A view without a `state` is opened with state=all (see quickViewHref).
  if (current.size !== wanted.size) return false
  for (const [k, v] of wanted) if (current.get(k) !== v) return false
  return true
}
