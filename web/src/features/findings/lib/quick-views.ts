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
  /** On a view that leaves informational findings out: how many it leaves out. */
  informational_hidden?: number
}

export interface QuickViewsResponse {
  views: QuickView[]
  /**
   * Whether the work views show informational findings for this caller (their
   * preference, else the organization's default). When false, Active, My queue
   * and SLA breached carry `informational=false`; Needs triage always does.
   */
  include_informational?: boolean
  as_of?: string
}

/** English fallbacks; the i18n key is `findings.quickView.<key>`. */
export const QUICK_VIEW_LABELS: Record<QuickViewKey, string> = {
  active: 'Active',
  needs_triage: 'Needs triage',
  my_queue: 'My queue',
  sla_breached: 'SLA breached',
  pending_approval: 'Pending approval',
  accepted_expiring: 'Accepted, expiring soon',
  closed: 'Closed',
}

export const quickViewLabelKey = (key: string) => `findings.quickView.${key}`

/** Views the console knows how to label, in the API's order; an unknown key is dropped. */
export function knownQuickViews(views: readonly QuickView[] | undefined): QuickView[] {
  return (views ?? []).filter((v): v is QuickView =>
    (QUICK_VIEW_KEYS as readonly string[]).includes(v.key)
  )
}

/** The list filter that leaves informational findings (info and none) out. */
export const INFORMATIONAL_PARAM = 'informational'

/**
 * Whether a list leaves informational findings out when its URL does not say:
 * the API's work-view rule (api/docs/architecture/findings-work-views.md). An
 * explicit severity or a saved view never hides them; Needs triage (status new)
 * always does; the Open lens does unless the caller includes them.
 */
export function defaultHidesInformational(
  search: string | URLSearchParams,
  includeInformational: boolean
): boolean {
  const q = typeof search === 'string' ? new URLSearchParams(search) : search
  if (q.get('severity') || q.get('severities') || q.get('view')) return false
  if (q.get('status') === 'new') return true
  return (q.get('state') || 'open') === 'open' && !includeInformational
}

/**
 * Whether the list in `search` leaves informational findings out: the URL's
 * `informational` value when it has one, else the default. An explicit severity
 * always wins (picking Informational shows them).
 */
export function informationalHidden(
  search: string | URLSearchParams,
  includeInformational: boolean
): boolean {
  const q = typeof search === 'string' ? new URLSearchParams(search) : search
  if (q.get('severity') || q.get('severities')) return false
  const explicit = q.get(INFORMATIONAL_PARAM)
  if (explicit === 'false') return true
  if (explicit === 'true') return false
  return defaultHidesInformational(q, includeInformational)
}

/**
 * `search` with `informational` set only where it differs from the default, so
 * a link stays the plain view and the page reads it the same way.
 */
export function withInformational(
  search: URLSearchParams,
  hidden: boolean,
  includeInformational: boolean
): URLSearchParams {
  const q = new URLSearchParams(search)
  q.delete(INFORMATIONAL_PARAM)
  if (defaultHidesInformational(q, includeInformational) !== hidden) {
    q.set(INFORMATIONAL_PARAM, String(!hidden))
  }
  return q
}

/**
 * The page link of a view. A view that names no `state` opens across every
 * state (the API list without a state filter), so the page, which defaults to
 * the Open lens, is told `state=all` to show the same rows the count counted.
 * `informational` is kept only where the page would not apply it by itself.
 */
export function quickViewHref(params: string, includeInformational = false): string {
  const q = new URLSearchParams(params)
  if (!q.has('state')) q.set('state', 'all')
  const out = withInformational(
    q,
    informationalHidden(q, includeInformational),
    includeInformational
  )
  return `/findings?${out.toString()}`
}

/** Params that shape how a list shows, not which findings it holds. */
const PRESENTATION_PARAMS = new Set([
  'page',
  'per_page',
  'sort',
  'group',
  'density',
  'columns',
  'tab',
  'q',
  'view',
])

function scopeOf(
  search: string | URLSearchParams,
  includeInformational: boolean
): Map<string, string> {
  const q = typeof search === 'string' ? new URLSearchParams(search) : search
  const scope = new Map<string, string>()
  for (const [k, v] of q.entries())
    if (!PRESENTATION_PARAMS.has(k) && k !== INFORMATIONAL_PARAM && v !== '') scope.set(k, v)
  // Compared by effect: an absent value means the default for the rest.
  scope.set(INFORMATIONAL_PARAM, String(!informationalHidden(q, includeInformational)))
  return scope
}

/**
 * Whether the list in `search` is exactly this view: the same filter params
 * and nothing more. Page, sort, search text and grouping do not count. A list
 * with no params at all is the Open lens, i.e. the Active view.
 */
export function quickViewIsActive(
  search: string | URLSearchParams,
  view: QuickView,
  includeInformational = false
): boolean {
  const current = scopeOf(search, includeInformational)
  const wanted = scopeOf(
    quickViewHref(view.params, includeInformational).split('?')[1] ?? '',
    includeInformational
  )
  // The page defaults to the Open lens when the URL names no state.
  if (!current.has('state') && !current.has('status')) current.set('state', 'open')
  if (!wanted.has('state') && !wanted.has('status')) wanted.set('state', 'open')
  // A view without a `state` is opened with state=all (see quickViewHref).
  if (current.size !== wanted.size) return false
  for (const [k, v] of wanted) if (current.get(k) !== v) return false
  return true
}
