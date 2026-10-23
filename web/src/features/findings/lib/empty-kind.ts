/**
 * Which kind of empty the findings list is in. The three differ in what the
 * person should do next, so they never share one message:
 *
 * - `no_access`: the read was refused. Nothing is hidden by a filter; the
 *   caller may not read findings here.
 * - `nothing`: the organization has no findings at all and nothing narrows
 *   the list. The next step is to bring findings in.
 * - `no_match`: findings exist, but the filters, the search or the state hide
 *   them. The next step is to widen the view.
 */
export type FindingsEmptyKind = 'nothing' | 'no_match' | 'no_access'

export interface FindingsEmptyInput {
  /** Findings the caller can see in the page's scope, every state. */
  orgTotal: number | undefined
  /** Facet and chip filters applied by the person (not the page's context scope). */
  filterCount: number
  hasSearch: boolean
  /** The context scope the page was opened with (an asset, a scan, a CVE...). */
  hasContextScope: boolean
  /** The list read answered 403. */
  forbidden: boolean
}

export function findingsEmptyKind(input: FindingsEmptyInput): FindingsEmptyKind {
  if (input.forbidden) return 'no_access'
  const unnarrowed = input.filterCount === 0 && !input.hasSearch && !input.hasContextScope
  // An unknown total (stats not loaded or failed) never claims "nothing yet":
  // that would tell an admin to import what may already be there.
  if (unnarrowed && input.orgTotal === 0) return 'nothing'
  return 'no_match'
}
