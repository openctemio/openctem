import type { PracticeCounts } from '../api/use-practice-counts'
import type { PracticeView } from './practice'

/**
 * Which kind of empty the findings list is in. The three differ in what the
 * person should do next, so they never share one message:
 *
 * - `no_access`: the read was refused. Nothing is hidden by a filter; the
 *   caller may not read findings here.
 * - `nothing`: the organization has no findings at all and nothing narrows
 *   the list. The next step is to bring findings in.
 * - `practice_nothing`: the organization has findings, but the chosen practice
 *   (Compliance, Application security...) has none in any state and nothing
 *   else narrows the list: that practice's first run. The next step is to
 *   bring in what that practice covers.
 * - `no_match`: findings exist, but the filters, the search or the state hide
 *   them. The next step is to widen the view.
 */
export type FindingsEmptyKind = 'nothing' | 'practice_nothing' | 'no_match' | 'no_access'

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
  /**
   * Findings of the chosen practice in the page's scope, every state (no
   * practice chosen, or not known: undefined).
   */
  practiceTotal?: number
}

export function findingsEmptyKind(input: FindingsEmptyInput): FindingsEmptyKind {
  if (input.forbidden) return 'no_access'
  const unnarrowed = input.filterCount === 0 && !input.hasSearch && !input.hasContextScope
  // An unknown total (stats not loaded or failed) never claims "nothing yet":
  // that would tell an admin to import what may already be there.
  if (unnarrowed && input.orgTotal === 0) return 'nothing'
  if (unnarrowed && input.practiceTotal === 0) return 'practice_nothing'
  return 'no_match'
}

/**
 * Whether data already on the page shows that `practice` holds findings in the
 * page's scope: a list answer of that practice with rows, or a positive count
 * for it in the practice switch's counts (which come with every list answer).
 * Then an empty list of that practice is a no-match and its total in every
 * state need not be asked for.
 */
export function practiceKnownToHoldFindings(
  practice: PracticeView,
  input: { listTotal: number | undefined; counts: PracticeCounts | undefined }
): boolean {
  if ((input.listTotal ?? 0) > 0) return true
  const c = input.counts
  if (!c || practice === 'all') return false
  const n = practice === 'vulnerabilities' ? c.vulnerabilities : c.byPractice[practice]
  return (n ?? 0) > 0
}
