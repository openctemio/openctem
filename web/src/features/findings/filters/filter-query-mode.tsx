'use client'

/**
 * The findings list's Query mode: the whole filter as one line of query text
 * in the search field, editing the same state as the chips. A filter chips
 * can show is written back as today's flat URL params, so every link keeps
 * its form; one they cannot (an OR across fields, a group) goes to
 * `fq=<canonical text>` and shows as one Advanced chip in Basic mode, never
 * flattened or partly dropped. The field, the switch and the chip are the
 * shared ones of `features/query` and `ListSearch`.
 *
 * The State lens and the Practice switch are part of the filter: the text
 * says them (`state=open practice!=compliance`), and what the text leaves
 * out is not restricted (state and practice "all"), so a round trip through
 * the text never changes the list.
 */

import { type ParseResult } from '@/features/query/api/query-api'
import { FQ_PARAM } from '@/features/query/components/query-mode'
import { savedViewId } from '@/features/saved-views/api/use-saved-views'
import { isPractice, PRACTICE_PARAM, type PracticeView } from '../lib/practice'
import { NON_FILTER_PARAMS } from './model'

export { AdvancedChip, FQ_PARAM } from '@/features/query/components/query-mode'

/** The URL param of the State lens (the API's `state` field). */
const STATE_PARAM = 'state'

// Params the text does not stand for: page state (page, sort, view, columns,
// density, tab). The filter params, q, state and fq are the text's.
const KEEP = new Set(
  [...NON_FILTER_PARAMS].filter((p) => p !== 'q' && p !== STATE_PARAM && p !== FQ_PARAM)
)

/**
 * The filter part of the page URL as a list query string. `scope` adds the
 * State lens and the Practice switch as the list applies them (in the API's
 * names) where the URL does not say them itself.
 */
export function filterParams(
  search: URLSearchParams,
  skip: ReadonlySet<string>,
  scope: Record<string, string> = {}
): string {
  const out = new URLSearchParams()
  search.forEach((v, k) => {
    if (!KEEP.has(k) && !skip.has(k) && k !== FQ_PARAM) out.append(k, v)
  })
  for (const [k, v] of Object.entries(scope)) if (!out.has(k)) out.set(k, v)
  return out.toString()
}

/** The Practice switch a flat filter names, or null when the switch cannot show it. */
function practiceViewOf(params: Record<string, string>): PracticeView | null {
  const only = params.practice
  const not = params.practice_not
  if (only === undefined && not === undefined) return 'all'
  if (only === undefined && not === 'compliance') return 'vulnerabilities'
  if (not === undefined && only !== undefined && isPractice(only)) return only
  return null
}

/**
 * The page URL with the filter replaced by a checked text filter. The text
 * owns the State lens and the Practice switch: both are written explicitly,
 * "all" when the text leaves them out.
 *
 * With a saved view open (`view=<id>`) the view sets the lens and the switch
 * while the URL does not, and the text does not print them (`filterParams`
 * is given no scope for them): what the text leaves out then stays the
 * view's, so applying a text never widens the view's own scope.
 */
export function applyTextFilter(
  search: URLSearchParams,
  skip: ReadonlySet<string>,
  result: ParseResult
): URLSearchParams {
  const next = new URLSearchParams()
  search.forEach((v, k) => {
    if ((KEEP.has(k) || skip.has(k)) && k !== PRACTICE_PARAM) next.append(k, v)
  })
  next.delete('page')
  const view = !!savedViewId(search.get('view'))
  // null: not written, the open view's own applies.
  let state: string | null = view && !search.has(STATE_PARAM) ? null : 'all'
  let practice: PracticeView | null = view && !search.has(PRACTICE_PARAM) ? null : 'all'
  if (result.text !== '') {
    const flat = !result.advanced && result.params ? { ...result.params } : null
    const said = flat ? practiceViewOf(flat) : null
    if (flat && said !== null) {
      if (flat[STATE_PARAM]) state = flat[STATE_PARAM]
      delete flat[STATE_PARAM]
      delete flat.practice
      delete flat.practice_not
      if (said !== 'all') practice = said
      for (const [k, v] of Object.entries(flat)) next.set(k, v)
    } else {
      next.set(FQ_PARAM, result.text)
    }
  }
  if (state !== null) next.set(STATE_PARAM, state)
  if (practice !== null) next.set(PRACTICE_PARAM, practice)
  return next
}
