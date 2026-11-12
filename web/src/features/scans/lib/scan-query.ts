/**
 * The scans page and its query text. The page keeps its filters in its own
 * URL params (status, type, schedule, origin, tag, q); the text box speaks
 * the list's names. A filter the controls can show is written back as the
 * page's params, so every link keeps its form; one they cannot (an OR across
 * fields, a total_runs range, a group) goes to `fq=<canonical text>` and
 * shows as one Advanced chip, never flattened or partly dropped.
 */

import type { ParseResult } from '@/features/query/api/query-api'

/** The URL param of a filter the controls cannot show. */
export const SCAN_FQ_PARAM = 'fq'

/** Page URL param -> the list's param, for the filters the controls can show. */
const PAGE_TO_LIST: Readonly<Record<string, string>> = {
  status: 'status',
  type: 'scan_type',
  schedule: 'schedule_type',
  origin: 'origin',
  tag: 'tag',
  q: 'q',
}

const LIST_TO_PAGE: Readonly<Record<string, string>> = Object.fromEntries(
  Object.entries(PAGE_TO_LIST).map(([page, list]) => [list, page])
)

/** The filter part of the page URL as a list query string (the list's names). */
export function scanFilterParams(search: URLSearchParams): string {
  const out = new URLSearchParams()
  for (const [pageName, listName] of Object.entries(PAGE_TO_LIST)) {
    const v = search.get(pageName)
    if (v && v !== 'all') out.set(listName, v)
  }
  return out.toString()
}

/** Whether the controls can show a parsed filter: its params are theirs, one value each. */
function showable(result: ParseResult): boolean {
  if (result.advanced || !result.params) return false
  return Object.entries(result.params).every(
    ([name, value]) =>
      name in LIST_TO_PAGE && (name === 'tag' || name === 'q' || !value.includes(','))
  )
}

/** The page URL with the filter replaced by a checked text filter. */
export function applyScanTextFilter(search: URLSearchParams, result: ParseResult): URLSearchParams {
  const next = new URLSearchParams(search)
  for (const pageName of [...Object.keys(PAGE_TO_LIST), SCAN_FQ_PARAM, 'page'])
    next.delete(pageName)
  if (result.text === '') return next
  if (showable(result)) {
    for (const [name, value] of Object.entries(result.params ?? {}))
      next.set(LIST_TO_PAGE[name], value)
  } else {
    next.set(SCAN_FQ_PARAM, result.text)
  }
  return next
}
