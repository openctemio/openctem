'use client'

/**
 * The findings filter bar's text mode: the whole filter as one line of query
 * text in the shared QueryInput, editing the same state as the chips. A
 * filter chips can show is written back as today's flat URL params, so every
 * link keeps its form; one they cannot (an OR across fields, a group) goes to
 * `fq=<canonical text>` and shows as one Advanced chip, never flattened or
 * partly dropped. The toggle, the editor and the chip are the shared ones of
 * `features/query`.
 */

import { type ParseResult } from '@/features/query/api/query-api'
import {
  FQ_PARAM,
  QueryEditor,
  useFilterText as useQueryFilterText,
} from '@/features/query/components/query-mode'
import { NON_FILTER_PARAMS } from './model'

export { AdvancedChip, FQ_PARAM, QueryModeToggle } from '@/features/query/components/query-mode'

// Params the text stands for: the filter params and q. Page state (page,
// sort, view, columns, density, tab) is kept.
const KEEP = new Set(
  [...NON_FILTER_PARAMS].filter((p) => p !== 'q' && p !== 'state' && p !== FQ_PARAM)
)

/** The filter part of the page URL as a list query string. */
export function filterParams(search: URLSearchParams, skip: ReadonlySet<string>): string {
  const out = new URLSearchParams()
  search.forEach((v, k) => {
    if (!KEEP.has(k) && !skip.has(k) && k !== FQ_PARAM) out.append(k, v)
  })
  return out.toString()
}

/** The page URL with the filter replaced by a checked text filter. */
export function applyTextFilter(
  search: URLSearchParams,
  skip: ReadonlySet<string>,
  result: ParseResult
): URLSearchParams {
  const next = new URLSearchParams()
  search.forEach((v, k) => {
    if (KEEP.has(k) || skip.has(k)) next.append(k, v)
  })
  next.delete('page')
  if (result.text === '') return next
  if (!result.advanced && result.params) {
    for (const [k, v] of Object.entries(result.params)) next.set(k, v)
  } else {
    next.set(FQ_PARAM, result.text)
  }
  return next
}

/** The text of the current filter: fq as written, or the params printed by the server. */
export function useFilterText(search: URLSearchParams, skip: ReadonlySet<string>, active: boolean) {
  return useQueryFilterText('findings', search.get(FQ_PARAM), filterParams(search, skip), active)
}

/** The text editor of the filter. */
export function FilterQueryEditor({
  search,
  skip,
  resultCount,
  onSearchChange,
}: {
  search: URLSearchParams
  skip: ReadonlySet<string>
  resultCount?: number | null
  onSearchChange: (next: URLSearchParams) => void
}) {
  const initial = useFilterText(search, skip, true)
  return (
    <QueryEditor
      entity="findings"
      testId="findings-query-editor"
      initial={initial}
      resultCount={resultCount}
      onResult={(r) => onSearchChange(applyTextFilter(search, skip, r))}
    />
  )
}
