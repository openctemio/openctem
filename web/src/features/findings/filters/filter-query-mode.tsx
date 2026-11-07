'use client'

/**
 * The findings filter bar's text mode: the whole filter as one line of query
 * text in the shared QueryInput, editing the same state as the chips. A
 * filter chips can show is written back as today's flat URL params, so every
 * link keeps its form; one they cannot (an OR across fields, a group) goes to
 * `fq=<canonical text>` and shows as one Advanced chip, never flattened or
 * partly dropped.
 */

import { useEffect, useState } from 'react'
import { Code2, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import { QueryInput } from '@/features/query/components/query-input'
import { queryApi, type ParseResult } from '@/features/query/api/query-api'
import { NON_FILTER_PARAMS } from './model'

/** The URL param of a filter chips cannot show. */
export const FQ_PARAM = 'fq'

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
  const fq = search.get(FQ_PARAM)
  const params = filterParams(search, skip)
  const [text, setText] = useState<string | null>(null)
  useEffect(() => {
    if (!active) return
    let cancelled = false
    if (fq) {
      setText(fq)
      return
    }
    if (params === '') {
      setText('')
      return
    }
    queryApi
      .parse({ entity: 'findings', params })
      .then((r) => {
        if (!cancelled) setText(r.valid ? r.text : '')
      })
      .catch(() => {
        if (!cancelled) setText('')
      })
    return () => {
      cancelled = true
    }
  }, [active, fq, params])
  return text
}

/** The text mode toggle (Ctrl+/ also toggles it). */
export function QueryModeToggle({ active, onToggle }: { active: boolean; onToggle: () => void }) {
  const { t } = useTranslation()
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === '/' && (e.ctrlKey || e.metaKey)) {
        e.preventDefault()
        onToggle()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onToggle])
  return (
    <Button
      type="button"
      variant={active ? 'secondary' : 'ghost'}
      size="sm"
      className="h-7 gap-1 px-2 text-xs"
      aria-pressed={active}
      onClick={onToggle}
      title={t('findings.query.toggleHint')}
    >
      <Code2 className="size-3.5" aria-hidden />
      {t('findings.query.toggle')}
    </Button>
  )
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
  const { t } = useTranslation()
  const initial = useFilterText(search, skip, true)
  const [text, setText] = useState('')
  const [loaded, setLoaded] = useState(false)
  useEffect(() => {
    if (initial !== null) {
      setText(initial)
      setLoaded(true)
    }
  }, [initial])
  return (
    <div className="w-full" data-testid="findings-query-editor">
      <QueryInput
        entity="findings"
        value={text}
        onChange={setText}
        disabled={!loaded}
        autoFocus
        resultCount={resultCount}
        ariaLabel={t('findings.query.label')}
        onSubmit={(r) => onSearchChange(applyTextFilter(search, skip, r))}
      />
    </div>
  )
}

/** The chip of an fq filter: its text, opening the editor; X removes it. */
export function AdvancedChip({
  text,
  onOpen,
  onRemove,
}: {
  text: string
  onOpen: () => void
  onRemove: () => void
}) {
  const { t } = useTranslation()
  return (
    <span
      data-testid="filter-chip-advanced"
      className="inline-flex max-w-full items-center gap-1 rounded-full border bg-muted/50 ps-2.5 pe-1 py-0.5 text-xs"
    >
      <button type="button" className="min-w-0 truncate text-start" onClick={onOpen}>
        {t('findings.query.advanced')}{' '}
        <span className="font-mono" dir="ltr">
          {toDisplayText(text, 80)}
        </span>
      </button>
      <button
        type="button"
        onClick={onRemove}
        aria-label={t('findings.query.removeAdvanced')}
        className="inline-flex size-5 shrink-0 items-center justify-center rounded-full text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <X className="size-3" aria-hidden />
      </button>
    </span>
  )
}
