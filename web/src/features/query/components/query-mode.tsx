'use client'

/**
 * The Query mode every list search field shares (the in-field Basic | Query
 * switch of `ListSearch`, the editor on the shared QueryInput), and the chip
 * of a filter chips cannot show. Chips and text are two views of one state; the page decides how
 * a checked text is written back to its URL (a filter chips can show as flat
 * params, anything else as one `fq` text).
 */

import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import type { ListSearchMode, ListSearchQuery } from '@/features/shared/components/list-search'
import { toDisplayText } from '@/lib/untrusted-text'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import { queryApi, type ParseResult, type QueryEntity } from '../api/query-api'

// The editor (completion, checks) loads when a list first switches to Query
// mode, not with the list.
const QueryInput = lazy(() => import('./query-input').then((m) => ({ default: m.QueryInput })))

/** The URL param of a filter chips cannot show. */
export const FQ_PARAM = 'fq'

/**
 * The URL param of the search field's mode: `mode=query` opens the list in
 * Query mode, with the filter as text in the field; absent, Basic. It is page
 * state, never a filter: no chip, no request param.
 */
export const MODE_PARAM = 'mode'
const QUERY_MODE = 'query'

/** Whether a list URL opens in Query mode. */
export function queryModeIn(search: URLSearchParams): boolean {
  return search.get(MODE_PARAM) === QUERY_MODE
}

/** A copy of a list URL in the given mode (Basic is the absent param). */
export function withQueryMode(search: URLSearchParams, active: boolean): URLSearchParams {
  const next = new URLSearchParams(search)
  if (active) next.set(MODE_PARAM, QUERY_MODE)
  else next.delete(MODE_PARAM)
  return next
}

/** A saved view's page params for the mode on screen (saved with the view). */
export function modePageParams(active: boolean): Record<string, string> {
  return { [MODE_PARAM]: active ? QUERY_MODE : 'basic' }
}

/** Whether a saved view opens in Query mode. */
export function viewOpensInQueryMode(view: { page_params?: Record<string, string> }): boolean {
  return view.page_params?.[MODE_PARAM] === QUERY_MODE
}

/**
 * The text of the current filter: the page's flat list params printed by the
 * server, with fq (a filter chips cannot show) ANDed after them, or null
 * while it is being read or while `active` is off. `params` is the filter part
 * of the list query, in the API's own names.
 */
export function useFilterText(
  entity: QueryEntity,
  fq: string | null,
  params: string,
  active: boolean
) {
  const [text, setText] = useState<string | null>(null)
  useEffect(() => {
    if (!active) {
      setText(null)
      return
    }
    let cancelled = false
    if (params === '') {
      setText(fq ?? '')
      return
    }
    queryApi
      .parse({ entity, params })
      .then((r) => {
        if (cancelled) return
        const printed = r.valid ? r.text : ''
        setText(joinFilterText(printed, fq))
      })
      .catch(() => {
        // Without the printer the text would drop the params: say nothing
        // rather than something partial.
        if (!cancelled) setText(fq ?? '')
      })
    return () => {
      cancelled = true
    }
  }, [entity, active, fq, params])
  return text
}

/** Printed params and an fq text as one filter (both apply, as on the list). */
export function joinFilterText(printed: string, fq: string | null): string {
  if (!fq) return printed
  if (!printed) return fq
  return `${printed} (${fq})`
}

export interface ListQueryModeOptions {
  entity: QueryEntity
  /** Query mode is on: the page's URL says so (`mode=query`, `queryModeIn`). */
  active: boolean
  /** Write the mode alone into the page's URL. */
  onActiveChange: (active: boolean) => void
  /** The fq text, when the filter has one. */
  fq: string | null
  /** The filter as the list's params (API names), for the server's printer. */
  params: string
  /**
   * Write a checked text back to the page, with the mode the field is left
   * in, in one URL write (Enter keeps Query mode; switching to Basic with an
   * edit applies it and leaves Query mode).
   */
  onApply: (result: ParseResult, active: boolean) => void
  /** The list's total, read out under the field. */
  resultCount?: number | null
  /** Fields the completion lists first (the open tab's own fields). */
  preferFields?: string[]
  /** Recent queries are kept per scope (an entity and tab). */
  recentScope?: string
  /** The editor's accessible name (default "Filter as query text"). */
  ariaLabel?: string
  testId: string
}

/**
 * The Query mode of a list's search field (`ListSearch` `query`). The page
 * holds it, so the chips row can step aside while the text owns the filter.
 *
 * - Basic to Query: the field shows the current filter as text, printed by
 *   the server from the page's params (never built on the client).
 * - Enter applies a valid text (the page writes it back as flat params, or as
 *   fq when chips cannot show it); the field stays in Query mode.
 * - Escape puts back the applied text.
 * - Query to Basic with an edit not applied yet applies it first, so the
 *   switch never drops what was typed; an invalid text keeps Query mode with
 *   its problem shown.
 * - The mode is the page's, kept in its URL (`mode=query`): a shared link,
 *   a reload or a saved view opens in the mode it was left in.
 */
export function useListQueryMode(opts: ListQueryModeOptions): {
  active: boolean
  setActive: (on: boolean) => void
  /** The mode, for a switch drawn outside the field (`ListSearchModeSwitch`). */
  mode: ListSearchMode
  onModeChange: (mode: ListSearchMode) => void
  query: ListSearchQuery
} {
  const { t } = useTranslation()
  const { entity, fq, params, active, resultCount, preferFields, recentScope, ariaLabel, testId } =
    opts
  const applied = useFilterText(entity, fq, params, active)
  const [draft, setDraftState] = useState<string | null>(null)
  // The server's refusal of a text the mode switch tried to apply, or of a
  // link's text, shown in the editor until the text changes.
  const [refused, setRefused] = useState<ParseResult | null>(null)
  // The field takes the focus when the person switches to Query mode, not
  // when a link or a reload opens the page in it.
  const [switched, setSwitched] = useState(false)
  const setDraft = useCallback((text: string | null) => {
    setDraftState(text)
    setRefused(null)
  }, [])
  useEffect(() => {
    setDraft(applied)
  }, [applied, setDraft])

  const latest = useRef({ draft, applied, onApply: opts.onApply, onActive: opts.onActiveChange })
  useEffect(() => {
    latest.current = { draft, applied, onApply: opts.onApply, onActive: opts.onActiveChange }
  })

  // A link (or a reload) that opens in Query mode with a text chips cannot
  // show: the text is checked once, so a text the server refuses shows its
  // problem in the field instead of an empty list without a reason.
  const firstText = useRef(true)
  useEffect(() => {
    if (applied === null || !firstText.current) return
    firstText.current = false
    if (switched || !fq || applied.trim() === '') return
    const text = applied
    queryApi
      .parse({ entity, text })
      .then((r) => {
        // Only while the field still holds that text.
        if (!r.valid && latest.current.draft === text) setRefused(r)
      })
      .catch(() => undefined)
  }, [applied, entity, fq, switched])

  const setActive = useCallback(
    (on: boolean) => {
      const { draft: text, applied: was, onApply, onActive } = latest.current
      if (on) {
        setSwitched(true)
        onActive(true)
        return
      }
      if (text === null || text.trim() === (was ?? '').trim()) {
        onActive(false)
        return
      }
      queryApi
        .parse({ entity, text })
        .then((r) => {
          if (!r.valid) {
            setRefused(r)
            return
          }
          onApply(r, false)
        })
        .catch(() => undefined)
    },
    [entity]
  )

  const onSubmit = useCallback((r: ParseResult) => latest.current.onApply(r, true), [])
  const revert = useCallback(() => setDraft(latest.current.applied), [setDraft])

  const query: ListSearchQuery = {
    active,
    onActiveChange: setActive,
    renderEditor: ({ inputClassName, adornments }) => (
      <div className="w-full" data-testid={testId}>
        <Suspense
          fallback={
            <div className="relative">
              <Input
                disabled
                className={cn('font-mono', inputClassName)}
                aria-label={ariaLabel ?? t('queryInput.mode.label')}
                value={draft ?? ''}
                readOnly
              />
              {adornments}
            </div>
          }
        >
          <QueryInput
            entity={entity}
            value={draft ?? ''}
            onChange={setDraft}
            applied={applied ?? ''}
            checked={refused}
            disabled={draft === null}
            autoFocus={switched}
            resultCount={resultCount}
            preferFields={preferFields}
            recentScope={recentScope}
            ariaLabel={ariaLabel ?? t('queryInput.mode.label')}
            onSubmit={onSubmit}
            onEscape={revert}
            quietStatus
            inputClassName={inputClassName}
            adornments={adornments}
          />
        </Suspense>
      </div>
    ),
  }
  const onModeChange = useCallback((m: ListSearchMode) => setActive(m === 'query'), [setActive])
  return { active, setActive, mode: active ? 'query' : 'basic', onModeChange, query }
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
        {t('queryInput.mode.advanced')}{' '}
        <span className="font-mono" dir="ltr">
          {toDisplayText(text, 80)}
        </span>
      </button>
      <button
        type="button"
        onClick={onRemove}
        aria-label={t('queryInput.mode.removeAdvanced')}
        className="inline-flex size-5 shrink-0 items-center justify-center rounded-full text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <X className="size-3" aria-hidden />
      </button>
    </span>
  )
}
