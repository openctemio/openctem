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
import type { ListSearchQuery } from '@/features/shared/components/list-search'
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
  /** The fq text, when the filter has one. */
  fq: string | null
  /** The filter as the list's params (API names), for the server's printer. */
  params: string
  /** Write a checked text back to the page. */
  onApply: (result: ParseResult) => void
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
 */
export function useListQueryMode(opts: ListQueryModeOptions): {
  active: boolean
  setActive: (on: boolean) => void
  query: ListSearchQuery
} {
  const { t } = useTranslation()
  const { entity, fq, params, resultCount, preferFields, recentScope, ariaLabel, testId } = opts
  const [active, setActiveState] = useState(false)
  const applied = useFilterText(entity, fq, params, active)
  const [draft, setDraftState] = useState<string | null>(null)
  // The server's refusal of a text the mode switch tried to apply, shown in
  // the editor until the text changes.
  const [refused, setRefused] = useState<ParseResult | null>(null)
  const setDraft = useCallback((text: string | null) => {
    setDraftState(text)
    setRefused(null)
  }, [])
  useEffect(() => {
    setDraft(applied)
  }, [applied, setDraft])

  const latest = useRef({ draft, applied, onApply: opts.onApply })
  useEffect(() => {
    latest.current = { draft, applied, onApply: opts.onApply }
  })

  const setActive = useCallback(
    (on: boolean) => {
      if (on) {
        setActiveState(true)
        return
      }
      const { draft: text, applied: was, onApply } = latest.current
      if (text === null || text.trim() === (was ?? '').trim()) {
        setActiveState(false)
        return
      }
      queryApi
        .parse({ entity, text })
        .then((r) => {
          if (!r.valid) {
            setRefused(r)
            return
          }
          onApply(r)
          setActiveState(false)
        })
        .catch(() => undefined)
    },
    [entity]
  )

  const onSubmit = useCallback((r: ParseResult) => latest.current.onApply(r), [])
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
            autoFocus
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
  return { active, setActive, query }
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
