'use client'

/**
 * The text mode every filter bar shares: a toggle (Ctrl+/ also toggles it),
 * the text editor on the shared QueryInput, and the chip of a filter chips
 * cannot show. Chips and text are two views of one state; the page decides how
 * a checked text is written back to its URL (a filter chips can show as flat
 * params, anything else as one `fq` text).
 */

import { useEffect, useState } from 'react'
import { Code2, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import { QueryInput } from './query-input'
import { queryApi, type ParseResult, type QueryEntity } from '../api/query-api'

/** The URL param of a filter chips cannot show. */
export const FQ_PARAM = 'fq'

/**
 * The text of the current filter: fq as written, or the page's flat list
 * params printed by the server (null until known). `params` is the filter part
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
      .parse({ entity, params })
      .then((r) => {
        if (!cancelled) setText(r.valid ? r.text : '')
      })
      .catch(() => {
        if (!cancelled) setText('')
      })
    return () => {
      cancelled = true
    }
  }, [entity, active, fq, params])
  return text
}

/** The text mode toggle. */
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
      iconOnlyBelow="sm"
      type="button"
      variant={active ? 'secondary' : 'ghost'}
      size="sm"
      className="size-7 gap-1 px-0 text-xs sm:w-auto sm:px-2"
      aria-pressed={active}
      onClick={onToggle}
      title={t('queryInput.mode.toggleHint')}
    >
      <Code2 className="size-3.5" aria-hidden />
      {/* Icon only on a phone (the label stays for screen readers), so the
          toolbar keeps its two rows. */}
      <span className="sr-only sm:not-sr-only">{t('queryInput.mode.toggle')}</span>
    </Button>
  )
}

/** The text editor of a filter: loads the current text, then edits it. */
export function QueryEditor({
  entity,
  testId,
  initial,
  resultCount,
  preferFields,
  recentScope,
  onResult,
}: {
  entity: QueryEntity
  testId: string
  /** The current filter's text; null while it is still being read. */
  initial: string | null
  resultCount?: number | null
  /** Fields the completion lists first (the open tab's own fields). */
  preferFields?: string[]
  /** Recent queries are kept per scope (an entity and tab). */
  recentScope?: string
  onResult: (result: ParseResult) => void
}) {
  const { t } = useTranslation()
  const [text, setText] = useState('')
  const [loaded, setLoaded] = useState(false)
  useEffect(() => {
    if (initial !== null) {
      setText(initial)
      setLoaded(true)
    }
  }, [initial])
  return (
    <div className="w-full" data-testid={testId}>
      <QueryInput
        entity={entity}
        value={text}
        onChange={setText}
        disabled={!loaded}
        autoFocus
        resultCount={resultCount}
        preferFields={preferFields}
        recentScope={recentScope}
        ariaLabel={t('queryInput.mode.label')}
        onSubmit={onResult}
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
