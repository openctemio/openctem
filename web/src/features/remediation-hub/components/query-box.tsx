'use client'

/**
 * A query box for "findings where ..." (the custom query language,
 * api/docs/rfcs/RFC-115-custom-query-language.md): the text, field and value
 * completion from the caller's own schema, and a live check through
 * POST /api/v1/query/explain that shows the query in plain words or its
 * problems with their line and column. The query is plain text: nothing is
 * rendered as HTML.
 */

import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Textarea } from '@/components/ui/textarea'
import { cn } from '@/lib/utils'
import {
  queryProblems,
  taskQueryApi,
  useFindingQuerySchema,
  type QueryProblem,
} from '../api/use-task-query'
import { applySuggestion, suggest } from '../lib/query-complete'

const CHECK_DELAY_MS = 600

export function QueryBox({
  id,
  value,
  onChange,
  disabled,
  autoFocus,
}: {
  id: string
  value: string
  onChange: (v: string) => void
  disabled?: boolean
  autoFocus?: boolean
}) {
  const { t } = useTranslation()
  const listId = useId()
  const hintId = useId()
  const ref = useRef<HTMLTextAreaElement>(null)
  const { data: schema } = useFindingQuerySchema(!disabled)
  const fields = useMemo(() => schema?.fields ?? [], [schema])
  const [caret, setCaret] = useState(0)
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const [description, setDescription] = useState<string | null>(null)
  const [problems, setProblems] = useState<QueryProblem[]>([])
  const [checking, setChecking] = useState(false)

  const options = useMemo(
    () => (open ? suggest(value, caret, fields) : []),
    [open, value, caret, fields]
  )

  // Live check, debounced; a stale answer never overwrites a newer one.
  useEffect(() => {
    const text = value.trim()
    if (!text || disabled) {
      setDescription(null)
      setProblems([])
      return
    }
    let cancelled = false
    const timer = setTimeout(() => {
      setChecking(true)
      taskQueryApi
        .explain(text)
        .then((ex) => {
          if (cancelled) return
          setDescription(ex.description)
          setProblems([])
        })
        .catch((err: unknown) => {
          if (cancelled) return
          setDescription(null)
          const p = queryProblems(err)
          setProblems(p.length > 0 ? p : [{ start: 0, end: 0, line: 0, column: 0, message: '' }])
        })
        .finally(() => {
          if (!cancelled) setChecking(false)
        })
    }, CHECK_DELAY_MS)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [value, disabled])

  const accept = (option: string) => {
    const next = applySuggestion(value, caret, option)
    onChange(next.text)
    setOpen(false)
    requestAnimationFrame(() => {
      ref.current?.setSelectionRange(next.caret, next.caret)
      setCaret(next.caret)
    })
  }

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (options.length === 0) return
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((a) => (a + 1) % options.length)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((a) => (a - 1 + options.length) % options.length)
    } else if (e.key === 'Enter' || e.key === 'Tab') {
      e.preventDefault()
      accept(options[Math.min(active, options.length - 1)])
    } else if (e.key === 'Escape') {
      e.stopPropagation()
      setOpen(false)
    }
  }

  const expanded = options.length > 0
  return (
    <div className="space-y-1.5">
      <div className="relative">
        <Textarea
          id={id}
          ref={ref}
          value={value}
          disabled={disabled}
          autoFocus={autoFocus}
          rows={3}
          maxLength={4096}
          spellCheck={false}
          className="font-mono text-sm"
          placeholder={t('remediationQuery.box.placeholder')}
          role="combobox"
          aria-autocomplete="list"
          aria-expanded={expanded}
          aria-controls={listId}
          aria-activedescendant={expanded ? `${listId}-${active}` : undefined}
          aria-describedby={hintId}
          aria-invalid={problems.length > 0}
          onChange={(e) => {
            onChange(e.target.value)
            setCaret(e.target.selectionStart ?? e.target.value.length)
            setActive(0)
            setOpen(true)
          }}
          onKeyDown={onKeyDown}
          onClick={(e) => setCaret(e.currentTarget.selectionStart ?? 0)}
          onBlur={() => setOpen(false)}
        />
        <ul
          id={listId}
          role="listbox"
          aria-label={t('remediationQuery.box.suggestions')}
          className={cn(
            'bg-popover absolute top-full left-0 z-50 mt-1 max-h-48 w-64 overflow-auto rounded-md border p-1 shadow-md',
            !expanded && 'hidden'
          )}
        >
          {options.map((o, i) => (
            <li
              key={o}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === active}
              className={cn(
                'cursor-pointer rounded px-2 py-1 font-mono text-xs',
                i === active && 'bg-accent text-accent-foreground'
              )}
              onMouseDown={(e) => {
                e.preventDefault()
                accept(o)
              }}
            >
              {o}
            </li>
          ))}
        </ul>
      </div>
      <div id={hintId} aria-live="polite" className="min-h-5 text-xs">
        {checking ? (
          <span className="text-muted-foreground">{t('remediationQuery.box.checking')}</span>
        ) : problems.length > 0 ? (
          <ul className="text-destructive space-y-0.5">
            {problems.map((p, i) => (
              <li key={i}>
                {p.line > 0
                  ? t('remediationQuery.box.problemAt', undefined, {
                      line: p.line,
                      column: p.column,
                      message: p.message,
                    })
                  : p.message || t('remediationQuery.box.invalid')}
              </li>
            ))}
          </ul>
        ) : description ? (
          <span className="text-muted-foreground">{description}</span>
        ) : (
          <span className="text-muted-foreground">{t('remediationQuery.box.hint')}</span>
        )}
      </div>
    </div>
  )
}
