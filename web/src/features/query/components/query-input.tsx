'use client'

/**
 * QueryInput: the one search box for filtered lists and custom queries
 * (api/docs/architecture/query-language.md, "Short form"). People type plain
 * words (a text search) or conditions such as
 * `severity>=high kev=true -status:accepted last_seen<7d`; the long form
 * (`findings where ...`) is accepted too. The server parses and checks the
 * text (POST /api/v1/query/parse) for the caller's own fields; this box only
 * completes fields, operators and values near the caret, shows the first
 * problem with its fix, and keeps recent queries in this browser. The text
 * is plain text: nothing is rendered as HTML.
 */

import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import {
  queryApi,
  useQuerySchema,
  type ParseResult,
  type QueryEntity,
  type QueryProblem,
} from '../api/query-api'
import {
  applyCompletion,
  applyFix,
  contextAt,
  fieldCompletions,
  formatCount,
  localValues,
  quoteValue,
  type CaretContext,
  type Completion,
} from '../lib/complete'
import { pushRecent, readRecent } from '../lib/recent'

/** Server check delay after the last keystroke. */
export const CHECK_DELAY_MS = 250
/** Value lookup delay. */
const VALUES_DELAY_MS = 250
const MAX_OPTIONS = 10

export interface QueryInputProps {
  entity: QueryEntity
  value: string
  onChange: (text: string) => void
  /** Enter with a valid filter (single-line boxes), with the server's answer. */
  onSubmit?: (result: ParseResult) => void
  /** Every finished check: the server's answer, or null for empty text. */
  onParsed?: (result: ParseResult | null) => void
  /** Recent queries are kept per scope (an entity and tab, "findings"). */
  recentScope?: string
  /** The result count of the current filter, shown under the box. */
  resultCount?: number | null
  /** A text area for long queries (custom query dialogs). */
  multiline?: boolean
  placeholder?: string
  id?: string
  autoFocus?: boolean
  disabled?: boolean
  className?: string
  /** Accessible name when no visible label points at the box. */
  ariaLabel?: string
  /** Fields completion lists first (the open tab's own fields). */
  preferFields?: string[]
}

export function QueryInput({
  entity,
  value,
  onChange,
  onSubmit,
  onParsed,
  recentScope,
  resultCount,
  multiline,
  placeholder,
  id,
  autoFocus,
  disabled,
  className,
  ariaLabel,
  preferFields,
}: QueryInputProps) {
  const { t, locale } = useTranslation()
  const ownId = useId()
  const inputId = id ?? `${ownId}-input`
  const listId = `${ownId}-list`
  const statusId = `${ownId}-status`
  const ref = useRef<HTMLInputElement & HTMLTextAreaElement>(null)
  const { data: schema } = useQuerySchema(entity, !disabled)
  const fields = useMemo(() => {
    const all = schema?.fields ?? []
    if (!preferFields?.length) return all
    const first = new Set(preferFields)
    return [...all.filter((f) => first.has(f.path)), ...all.filter((f) => !first.has(f.path))]
  }, [schema, preferFields])
  const scope = recentScope ?? entity

  const [caret, setCaret] = useState(0)
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const [result, setResult] = useState<ParseResult | null>(null)
  const [checking, setChecking] = useState(false)
  const [failed, setFailed] = useState(false)
  const [remote, setRemote] = useState<{ key: string; options: Completion[] } | null>(null)
  const seq = useRef(0)
  // The latest onParsed, so the check below reruns on the text only.
  const onParsedRef = useRef(onParsed)
  useEffect(() => {
    onParsedRef.current = onParsed
  }, [onParsed])

  // Server check, debounced; a stale answer never replaces a newer one.
  useEffect(() => {
    const text = value.trim()
    if (!text || disabled) {
      setResult(null)
      setFailed(false)
      onParsedRef.current?.(null)
      return
    }
    const mine = ++seq.current
    const timer = setTimeout(() => {
      setChecking(true)
      queryApi
        .parse({ entity, text })
        .then((res) => {
          if (mine !== seq.current) return
          setResult(res)
          setFailed(false)
          onParsedRef.current?.(res)
        })
        .catch(() => {
          if (mine !== seq.current) return
          setResult(null)
          setFailed(true)
        })
        .finally(() => {
          if (mine === seq.current) setChecking(false)
        })
    }, CHECK_DELAY_MS)
    return () => clearTimeout(timer)
  }, [value, entity, disabled])

  const ctx: CaretContext = useMemo(() => contextAt(value, caret), [value, caret])
  const field = useMemo(
    () => (ctx.kind === 'value' ? fields.find((f) => f.path === ctx.path) : undefined),
    [ctx, fields]
  )
  const remoteKey = ctx.kind === 'value' ? `${ctx.path}\u0000${ctx.prefix}\u0000${ctx.rest}` : ''
  const needsRemote = open && ctx.kind === 'value' && localValues(field, ctx) === null && !!ctx.path

  // Values of string fields (tools, CVEs, domains): the server's top values
  // in the caller's scope, under the rest of the filter.
  useEffect(() => {
    if (!needsRemote || !ctx.path) return
    let cancelled = false
    const timer = setTimeout(() => {
      queryApi
        .values(entity, ctx.path ?? '', ctx.prefix, ctx.rest)
        .then((res) => {
          if (cancelled) return
          setRemote({
            key: remoteKey,
            options: res.values.map((v) => ({
              kind: 'value' as const,
              label: String(v.value),
              insert: quoteValue(String(v.value)),
              count: res.counted ? v.count : undefined,
            })),
          })
        })
        .catch(() => {
          if (!cancelled) setRemote({ key: remoteKey, options: [] })
        })
    }, VALUES_DELAY_MS)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [needsRemote, remoteKey, entity, ctx.path, ctx.prefix, ctx.rest])

  const options: Completion[] = useMemo(() => {
    if (!open) return []
    if (value.trim() === '') {
      return readRecent(scope)
        .slice(0, MAX_OPTIONS)
        .map((r) => ({ kind: 'recent' as const, label: r, insert: r }))
    }
    if (ctx.kind === 'field') return fieldCompletions(ctx, fields, MAX_OPTIONS)
    if (ctx.kind === 'value') {
      const local = localValues(field, ctx)
      if (local) return local.slice(0, MAX_OPTIONS)
      return remote?.key === remoteKey ? remote.options.slice(0, MAX_OPTIONS) : []
    }
    return []
  }, [open, value, ctx, fields, field, remote, remoteKey, scope])

  const setText = useCallback(
    (text: string, nextCaret: number) => {
      onChange(text)
      requestAnimationFrame(() => {
        ref.current?.setSelectionRange(nextCaret, nextCaret)
        setCaret(nextCaret)
      })
    },
    [onChange]
  )

  const accept = (o: Completion) => {
    if (o.kind === 'recent') {
      setText(o.insert, o.insert.length)
      setOpen(false)
      return
    }
    const next = applyCompletion(value, ctx, o.insert)
    setText(next.text, next.caret)
    setActive(0)
    // After a field or an operator the next suggestions follow at once.
    setOpen(o.kind === 'field' || o.kind === 'operator')
  }

  const submit = () => {
    if (!onSubmit) return
    if (value.trim() === '') {
      onSubmit({
        entity,
        valid: true,
        text: '',
        query: '',
        chips: [],
        advanced: false,
        problems: [],
      })
      return
    }
    queryApi
      .parse({ entity, text: value })
      .then((res) => {
        setResult(res)
        if (res.valid) {
          pushRecent(scope, res.text || value)
          onSubmit(res)
          setOpen(false)
        }
      })
      .catch(() => setFailed(true))
  }

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const listOpen = options.length > 0
    if (e.key === ' ' && e.ctrlKey) {
      e.preventDefault()
      setOpen(true)
      return
    }
    if (e.key === 'ArrowDown' && listOpen) {
      e.preventDefault()
      setActive((a) => (a + 1) % options.length)
    } else if (e.key === 'ArrowUp' && listOpen) {
      e.preventDefault()
      setActive((a) => (a - 1 + options.length) % options.length)
    } else if (e.key === 'ArrowUp' && value === '') {
      const last = readRecent(scope)[0]
      if (last) {
        e.preventDefault()
        setText(last, last.length)
      }
    } else if (e.key === 'Tab' && listOpen) {
      e.preventDefault()
      accept(options[Math.min(active, options.length - 1)])
    } else if (e.key === 'Enter' && !e.shiftKey) {
      if (listOpen) {
        e.preventDefault()
        accept(options[Math.min(active, options.length - 1)])
      } else if (!multiline || e.ctrlKey || e.metaKey) {
        e.preventDefault()
        submit()
      }
    } else if (e.key === 'Escape') {
      if (listOpen) {
        e.stopPropagation()
        setOpen(false)
      } else {
        ref.current?.blur()
      }
    }
  }

  const problem = result && !result.valid ? result.problems[0] : undefined
  const expanded = options.length > 0
  const shared = {
    id: inputId,
    value,
    disabled,
    autoFocus,
    spellCheck: false,
    autoComplete: 'off',
    maxLength: 4096,
    placeholder: placeholder ?? t(`queryInput.placeholder.${entity}`),
    role: 'combobox',
    'aria-label': ariaLabel,
    'aria-autocomplete': 'list' as const,
    'aria-expanded': expanded,
    'aria-controls': listId,
    'aria-activedescendant': expanded ? `${listId}-${active}` : undefined,
    'aria-describedby': statusId,
    'aria-invalid': !!problem,
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      onChange(e.target.value)
      setCaret(e.target.selectionStart ?? e.target.value.length)
      setActive(0)
      setOpen(true)
    },
    onKeyDown,
    onClick: (e: React.MouseEvent<HTMLInputElement | HTMLTextAreaElement>) =>
      setCaret(e.currentTarget.selectionStart ?? 0),
    onFocus: () => setOpen(true),
    onBlur: () => setOpen(false),
  }

  return (
    <div className={cn('min-w-0 space-y-1', className)}>
      <div className="relative">
        {multiline ? (
          <Textarea ref={ref} rows={3} className="font-mono text-sm" {...shared} />
        ) : (
          <Input ref={ref} className="h-9 font-mono text-sm" {...shared} />
        )}
        <ul
          id={listId}
          role="listbox"
          aria-label={t('queryInput.suggestions')}
          className={cn(
            'bg-popover absolute top-full left-0 z-50 mt-1 max-h-64 w-full max-w-md overflow-auto rounded-md border p-1 shadow-md',
            !expanded && 'hidden'
          )}
        >
          {options.map((o, i) => (
            <li
              key={`${o.kind}-${o.label}`}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === active}
              className={cn(
                'flex cursor-pointer items-center justify-between gap-3 rounded px-2 py-1 text-xs',
                i === active && 'bg-accent text-accent-foreground'
              )}
              onMouseDown={(e) => {
                e.preventDefault()
                accept(o)
              }}
            >
              <span className="truncate font-mono">{o.label}</span>
              <span className="text-muted-foreground shrink-0">
                {o.count !== undefined
                  ? formatCount(o.count, locale)
                  : t(`queryInput.kind.${o.kind}`)}
              </span>
            </li>
          ))}
        </ul>
      </div>
      <div id={statusId} aria-live="polite" className="text-muted-foreground min-h-5 text-xs">
        {problem ? (
          <ProblemLine
            problem={problem}
            onFix={(fix) =>
              setText(applyFix(value, problem.start, problem.end, fix), problem.start + fix.length)
            }
          />
        ) : checking ? (
          <span>{t('queryInput.checking')}</span>
        ) : failed ? (
          <span>{t('queryInput.unavailable')}</span>
        ) : typeof resultCount === 'number' && value.trim() !== '' ? (
          <span>
            {t('queryInput.results', undefined, { count: formatCount(resultCount, locale) })}
          </span>
        ) : (
          <span>{t('queryInput.hint')}</span>
        )}
      </div>
    </div>
  )
}

/** The first problem, in the person's language, with its fixes as buttons. */
function ProblemLine({ problem, onFix }: { problem: QueryProblem; onFix: (fix: string) => void }) {
  const { t } = useTranslation()
  const known = KNOWN_CODES.has(problem.code)
  const fixes = FIXABLE.has(problem.code) ? (problem.suggestions ?? []).slice(0, 3) : []
  return (
    <span className="text-destructive flex flex-wrap items-center gap-x-2 gap-y-1">
      <span>
        {known ? t(`queryInput.problem.${problem.code}`) : t('queryInput.problem.invalid')}
        {DETAILED.has(problem.code) && problem.message ? ` (${problem.message})` : ''}
        {problem.code === 'operator_not_allowed' && problem.suggestions?.length
          ? ' ' +
            t('queryInput.allowedOperators', undefined, { ops: problem.suggestions.join(' ') })
          : ''}
      </span>
      {fixes.length > 0 && <span>{t('queryInput.didYouMean')}</span>}
      {fixes.map((f) => (
        <Button
          key={f}
          type="button"
          variant="outline"
          size="sm"
          className="h-6 px-2 font-mono text-xs"
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => onFix(f)}
        >
          {f}
        </Button>
      ))}
    </span>
  )
}

const KNOWN_CODES = new Set([
  'syntax',
  'unknown_field',
  'operator_not_allowed',
  'bad_value',
  'unknown_value',
  'pattern_not_allowed',
  'wrong_entity',
  'pipeline_not_allowed',
  'too_complex',
  'not_on_list',
])

// Problems whose server message (English, no values from the query) adds
// the specifics: what was expected.
const DETAILED = new Set(['syntax', 'bad_value'])

// Problems whose suggestions replace the problem's text (a field or a value).
const FIXABLE = new Set(['unknown_field', 'unknown_value'])
