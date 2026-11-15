'use client'

/**
 * QueryInput: the one search box for filtered lists and custom queries
 * (server/docs/architecture/query-language.md, "Short form"). People type plain
 * words (a text search) or conditions such as
 * `severity>=high kev=true -status:accepted last_seen<7d`; the long form
 * (`findings where ...`) is accepted too. The text is plain text: nothing is
 * rendered as HTML.
 *
 * Typing sends nothing to the server. Fields, operators and enum values come
 * from the entity's schema, read once and kept for the session; the caret's
 * context is read here; quotes and parentheses are checked here. The server
 * checks the text once, when it is applied (Enter, Ctrl/Cmd+Enter in a text
 * area, or the Apply button), and its first problem shows under the box with
 * its fix. Values only the server knows (tools, CVEs, domains) are asked for
 * after two characters or Ctrl+Space, 300 ms after the last key, and a newer
 * key cancels the request in flight.
 */

import { useCallback, useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Button } from '@/components/ui/button'
import { Popover, PopoverAnchor, PopoverContent } from '@/components/ui/popover'
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
  localProblem,
  localValues,
  quoteValue,
  type CaretContext,
  type Completion,
  type LocalProblem,
} from '../lib/complete'
import { pushRecent, readRecent } from '../lib/recent'

/** Value lookup delay after the last key. */
export const VALUES_DELAY_MS = 300
/** Characters of a value typed before the server is asked for values (Ctrl+Space asks at once). */
export const VALUES_MIN_PREFIX = 2
const MAX_OPTIONS = 10

/**
 * The suggestion list is a kit popover in a portal, so a dialog body or any
 * other scroll container never clips it. It lines up with the start of the
 * field and its status line (the hint or the problem stays readable), opens
 * below them, or above the field when there is no room below, is never wider
 * than the field (28rem at most) and never taller than the room on its side
 * (16rem at most, about ten rows), scrolling inside.
 */
export const SUGGESTION_LIST_CLASSES =
  'w-[min(28rem,var(--radix-popover-trigger-width))] min-w-0 max-h-[min(16rem,var(--radix-popover-content-available-height))] overflow-y-auto p-1'

export interface QueryInputProps {
  entity: QueryEntity
  value: string
  onChange: (text: string) => void
  /**
   * Apply: Enter (Ctrl/Cmd+Enter in a text area) or the Apply button. The
   * server checks the text once; a valid answer is handed over, a refusal
   * shows under the box.
   */
  onSubmit?: (result: ParseResult) => void
  /**
   * The text that is in force (a list's current filter). With `onSubmit` the
   * box shows an Apply button, enabled while the text differs from it, and
   * says the edit is not applied yet.
   */
  applied?: string
  /**
   * A server answer the owner of the box obtained for the current text (a
   * mode switch, a preview): its problem shows under the box. The owner
   * clears it when the text changes.
   */
  checked?: ParseResult | null
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
  /** Extra classes for the input (a list search field leaves room for its icons). */
  inputClassName?: string
  /** Controls drawn over the input (a list search field's icon and mode switch). */
  adornments?: ReactNode
  /**
   * Show only problems under the box (a list toolbar keeps one line): the
   * hint, the check and the result count are still read out, not drawn.
   */
  quietStatus?: boolean
  /** Escape with no suggestion open (a list search field reverts its text). */
  onEscape?: () => void
}

export function QueryInput({
  entity,
  value,
  onChange,
  onSubmit,
  applied,
  checked,
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
  inputClassName,
  adornments,
  quietStatus,
  onEscape,
}: QueryInputProps) {
  const { t, locale } = useTranslation()
  const ownId = useId()
  const inputId = id ?? `${ownId}-input`
  const listId = `${ownId}-list`
  const statusId = `${ownId}-status`
  const ref = useRef<HTMLInputElement & HTMLTextAreaElement>(null)
  const anchorRef = useRef<HTMLDivElement>(null)
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
  // Ctrl+Space: values are asked for at once, whatever was typed.
  const [explicit, setExplicit] = useState(false)
  // The server's answer to the text it was asked about on Apply.
  const [answer, setAnswer] = useState<{ text: string; result: ParseResult } | null>(null)
  // Apply refused before asking (quotes or parentheses do not pair up).
  const [refused, setRefused] = useState<string | null>(null)
  const [checking, setChecking] = useState(false)
  const [failed, setFailed] = useState<string | null>(null)
  const [remote, setRemote] = useState<{ key: string; options: Completion[] } | null>(null)

  const ctx: CaretContext = useMemo(() => contextAt(value, caret), [value, caret])
  const field = useMemo(
    () => (ctx.kind === 'value' ? fields.find((f) => f.path === ctx.path) : undefined),
    [ctx, fields]
  )
  const remoteKey = ctx.kind === 'value' ? `${ctx.path}\u0000${ctx.prefix}\u0000${ctx.rest}` : ''
  const needsRemote =
    open &&
    ctx.kind === 'value' &&
    !!ctx.path &&
    localValues(field, ctx) === null &&
    (explicit || ctx.prefix.length >= VALUES_MIN_PREFIX)

  // Values of string fields (tools, CVEs, domains): the server's top values
  // in the caller's scope, under the rest of the filter. Only on demand, after
  // a pause; the next key cancels the request in flight.
  useEffect(() => {
    if (!needsRemote || !ctx.path) return
    const abort = new AbortController()
    const timer = setTimeout(() => {
      queryApi
        .values(entity, ctx.path ?? '', ctx.prefix, ctx.rest, abort.signal)
        .then((res) => {
          if (abort.signal.aborted) return
          setRemote({
            key: remoteKey,
            options: res.values.slice(0, MAX_OPTIONS).map((v) => ({
              kind: 'value' as const,
              label: String(v.value),
              insert: quoteValue(String(v.value)),
              count: res.counted ? v.count : undefined,
            })),
          })
        })
        .catch(() => {
          if (!abort.signal.aborted) setRemote({ key: remoteKey, options: [] })
        })
    }, VALUES_DELAY_MS)
    return () => {
      clearTimeout(timer)
      abort.abort()
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
      return remote?.key === remoteKey ? remote.options : []
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

  /** Selects a range of the text: the field scrolls to it, typing replaces it. */
  const select = (start: number, end: number) => {
    const el = ref.current
    if (!el) return
    const s = Math.min(start, value.length)
    el.focus()
    el.setSelectionRange(s, Math.max(s, Math.min(end, value.length)))
    setCaret(s)
  }

  const submit = () => {
    if (!onSubmit || checking) return
    const text = value
    if (text.trim() === '') {
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
    // The suggestions close so the problem line shows.
    setOpen(false)
    const local = localProblem(text)
    if (local) {
      // A text that cannot be read is not sent.
      setRefused(text)
      select(local.start, local.end)
      return
    }
    setRefused(null)
    setFailed(null)
    setChecking(true)
    queryApi
      .parse({ entity, text })
      .then((res) => {
        setAnswer({ text, result: res })
        if (res.valid) {
          pushRecent(scope, res.text || text)
          onSubmit(res)
          return
        }
        const p = res.problems[0]
        if (p) select(p.start, p.end)
      })
      .catch(() => setFailed(text))
      .finally(() => setChecking(false))
  }

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const listOpen = options.length > 0
    if (e.key === ' ' && e.ctrlKey) {
      e.preventDefault()
      setExplicit(true)
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
      if (listOpen && !e.ctrlKey && !e.metaKey) {
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
      } else if (onEscape) {
        e.preventDefault()
        e.stopPropagation()
        onEscape()
      } else {
        ref.current?.blur()
      }
    }
  }

  // The server's word on this very text: from Apply, or from the box's owner.
  const server = answer?.text === value ? answer.result : (checked ?? null)
  const problem = server && !server.valid ? server.problems[0] : undefined
  // Pairing problems are found while typing; they are drawn as a problem
  // once Apply was refused for them, and read out (muted) before that.
  const local = problem ? null : localProblem(value)
  const localShown = !!local && refused === value
  const dirty = applied !== undefined && value.trim() !== applied.trim()
  const showApply = !!onSubmit && applied !== undefined
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
    'aria-controls': expanded ? listId : undefined,
    'aria-activedescendant': expanded ? `${listId}-${active}` : undefined,
    'aria-describedby': statusId,
    'aria-invalid': !!problem || localShown,
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      onChange(e.target.value)
      setCaret(e.target.selectionStart ?? e.target.value.length)
      setActive(0)
      setExplicit(false)
      setOpen(true)
    },
    onKeyDown,
    onClick: (e: React.MouseEvent<HTMLInputElement | HTMLTextAreaElement>) =>
      setCaret(e.currentTarget.selectionStart ?? 0),
    onFocus: () => setOpen(true),
    onBlur: () => setOpen(false),
  }

  const drawn = !!problem || localShown || failed === value
  return (
    <Popover
      open={expanded}
      onOpenChange={(next) => {
        if (!next) setOpen(false)
      }}
    >
      <PopoverAnchor asChild>
        <div ref={anchorRef} className={cn('min-w-0', !quietStatus && 'space-y-1', className)}>
          <div className="flex items-start gap-2">
            <div className="relative min-w-0 flex-1">
              {multiline ? (
                <Textarea
                  ref={ref}
                  rows={3}
                  className={cn('font-mono text-sm', inputClassName)}
                  {...shared}
                />
              ) : (
                <Input ref={ref} className={cn('font-mono', inputClassName)} {...shared} />
              )}
              {adornments}
            </div>
            {showApply && (
              <Button
                type="button"
                data-slot="query-apply"
                variant={dirty ? 'default' : 'outline'}
                disabled={disabled || !dirty || checking}
                aria-describedby={statusId}
                // The caret stays in the box.
                onMouseDown={(e) => e.preventDefault()}
                onClick={submit}
              >
                {t('queryInput.apply')}
              </Button>
            )}
          </div>
          <div
            id={statusId}
            aria-live="polite"
            className={cn(
              'text-muted-foreground min-h-5 text-xs',
              // A list field adds no space under itself until there is a problem.
              quietStatus && (drawn ? 'mt-1' : 'sr-only')
            )}
          >
            {problem ? (
              <ProblemLine
                problem={problem}
                onFix={(fix) =>
                  setText(
                    applyFix(value, problem.start, problem.end, fix),
                    problem.start + fix.length
                  )
                }
              />
            ) : local ? (
              <LocalProblemLine problem={local} text={value} strong={localShown} />
            ) : checking ? (
              <span>{t('queryInput.checking')}</span>
            ) : failed === value ? (
              <span>{t('queryInput.unavailable')}</span>
            ) : dirty ? (
              <span>{t('queryInput.pending')}</span>
            ) : typeof resultCount === 'number' && value.trim() !== '' ? (
              <span>
                {t('queryInput.results', undefined, { count: formatCount(resultCount, locale) })}
              </span>
            ) : (
              <span>{t('queryInput.hint')}</span>
            )}
          </div>
        </div>
      </PopoverAnchor>
      <PopoverContent
        asChild
        side="bottom"
        hideWhenDetached
        className={SUGGESTION_LIST_CLASSES}
        // The caret stays in the field: the list never takes focus.
        onOpenAutoFocus={(e) => e.preventDefault()}
        onCloseAutoFocus={(e) => e.preventDefault()}
        // Clicking in the field moves the caret; it does not close the list.
        onInteractOutside={(e) => {
          if (e.target instanceof Node && anchorRef.current?.contains(e.target)) e.preventDefault()
        }}
      >
        <ul id={listId} role="listbox" aria-label={t('queryInput.suggestions')}>
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
      </PopoverContent>
    </Popover>
  )
}

/** A quote or parenthesis that does not pair up, found while typing. */
function LocalProblemLine({
  problem,
  text,
  strong,
}: {
  problem: LocalProblem
  text: string
  strong: boolean
}) {
  const { t } = useTranslation()
  const column = [...text.slice(0, problem.start)].length + 1
  return (
    <span className={cn(strong && 'text-destructive')}>
      {t(`queryInput.local.${problem.code}`)} {t('queryInput.atColumn', undefined, { column })}
    </span>
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
        {problem.column > 0
          ? ` ${t('queryInput.atColumn', undefined, { column: problem.column })}`
          : ''}
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
